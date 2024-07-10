//! The keccak circuit implementation.
#![allow(dead_code, unused_imports)]
mod cell_manager;
/// Keccak packed multi
pub mod keccak_packed_multi;
mod param;
mod table;
/// Util
mod util;

use std::marker::PhantomData;
pub use KeccakCircuitConfig as KeccakConfig;

use self::{
    cell_manager::*,
    keccak_packed_multi::{keccak_unusable_rows, KeccakRow},
    param::*,
    table::*,
    util::*,
};
use crate::bitwise_circuit::{BitwiseCircuit, BitwiseCircuitConfig, BitwiseCircuitConfigArgs};
use crate::keccak_circuit::keccak_packed_multi::{calc_keccak_with_rlc, multi_keccak};
use crate::table::{BitwiseTable, FixedTable, KeccakTable};
use crate::witness::bitwise::Tag;
use crate::witness::Witness;
use crate::{
    keccak_circuit::keccak_packed_multi::{
        decode, get_num_bits_per_absorb_lookup, get_num_bits_per_base_chi_lookup,
        get_num_bits_per_rho_pi_lookup, get_num_bits_per_theta_c_lookup, get_num_rows_per_round,
        split, split_uniform, transform, transform_to, Part,
    },
    util::{BaseConstraintBuilder, ConstrainBuilderCommon},
    util::{Challenges, SubCircuit, SubCircuitConfig},
    witness,
};
use eth_types::Field;
use gadgets::util::{and, expr_from_bytes, not, select, sum, Expr};
use halo2_proofs::plonk::{Advice, Selector};
use halo2_proofs::{
    circuit::{Layouter, Region, Value},
    plonk::{Column, ConstraintSystem, Error, Expression, Fixed, TableColumn, VirtualCells},
    poly::Rotation,
};
use log::info;

const DEFAULT_MAX_KECCAK_ROWS_NUM: usize = 0;

/// KeccakConfig
#[derive(Clone, Debug)]
pub struct KeccakCircuitConfig<F> {
    q_enable: Column<Fixed>,
    q_first: Column<Fixed>,
    q_round: Column<Fixed>,
    q_absorb: Column<Fixed>,
    q_round_last: Column<Fixed>,
    q_padding: Column<Fixed>,
    q_padding_last: Column<Fixed>,
    pub is_final: Column<Advice>,
    /// Byte array input as `RLC(reversed(input))`
    pub input_rlc: Column<Advice>, // RLC of input bytes
    /// Byte array input length
    pub input_len: Column<Advice>,
    /// RLC of the hash result
    pub output_rlc: Column<Advice>, // RLC of hash of input bytes
    // rlc not used now
    // new columns to hold hash hi and lo 128 bits without RLC
    pub output_hi: Column<Advice>,
    pub output_lo: Column<Advice>,
    cell_manager: CellManager<F>,
    round_cst: Column<Fixed>,
    normalize_3: [TableColumn; 2],
    normalize_4: [TableColumn; 2],
    normalize_6: [TableColumn; 2],
    chi_base_table: [TableColumn; 2],
    pack_table: [TableColumn; 2],
    _marker: PhantomData<F>,
}

/// Circuit configuration arguments
pub struct KeccakCircuitConfigArgs {
    /// KeccakTable
    pub keccak_table: KeccakTable,
    /// Challenges randomness
    pub challenges: Challenges,
}

impl<F: Field> SubCircuitConfig<F> for KeccakCircuitConfig<F> {
    type ConfigArgs = KeccakCircuitConfigArgs;

    /// Return a new KeccakCircuitConfig
    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs {
            keccak_table,
            challenges,
        }: Self::ConfigArgs,
    ) -> Self {
        assert!(
            get_num_rows_per_round() > NUM_BYTES_PER_WORD,
            "KeccakCircuit requires KECCAK_ROWS>=9"
        );
        let q_enable = meta.fixed_column();
        let q_first = meta.fixed_column();
        let q_round = meta.fixed_column();
        let q_absorb = meta.fixed_column();
        let q_round_last = meta.fixed_column();
        let q_padding = meta.fixed_column();
        let q_padding_last = meta.fixed_column();
        let round_cst = meta.fixed_column();

        let is_final = meta.advice_column();
        let length = keccak_table.input_len;
        let data_rlc = keccak_table.input_rlc;
        let hash_rlc = keccak_table.output_rlc;
        let hash_hi = keccak_table.output_hi;
        let hash_lo = keccak_table.output_lo;

        let normalize_3 = std::array::from_fn(|_| meta.lookup_table_column());
        let normalize_4 = std::array::from_fn(|_| meta.lookup_table_column());
        let normalize_6 = std::array::from_fn(|_| meta.lookup_table_column());
        let chi_base_table = std::array::from_fn(|_| meta.lookup_table_column());
        let pack_table = std::array::from_fn(|_| meta.lookup_table_column());

        let challenges_expr = challenges.exprs(meta);

        let mut cell_manager = CellManager::new(get_num_rows_per_round());
        let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
        let mut total_lookup_counter = 0;

        let start_new_hash = |meta: &mut VirtualCells<F>, rot| {
            // A new hash is started when the previous hash is done or on the first row
            meta.query_fixed(q_first, rot) + meta.query_advice(is_final, rot)
        };

        // Round constant
        let mut round_cst_expr = 0.expr();
        meta.create_gate("Query round cst", |meta| {
            round_cst_expr = meta.query_fixed(round_cst, Rotation::cur());
            vec![0u64.expr()]
        });
        // State data
        let mut s = vec![vec![0u64.expr(); 5]; 5];
        let mut s_next = vec![vec![0u64.expr(); 5]; 5];
        for i in 0..5 {
            for j in 0..5 {
                let cell = cell_manager.query_cell(meta);
                s[i][j] = cell.expr();
                s_next[i][j] = cell.at_offset(meta, get_num_rows_per_round() as i32).expr();
            }
        }
        // Absorb data
        let absorb_from = cell_manager.query_cell(meta);
        let absorb_data = cell_manager.query_cell(meta);
        let absorb_result = cell_manager.query_cell(meta);
        let mut absorb_from_next = vec![0u64.expr(); NUM_WORDS_TO_ABSORB];
        let mut absorb_data_next = vec![0u64.expr(); NUM_WORDS_TO_ABSORB];
        let mut absorb_result_next = vec![0u64.expr(); NUM_WORDS_TO_ABSORB];
        for i in 0..NUM_WORDS_TO_ABSORB {
            let rot = ((i + 1) * get_num_rows_per_round()) as i32;
            absorb_from_next[i] = absorb_from.at_offset(meta, rot).expr();
            absorb_data_next[i] = absorb_data.at_offset(meta, rot).expr();
            absorb_result_next[i] = absorb_result.at_offset(meta, rot).expr();
        }

        // Store the pre-state
        let pre_s = s.clone();

        // Absorb
        // The absorption happening at the start of the 24 rounds is done spread out
        // over those 24 rounds. In a single round (in 17 of the 24 rounds) a
        // single word is absorbed so the work is spread out. The absorption is
        // done simply by doing state + data and then normalizing the result to [0,1].
        // We also need to convert the input data into bytes to calculate the input data
        // rlc.
        cell_manager.start_region();
        let mut lookup_counter = 0;
        let part_size = get_num_bits_per_absorb_lookup();
        let input = absorb_from.expr() + absorb_data.expr();
        let absorb_fat = split::expr(meta, &mut cell_manager, &mut cb, input, 0, part_size);
        cell_manager.start_region();
        let absorb_res = transform::expr(
            "absorb",
            meta,
            &mut cell_manager,
            &mut lookup_counter,
            absorb_fat,
            normalize_3,
            true,
        );
        cb.require_equal(
            "absorb result",
            decode::expr(absorb_res),
            absorb_result.expr(),
        );
        info!("- Post absorb:");
        info!("Lookups: {}", lookup_counter);
        info!("Columns: {}", cell_manager.get_width());
        total_lookup_counter += lookup_counter;

        // Process inputs.
        // "Absorb" happens at the first round. However, the input is witnessed and
        // processed over the first 17 rounds. Each round converts a word into 8
        // bytes.
        cell_manager.start_region();
        let mut lookup_counter = 0;
        // Potential optimization: could do multiple bytes per lookup
        let packed_parts = split::expr(
            meta,
            &mut cell_manager,
            &mut cb,
            absorb_data.expr(),
            0,
            NUM_BYTES_PER_WORD,
        );
        cell_manager.start_region();
        let input_bytes = transform::expr(
            "input unpack",
            meta,
            &mut cell_manager,
            &mut lookup_counter,
            packed_parts,
            pack_table
                .into_iter()
                .rev()
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
            true,
        );

        // Padding data
        cell_manager.start_region();
        let mut is_paddings = Vec::new();
        for _ in input_bytes.iter() {
            is_paddings.push(cell_manager.query_cell(meta));
        }
        info!("- Post padding:");
        info!("Lookups: {}", lookup_counter);
        info!("Columns: {}", cell_manager.get_width());
        total_lookup_counter += lookup_counter;

        // Theta
        // Calculate
        // - `c[i] = s[i][0] + s[i][1] + s[i][2] + s[i][3] + s[i][4]`
        // - `bc[i] = normalize(c)`.
        // - `t[i] = bc[(i + 4) % 5] + rot(bc[(i + 1)% 5], 1)`
        // This is done by splitting the bc values in parts in a way
        // that allows us to also calculate the rotated value "for free".
        cell_manager.start_region();
        let mut lookup_counter = 0;
        let part_size_c = get_num_bits_per_theta_c_lookup();
        let mut c_parts = Vec::new();
        for s in s.iter() {
            // Calculate c and split into parts
            let c = s[0].clone() + s[1].clone() + s[2].clone() + s[3].clone() + s[4].clone();
            c_parts.push(split::expr(
                meta,
                &mut cell_manager,
                &mut cb,
                c,
                1,
                part_size_c,
            ));
        }
        // Now calculate `bc` by normalizing `c`
        cell_manager.start_region();
        let mut bc = Vec::new();
        for c in c_parts {
            // Normalize c
            bc.push(transform::expr(
                "theta c",
                meta,
                &mut cell_manager,
                &mut lookup_counter,
                c,
                normalize_6,
                true,
            ));
        }
        // Now do `bc[(i + 4) % 5] + rot(bc[(i + 1) % 5], 1)` using just expressions.
        // We don't normalize the result here. We do it as part of the rho/pi step, even
        // though we would only have to normalize 5 values instead of 25, because of the
        // way the rho/pi and chi steps can be combined it's more efficient to
        // do it there (the max value for chi is 4 already so that's the
        // limiting factor).
        let mut os = vec![vec![0u64.expr(); 5]; 5];
        for i in 0..5 {
            let t = decode::expr(bc[(i + 4) % 5].clone())
                + decode::expr(rotate(bc[(i + 1) % 5].clone(), 1, part_size_c));
            for j in 0..5 {
                os[i][j] = s[i][j].clone() + t.clone();
            }
        }
        s = os.clone();
        info!("- Post theta:");
        info!("Lookups: {}", lookup_counter);
        info!("Columns: {}", cell_manager.get_width());
        total_lookup_counter += lookup_counter;

        // Rho/Pi
        // For the rotation of rho/pi we split up the words like expected, but in a way
        // that allows reusing the same parts in an optimal way for the chi step.
        // We can save quite a few columns by not recombining the parts after rho/pi and
        // re-splitting the words again before chi. Instead we do chi directly
        // on the output parts of rho/pi. For rho/pi specically we do
        // `s[j][2 * i + 3 * j) % 5] = normalize(rot(s[i][j], RHOM[i][j]))`.
        cell_manager.start_region();
        let mut lookup_counter = 0;
        let part_size = get_num_bits_per_base_chi_lookup();
        // To combine the rho/pi/chi steps we have to ensure a specific layout so
        // query those cells here first.
        // For chi we have to do `s[i][j] ^ ((~s[(i+1)%5][j]) & s[(i+2)%5][j])`. `j`
        // remains static but `i` is accessed in a wrap around manner. To do this using
        // multiple rows with lookups in a way that doesn't require any
        // extra additional cells or selectors we have to put all `s[i]`'s on the same
        // row. This isn't that strong of a requirement actually because we the
        // words are split into multipe parts, and so only the parts at the same
        // position of those words need to be on the same row.
        let target_word_sizes = target_part_sizes(part_size);
        let num_word_parts = target_word_sizes.len();
        let mut rho_pi_chi_cells: [[[Vec<Cell<F>>; 5]; 5]; 3] =
            std::array::from_fn(|_| std::array::from_fn(|_| std::array::from_fn(|_| Vec::new())));
        let mut num_columns = 0;
        let mut column_starts = [0usize; 3];
        for p in 0..3 {
            column_starts[p] = cell_manager.start_region();
            let mut row_idx = 0;
            num_columns = 0;
            for j in 0..5 {
                for _ in 0..num_word_parts {
                    for i in 0..5 {
                        rho_pi_chi_cells[p][i][j]
                            .push(cell_manager.query_cell_at_row(meta, row_idx));
                    }
                    if row_idx == 0 {
                        num_columns += 1;
                    }
                    row_idx = (((row_idx as usize) + 1) % get_num_rows_per_round()) as i32;
                }
            }
        }
        // Do the transformation, resulting in the word parts also being normalized.
        let pi_region_start = cell_manager.start_region();
        let mut os_parts = vec![vec![Vec::new(); 5]; 5];
        for (j, os_part) in os_parts.iter_mut().enumerate() {
            for i in 0..5 {
                // Split s into parts
                let s_parts = split_uniform::expr(
                    meta,
                    &rho_pi_chi_cells[0][j][(2 * i + 3 * j) % 5],
                    &mut cell_manager,
                    &mut cb,
                    s[i][j].clone(),
                    RHO_MATRIX[i][j],
                    part_size,
                );
                // Normalize the data to the target cells
                let s_parts = transform_to::expr(
                    "rho/pi",
                    meta,
                    &rho_pi_chi_cells[1][j][(2 * i + 3 * j) % 5],
                    &mut lookup_counter,
                    s_parts.clone(),
                    normalize_4,
                    true,
                );
                os_part[(2 * i + 3 * j) % 5] = s_parts.clone();
            }
        }
        let pi_region_end = cell_manager.start_region();
        // Pi parts range checks
        // To make the uniform stuff work we had to combine some parts together
        // in new cells (see split_uniform). Here we make sure those parts are range
        // checked. Potential improvement: Could combine multiple smaller parts
        // in a single lookup but doesn't save that much.
        for c in pi_region_start..pi_region_end {
            meta.lookup("pi part range check", |_| {
                vec![(cell_manager.columns()[c].expr.clone(), normalize_4[0])]
            });
            lookup_counter += 1;
        }
        info!("- Post rho/pi:");
        info!("Lookups: {}", lookup_counter);
        info!("Columns: {}", cell_manager.get_width());
        total_lookup_counter += lookup_counter;

        // Chi
        // In groups of 5 columns, we have to do `s[i][j] ^ ((~s[(i+1)%5][j]) &
        // s[(i+2)%5][j])` five times, on each row (no selector needed).
        // This is calculated by making use of `CHI_BASE_LOOKUP_TABLE`.
        let mut lookup_counter = 0;
        let part_size_base = get_num_bits_per_base_chi_lookup();
        for idx in 0..num_columns {
            // First fetch the cells we wan to use
            let mut input: [Expression<F>; 5] = std::array::from_fn(|_| 0.expr());
            let mut output: [Expression<F>; 5] = std::array::from_fn(|_| 0.expr());
            for c in 0..5 {
                input[c] = cell_manager.columns()[column_starts[1] + idx * 5 + c]
                    .expr
                    .clone();
                output[c] = cell_manager.columns()[column_starts[2] + idx * 5 + c]
                    .expr
                    .clone();
            }
            // Now calculate `a ^ ((~b) & c)` by doing `lookup[3 - 2*a + b - c]`
            for i in 0..5 {
                let input = scatter::expr(3, part_size_base) - 2.expr() * input[i].clone()
                    + input[(i + 1) % 5].clone()
                    - input[(i + 2) % 5].clone().clone();
                let output = output[i].clone();
                meta.lookup("chi base", |_| {
                    vec![
                        (input.clone(), chi_base_table[0]),
                        (output.clone(), chi_base_table[1]),
                    ]
                });
                lookup_counter += 1;
            }
        }
        // Now just decode the parts after the chi transformation done with the lookups
        // above.
        let mut os = vec![vec![0u64.expr(); 5]; 5];
        for (i, os) in os.iter_mut().enumerate() {
            for (j, os) in os.iter_mut().enumerate() {
                let mut parts = Vec::new();
                for idx in 0..num_word_parts {
                    parts.push(Part {
                        num_bits: part_size_base,
                        cell: rho_pi_chi_cells[2][i][j][idx].clone(),
                        expr: rho_pi_chi_cells[2][i][j][idx].expr(),
                    });
                }
                *os = decode::expr(parts);
            }
        }
        s = os.clone();

        // iota
        // Simply do the single xor on state [0][0].
        cell_manager.start_region();
        let part_size = get_num_bits_per_absorb_lookup();
        let input = s[0][0].clone() + round_cst_expr.clone();
        let iota_parts = split::expr(meta, &mut cell_manager, &mut cb, input, 0, part_size);
        cell_manager.start_region();
        // Could share columns with absorb which may end up using 1 lookup/column
        // fewer...
        s[0][0] = decode::expr(transform::expr(
            "iota",
            meta,
            &mut cell_manager,
            &mut lookup_counter,
            iota_parts,
            normalize_3,
            true,
        ));
        // Final results stored in the next row
        for i in 0..5 {
            for j in 0..5 {
                cb.require_equal("next row check", s[i][j].clone(), s_next[i][j].clone());
            }
        }
        info!("- Post chi:");
        info!("Lookups: {}", lookup_counter);
        info!("Columns: {}", cell_manager.get_width());
        total_lookup_counter += lookup_counter;

        let mut lookup_counter = 0;
        cell_manager.start_region();

        // Squeeze data
        let squeeze_from = cell_manager.query_cell(meta);
        let mut squeeze_from_prev = vec![0u64.expr(); NUM_WORDS_TO_SQUEEZE];
        for (idx, squeeze_from_prev) in squeeze_from_prev.iter_mut().enumerate() {
            let rot = (-(idx as i32) - 1) * get_num_rows_per_round() as i32;
            *squeeze_from_prev = squeeze_from.at_offset(meta, rot).expr();
        }
        // Squeeze
        // The squeeze happening at the end of the 24 rounds is done spread out
        // over those 24 rounds. In a single round (in 4 of the 24 rounds) a
        // single word is converted to bytes.
        // Potential optimization: could do multiple bytes per lookup
        cell_manager.start_region();
        // Unpack a single word into bytes (for the squeeze)
        // Potential optimization: could do multiple bytes per lookup
        let squeeze_from_parts =
            split::expr(meta, &mut cell_manager, &mut cb, squeeze_from.expr(), 0, 8);
        cell_manager.start_region();
        let squeeze_bytes = transform::expr(
            "squeeze unpack",
            meta,
            &mut cell_manager,
            &mut lookup_counter,
            squeeze_from_parts,
            pack_table
                .into_iter()
                .rev()
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
            true,
        );
        info!("- Post squeeze:");
        info!("Lookups: {}", lookup_counter);
        info!("Columns: {}", cell_manager.get_width());
        total_lookup_counter += lookup_counter;

        // The round constraints that we've been building up till now
        meta.create_gate("round", |meta| {
            cb.gate(meta.query_fixed(q_round, Rotation::cur()))
        });

        // Absorb
        meta.create_gate("absorb", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            let continue_hash = not::expr(start_new_hash(meta, Rotation::cur()));
            let absorb_positions = get_absorb_positions();
            let mut a_slice = 0;
            for j in 0..5 {
                for i in 0..5 {
                    if absorb_positions.contains(&(i, j)) {
                        cb.condition(continue_hash.clone(), |cb| {
                            cb.require_equal(
                                "absorb verify input",
                                absorb_from_next[a_slice].clone(),
                                pre_s[i][j].clone(),
                            );
                        });
                        cb.require_equal(
                            "absorb result copy",
                            select::expr(
                                continue_hash.clone(),
                                absorb_result_next[a_slice].clone(),
                                absorb_data_next[a_slice].clone(),
                            ),
                            s_next[i][j].clone(),
                        );
                        a_slice += 1;
                    } else {
                        cb.require_equal(
                            "absorb state copy",
                            pre_s[i][j].clone() * continue_hash.clone(),
                            s_next[i][j].clone(),
                        );
                    }
                }
            }
            cb.gate(meta.query_fixed(q_absorb, Rotation::cur()))
        });

        // Collect the bytes that are spread out over previous rows
        let mut hash_bytes = Vec::new();
        for i in 0..NUM_WORDS_TO_SQUEEZE {
            for byte in squeeze_bytes.iter() {
                let rot = (-(i as i32) - 1) * get_num_rows_per_round() as i32;
                hash_bytes.push(byte.cell.at_offset(meta, rot).expr());
            }
        }

        // Squeeze
        meta.create_gate("squeeze", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            let start_new_hash = start_new_hash(meta, Rotation::cur());
            // The words to squeeze
            let hash_words: Vec<_> = pre_s
                .into_iter()
                .take(4)
                .map(|a| a[0].clone())
                .take(4)
                .collect();
            // Verify if we converted the correct words to bytes on previous rows
            for (idx, word) in hash_words.iter().enumerate() {
                cb.condition(start_new_hash.clone(), |cb| {
                    cb.require_equal(
                        "squeeze verify packed",
                        word.clone(),
                        squeeze_from_prev[idx].clone(),
                    );
                });
            }
            let hash_bytes_le = hash_bytes.into_iter().rev().collect::<Vec<_>>();
            // below vector, [0] is lo, [1] is hi
            let lo_hi_vec: Vec<Expression<F>> = hash_bytes_le
                .chunks_exact(16)
                .map(|x| expr_from_bytes(x))
                .collect();
            let rlc = compose_rlc::expr(&hash_bytes_le, challenges_expr.evm_word());
            cb.condition(start_new_hash, |cb| {
                cb.require_equal(
                    "hash rlc check",
                    rlc,
                    meta.query_advice(hash_rlc, Rotation::cur()),
                );
                cb.require_equal(
                    "hash hi check",
                    lo_hi_vec[1].clone(),
                    meta.query_advice(hash_hi, Rotation::cur()),
                );
                cb.require_equal(
                    "hash lo check",
                    lo_hi_vec[0].clone(),
                    meta.query_advice(hash_lo, Rotation::cur()),
                );
            });
            cb.gate(meta.query_fixed(q_round_last, Rotation::cur()))
        });

        // Some general input checks
        meta.create_gate("input checks", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            cb.require_boolean(
                "boolean is_final",
                meta.query_advice(is_final, Rotation::cur()),
            );
            cb.gate(meta.query_fixed(q_enable, Rotation::cur()))
        });

        // Enforce fixed values on the first row
        meta.create_gate("first row", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            cb.require_zero(
                "is_final needs to be disabled on the first row",
                meta.query_advice(is_final, Rotation::cur()),
            );
            cb.gate(meta.query_fixed(q_first, Rotation::cur()))
        });

        // Enforce logic for when this block is the last block for a hash
        let last_is_padding_in_block = is_paddings.last().unwrap().at_offset(
            meta,
            -(((NUM_ROUNDS + 1 - NUM_WORDS_TO_ABSORB) * get_num_rows_per_round()) as i32),
        );
        meta.create_gate("is final", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            // All absorb rows except the first row
            cb.condition(
                meta.query_fixed(q_absorb, Rotation::cur())
                    - meta.query_fixed(q_first, Rotation::cur()),
                |cb| {
                    cb.require_equal(
                        "is_final needs to be the same as the last is_padding in the block",
                        meta.query_advice(is_final, Rotation::cur()),
                        last_is_padding_in_block.expr(),
                    );
                },
            );
            // For all the rows of a round, only the first row can have `is_final == 1`.
            cb.condition(
                (1..get_num_rows_per_round() as i32)
                    .map(|i| meta.query_fixed(q_enable, Rotation(-i)))
                    .fold(0.expr(), |acc, elem| acc + elem),
                |cb| {
                    cb.require_zero(
                        "is_final only when q_enable",
                        meta.query_advice(is_final, Rotation::cur()),
                    );
                },
            );
            cb.gate(1.expr())
        });

        // Padding
        // May be cleaner to do this padding logic in the byte conversion lookup but
        // currently easier to do it like this.
        let prev_is_padding = is_paddings
            .last()
            .unwrap()
            .at_offset(meta, -(get_num_rows_per_round() as i32));
        meta.create_gate("padding", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            let q_padding = meta.query_fixed(q_padding, Rotation::cur());
            let q_padding_last = meta.query_fixed(q_padding_last, Rotation::cur());

            // All padding selectors need to be boolean
            for is_padding in is_paddings.iter() {
                cb.condition(meta.query_fixed(q_enable, Rotation::cur()), |cb| {
                    cb.require_boolean("is_padding boolean", is_padding.expr());
                });
            }
            // This last padding selector will be used on the first round row so needs to be
            // zero
            cb.condition(meta.query_fixed(q_absorb, Rotation::cur()), |cb| {
                cb.require_zero(
                    "last is_padding should be zero on absorb rows",
                    is_paddings.last().unwrap().expr(),
                );
            });
            // Now for each padding selector
            for idx in 0..is_paddings.len() {
                // Previous padding selector can be on the previous row
                let is_padding_prev = if idx == 0 {
                    prev_is_padding.expr()
                } else {
                    is_paddings[idx - 1].expr()
                };
                let is_first_padding = is_paddings[idx].expr() - is_padding_prev.clone();

                // Check padding transition 0 -> 1 done only once
                cb.condition(q_padding.expr(), |cb| {
                    cb.require_boolean("padding step boolean", is_first_padding.clone());
                });

                // Padding start/intermediate/end byte checks
                if idx == is_paddings.len() - 1 {
                    // These can be combined in the future, but currently this would increase the
                    // degree by one Padding start/intermediate byte, all
                    // padding rows except the last one
                    cb.condition(
                        and::expr([
                            q_padding.expr() - q_padding_last.expr(),
                            is_paddings[idx].expr(),
                        ]),
                        |cb| {
                            // Input bytes need to be zero, or one if this is the first padding byte
                            cb.require_equal(
                                "padding start/intermediate byte last byte",
                                input_bytes[idx].expr.clone(),
                                is_first_padding.expr(),
                            );
                        },
                    );
                    // Padding start/end byte, only on the last padding row
                    cb.condition(
                        and::expr([q_padding_last.expr(), is_paddings[idx].expr()]),
                        |cb| {
                            // The input byte needs to be 128, unless it's also the first padding
                            // byte then it's 129
                            cb.require_equal(
                                "padding start/end byte",
                                input_bytes[idx].expr.clone(),
                                is_first_padding.expr() + 128.expr(),
                            );
                        },
                    );
                } else {
                    // Padding start/intermediate byte
                    cb.condition(
                        and::expr([q_padding.expr(), is_paddings[idx].expr()]),
                        |cb| {
                            // Input bytes need to be zero, or one if this is the first padding byte
                            cb.require_equal(
                                "padding start/intermediate byte",
                                input_bytes[idx].expr.clone(),
                                is_first_padding.expr(),
                            );
                        },
                    );
                }
            }
            cb.gate(1.expr())
        });

        // Length and input data rlc
        meta.create_gate("length and data rlc", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);

            let q_padding = meta.query_fixed(q_padding, Rotation::cur());
            let start_new_hash_prev =
                start_new_hash(meta, Rotation(-(get_num_rows_per_round() as i32)));
            let length_prev =
                meta.query_advice(length, Rotation(-(get_num_rows_per_round() as i32)));
            let length = meta.query_advice(length, Rotation::cur());
            let data_rlc_prev =
                meta.query_advice(data_rlc, Rotation(-(get_num_rows_per_round() as i32)));
            let data_rlcs: Vec<_> = (0..NUM_BYTES_PER_WORD + 1)
                .map(|i| meta.query_advice(data_rlc, Rotation(i as i32)))
                .collect();
            assert_eq!(data_rlcs.len(), input_bytes.len() + 1);

            // Update the length/data_rlc on rows where we absorb data
            cb.condition(q_padding.expr(), |cb| {
                // Length increases by the number of bytes that aren't padding
                cb.require_equal(
                    "update length",
                    length.clone(),
                    length_prev.clone() * not::expr(start_new_hash_prev.expr())
                        + sum::expr(
                            is_paddings
                                .iter()
                                .map(|is_padding| not::expr(is_padding.expr())),
                        ),
                );
                let mut new_data_rlc = data_rlcs[NUM_BYTES_PER_WORD].expr();

                // At the start of a hash, start at 0. Otherwise, continue from the previous
                // value.
                let data_rlc_zero_or_prev =
                    data_rlc_prev.clone() * not::expr(start_new_hash_prev.expr());
                cb.require_equal(
                    "initial data rlc",
                    data_rlc_zero_or_prev,
                    new_data_rlc.clone(),
                );

                // Add the word `input_bytes` to `data_rlc`. It has a variable length
                // represented by `is_paddings`, which requires intermediate
                // cells to keep the degree low.
                for (idx, (byte, is_padding)) in
                    input_bytes.iter().zip(is_paddings.iter()).enumerate()
                {
                    new_data_rlc = select::expr(
                        is_padding.expr(),
                        new_data_rlc.clone(),
                        new_data_rlc.clone() * challenges_expr.keccak_input() + byte.expr.clone(),
                    );
                    let data_rlc_after_this_byte = data_rlcs[NUM_BYTES_PER_WORD - (idx + 1)].expr();
                    cb.require_equal(
                        "intermediate data rlc",
                        data_rlc_after_this_byte.clone(),
                        new_data_rlc,
                    );
                    new_data_rlc = data_rlc_after_this_byte;
                }
                // At this point, `data_rlcs[0]` includes the new input word. It
                // will be copied into the next round, or it is
                // the final `input_rlc` in the lookup table.
            });
            // Keep length/data_rlc the same on rows where we don't absorb data
            cb.condition(
                and::expr([
                    meta.query_fixed(q_enable, Rotation::cur())
                        - meta.query_fixed(q_first, Rotation::cur()),
                    not::expr(q_padding),
                ]),
                |cb| {
                    cb.require_equal("length equality check", length.clone(), length_prev.clone());
                    cb.require_equal(
                        "data_rlc equality check",
                        data_rlcs[0].clone(),
                        data_rlc_prev.clone(),
                    );
                },
            );
            cb.gate(1.expr())
        });

        normalize_3.iter().enumerate().for_each(|(idx, &col)| {
            meta.annotate_lookup_column(col, || format!("KECCAK_normalize_3_{}", idx))
        });
        normalize_4.iter().enumerate().for_each(|(idx, &col)| {
            meta.annotate_lookup_column(col, || format!("KECCAK_normalize_4_{}", idx))
        });
        normalize_6.iter().enumerate().for_each(|(idx, &col)| {
            meta.annotate_lookup_column(col, || format!("KECCAK_normalize_6_{}", idx))
        });
        chi_base_table.iter().enumerate().for_each(|(idx, &col)| {
            meta.annotate_lookup_column(col, || format!("KECCAK_chi_base_{}", idx))
        });
        pack_table.iter().enumerate().for_each(|(idx, &col)| {
            meta.annotate_lookup_column(col, || format!("KECCAK_pack_table_{}", idx))
        });

        info!("Degree: {}", meta.degree());
        info!("Minimum rows: {}", meta.minimum_rows());
        info!("Total Lookups: {}", total_lookup_counter);
        info!("Total Columns: {}", cell_manager.get_width());
        info!("num unused cells: {}", cell_manager.get_num_unused_cells());
        info!("part_size absorb: {}", get_num_bits_per_absorb_lookup());
        info!("part_size theta: {}", get_num_bits_per_theta_c_lookup());
        info!(
            "part_size theta c: {}",
            get_num_bits_per_lookup(THETA_C_LOOKUP_RANGE)
        );
        info!("part_size theta t: {}", get_num_bits_per_lookup(4));
        info!("part_size rho/pi: {}", get_num_bits_per_rho_pi_lookup());
        info!("part_size chi base: {}", get_num_bits_per_base_chi_lookup());
        info!(
            "uniform part sizes: {:?}",
            target_part_sizes(get_num_bits_per_theta_c_lookup())
        );

        KeccakCircuitConfig {
            q_enable,
            q_first,
            q_round,
            q_absorb,
            q_round_last,
            q_padding,
            q_padding_last,
            is_final,
            input_rlc: data_rlc,
            input_len: length,
            output_rlc: hash_rlc,
            output_hi: hash_hi,
            output_lo: hash_lo,
            cell_manager,
            round_cst,
            normalize_3,
            normalize_4,
            normalize_6,
            chi_base_table,
            pack_table,
            _marker: PhantomData,
        }
    }
}

impl<F: Field> KeccakCircuitConfig<F> {
    pub(crate) fn assign_with_region(
        &self,
        region: &mut Region<'_, F>,
        rows: &[KeccakRow<F>],
        num_row_incl_padding: usize,
    ) -> Result<(), Error> {
        // assign the rest rows
        for (offset, keccak_row) in rows.iter().enumerate() {
            self.set_row(region, offset, keccak_row)?;
        }
        Ok(())
    }

    fn set_row(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        row: &KeccakRow<F>,
    ) -> Result<(), Error> {
        // Fixed selectors
        for (name, column, value) in &[
            ("q_enable", self.q_enable, F::from(row.q_enable as u64)),
            ("q_first", self.q_first, F::from((offset == 0) as u64)),
            ("q_round", self.q_round, F::from(row.q_round as u64)),
            (
                "q_round_last",
                self.q_round_last,
                F::from(row.q_round_last as u64),
            ),
            ("q_absorb", self.q_absorb, F::from(row.q_absorb as u64)),
            ("q_padding", self.q_padding, F::from(row.q_padding as u64)),
            (
                "q_padding_last",
                self.q_padding_last,
                F::from(row.q_padding_last as u64),
            ),
        ] {
            region.assign_fixed(
                || format!("assign {} {}", name, offset),
                *column,
                offset,
                || Value::known(*value),
            )?;
        }

        for (name, column, value) in &[
            (
                "is_final",
                self.is_final,
                Value::known(F::from(row.is_final as u64)),
            ),
            ("input_rlc", self.input_rlc, row.data_rlc),
            (
                "input_len",
                self.input_len,
                Value::known(F::from(row.length as u64)),
            ),
            ("output_rlc", self.output_rlc, row.hash_rlc),
            ("output_hi", self.output_hi, Value::known(row.hash_hi)),
            ("output_lo", self.output_lo, Value::known(row.hash_lo)),
        ] {
            region.assign_advice(
                || format!("assign {} {}", name, offset),
                *column,
                offset,
                || *value,
            )?;
        }

        // Cell values
        for (idx, (bit, column)) in row
            .cell_values
            .iter()
            .zip(self.cell_manager.columns())
            .enumerate()
        {
            region.assign_advice(
                || format!("assign lookup value {} {}", idx, offset),
                column.advice,
                offset,
                || Value::known(*bit),
            )?;
        }

        // Round constant
        region.assign_fixed(
            || format!("assign round cst {}", offset),
            self.round_cst,
            offset,
            || Value::known(row.round_cst),
        )?;

        Ok(())
    }

    pub(crate) fn load_aux_tables(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        load_normalize_table(layouter, "normalize_6", &self.normalize_6, 6u64)?;
        load_normalize_table(layouter, "normalize_4", &self.normalize_4, 4u64)?;
        load_normalize_table(layouter, "normalize_3", &self.normalize_3, 3u64)?;
        load_lookup_table(
            layouter,
            "chi base",
            &self.chi_base_table,
            get_num_bits_per_base_chi_lookup(),
            &CHI_BASE_LOOKUP_TABLE,
        )?;
        load_pack_table(layouter, &self.pack_table)
    }

    fn annotate_circuit_in_region(&self, region: &mut Region<F>) {
        region.name_column(|| "KECCAK_q_enable", self.q_enable);
        region.name_column(|| "KECCAK_q_first", self.q_first);
        region.name_column(|| "KECCAK_q_round", self.q_round);
        region.name_column(|| "KECCAK_q_absorb", self.q_absorb);
        region.name_column(|| "KECCAK_q_round_last", self.q_round_last);
        region.name_column(|| "KECCAK_q_padding_last", self.q_padding_last);
        region.name_column(|| "KECCAK_is_final", self.is_final);
        region.name_column(|| "KECCAK_input_rlc", self.input_rlc);
        region.name_column(|| "KECCAK_input_len", self.input_len);
        region.name_column(|| "KECCAK_output_rlc", self.output_rlc);
        region.name_column(|| "KECCAK_output_hi", self.output_hi);
        region.name_column(|| "KECCAK_output_lo", self.output_lo);
    }
}

/// KeccakCircuit
#[derive(Default, Clone, Debug)]
pub struct KeccakCircuit<F: Field, const MAX_NUM_ROW: usize> {
    witness: Witness,
    _marker: PhantomData<F>,
}

impl<F: Field, const MAX_NUM_ROW: usize> SubCircuit<F> for KeccakCircuit<F, MAX_NUM_ROW> {
    type Config = KeccakCircuitConfig<F>;
    type Cells = ();
    fn unusable_rows() -> (usize, usize) {
        (get_num_rows_per_round(), keccak_unusable_rows())
    }

    fn new_from_witness(witness: &Witness) -> Self {
        KeccakCircuit {
            witness: witness.clone(),
            _marker: PhantomData,
        }
    }

    fn num_rows(witness: &Witness) -> usize {
        Self::unusable_rows().0
            + Self::unusable_rows().1
            + witness.keccak.len() * (NUM_ROUNDS + 1) * get_num_rows_per_round()
    }

    fn synthesize_sub(
        &self,
        config: &Self::Config,
        layouter: &mut impl Layouter<F>,
        challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        // load aux tables
        config.load_aux_tables(layouter)?;

        // gen witnss rows
        let keccak_rows = self.gen_rows(*challenges)?;

        // assign value to cell
        layouter.assign_region(
            || "assign keccak rows",
            |mut region| {
                // set column information
                config.annotate_circuit_in_region(&mut region);

                // assign circuit table value
                config.assign_with_region(&mut region, keccak_rows.as_slice(), MAX_NUM_ROW)?;
                Ok(())
            },
        )
    }
}
impl<F: Field, const MAX_NUM_ROW: usize> KeccakCircuit<F, MAX_NUM_ROW> {
    /// The number of keccak_f's that can be done in this circuit
    pub fn capacity(&self) -> Option<usize> {
        if MAX_NUM_ROW > 0 {
            // Subtract two for unusable rows
            Some(MAX_NUM_ROW / ((NUM_ROUNDS + 1) * get_num_rows_per_round()) - 2)
        } else {
            None
        }
    }

    /// Sets the witness using the data to be hashed
    pub(crate) fn gen_rows(
        &self,
        challenges: Challenges<Value<F>>,
    ) -> Result<Vec<KeccakRow<F>>, Error> {
        multi_keccak(self.witness.keccak.as_slice(), challenges, self.capacity())
    }
}

/// test code
#[cfg(test)]
mod test {
    use super::*;
    use crate::keccak_circuit::keccak_packed_multi::{calc_keccak_hi_lo, calc_keccak_with_rlc};
    use crate::util::log2_ceil;
    use halo2_proofs::circuit::SimpleFloorPlanner;
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::halo2curves::bn256::Fr;
    use halo2_proofs::plonk::{Circuit, FirstPhase, SecondPhase};

    #[derive(Clone, Debug, Default)]
    pub struct KeccakTestRow<F: Field> {
        pub input_len: Value<F>,
        pub input_rlc: Value<F>,
        pub output_rlc: Value<F>,
        pub output_hi: Value<F>,
        pub output_lo: Value<F>,
    }

    #[derive(Clone)]
    pub struct KeccakTestCircuitConfig<F: Field> {
        q_enable: Selector,
        pub keccak_circuit: KeccakCircuitConfig<F>,

        // First phase
        pub input_len: Column<Advice>,
        pub challenges: Challenges,

        pub output_hi: Column<Advice>,
        pub output_lo: Column<Advice>,
        // Second phase
        pub input_rlc: Column<Advice>,
        pub output_rlc: Column<Advice>,
    }

    impl<F: Field> SubCircuitConfig<F> for KeccakTestCircuitConfig<F> {
        type ConfigArgs = ();

        /// Constructor， used to construct config object
        fn new(meta: &mut ConstraintSystem<F>, _args: Self::ConfigArgs) -> Self {
            let q_enable = meta.complex_selector();
            let keccak_table = KeccakTable::construct(meta);
            let challenges = Challenges::construct(meta);
            let keccak_circuit = KeccakCircuitConfig::new(
                meta,
                KeccakCircuitConfigArgs {
                    keccak_table,
                    challenges,
                },
            );
            KeccakTestCircuitConfig {
                q_enable,
                keccak_circuit,
                input_len: meta.advice_column(),
                input_rlc: meta.advice_column_in(SecondPhase),
                output_rlc: meta.advice_column_in(SecondPhase),
                challenges,
                output_hi: meta.advice_column(),
                output_lo: meta.advice_column(),
            }
        }
    }

    impl<F: Field> KeccakTestCircuitConfig<F> {
        /// assign BitwiseTestCircuit rows
        pub fn assign_with_region(
            &self,
            region: &mut Region<'_, F>,
            offset: usize,
            row: &KeccakTestRow<F>,
        ) -> Result<(), Error> {
            for (name, column, value) in &[
                // First phase
                ("input_len", self.input_len, row.input_len),
                // Second phase
                ("input_rlc", self.input_rlc, row.input_rlc),
                ("output_rlc", self.output_rlc, row.output_rlc),
                ("output_hi", self.output_hi, row.output_hi),
                ("output_lo", self.output_lo, row.output_lo),
            ] {
                region.assign_advice(
                    || format!("assign {} {}", name, offset),
                    *column,
                    offset,
                    || *value,
                )?;
            }
            Ok(())
        }
    }

    /// BitwiseTestCircuitConfig is a Circuit used for testing
    #[derive(Clone, Default, Debug)]
    pub struct KeccakTestCircuit<F: Field, const MAX_NUM_ROW: usize> {
        pub keccak_circuit: KeccakCircuit<F, MAX_NUM_ROW>,
        pub witness: Witness,
    }

    impl<F: Field, const MAX_NUM_ROW: usize> Circuit<F> for KeccakTestCircuit<F, MAX_NUM_ROW> {
        type Config = KeccakTestCircuitConfig<F>;
        type FloorPlanner = SimpleFloorPlanner;
        type Params = ();

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            // construct config object
            let config = Self::Config::new(meta, ());

            // Lookup logic code
            //used to verify whether acc_0, acc_1, acc_2, sum2 can be correctly looked up
            meta.lookup_any("keccak_circuit test lookup", |meta| {
                // get the value of the specified Column in BitwiseTestCircuit
                let input_rlc = meta.query_advice(config.input_rlc, Rotation::cur());
                let input_len = meta.query_advice(config.input_len, Rotation::cur());
                let output_rlc = meta.query_advice(config.output_rlc, Rotation::cur());
                let output_hi = meta.query_advice(config.output_hi, Rotation::cur());
                let output_lo = meta.query_advice(config.output_lo, Rotation::cur());

                // get the value of the specified Column in BitwiseCircuit
                let keccak_circuit_input_rlc =
                    meta.query_advice(config.keccak_circuit.input_rlc, Rotation::cur());
                let keccak_circuit_input_len =
                    meta.query_advice(config.keccak_circuit.input_len, Rotation::cur());
                let keccak_circuit_output_rlc =
                    meta.query_advice(config.keccak_circuit.output_rlc, Rotation::cur());
                let keccak_circuit_output_hi =
                    meta.query_advice(config.keccak_circuit.output_hi, Rotation::cur());
                let keccak_circuit_output_lo =
                    meta.query_advice(config.keccak_circuit.output_lo, Rotation::cur());

                let q_enable = meta.query_selector(config.q_enable);
                vec![
                    (q_enable.clone() * input_rlc, keccak_circuit_input_rlc),
                    (q_enable.clone() * input_len, keccak_circuit_input_len),
                    (q_enable.clone() * output_rlc, keccak_circuit_output_rlc),
                    (q_enable.clone() * output_hi, keccak_circuit_output_hi),
                    (q_enable.clone() * output_lo, keccak_circuit_output_lo),
                ]
            });

            config
        }
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let challenges = config.challenges.values(&mut layouter);

            // gen rows
            let keccak_test_rows: Vec<KeccakTestRow<F>> = self.gen_rows(challenges);

            // assign row
            layouter.assign_region(
                || "keccak test circuit",
                |mut region| {
                    for (offset, row) in keccak_test_rows.iter().enumerate() {
                        config.q_enable.enable(&mut region, offset)?;
                        config.assign_with_region(&mut region, offset, row)?;
                    }
                    Ok(())
                },
            )?;

            // synthesize sub circuit
            self.keccak_circuit
                .synthesize_sub(&config.keccak_circuit, &mut layouter, &challenges)
        }
    }

    impl<F: Field, const MAX_NUM_ROW: usize> KeccakTestCircuit<F, MAX_NUM_ROW> {
        pub fn new(witness: &Witness) -> Self {
            Self {
                keccak_circuit: KeccakCircuit::new_from_witness(witness),
                witness: witness.clone(),
            }
        }
        pub fn instance(&self) -> Vec<Vec<F>> {
            let mut vec = Vec::new();
            vec.extend(self.keccak_circuit.instance());
            vec
        }

        pub(crate) fn gen_rows(&self, challenges: Challenges<Value<F>>) -> Vec<KeccakTestRow<F>> {
            let mut keccak_test_rows: Vec<KeccakTestRow<F>> = vec![];

            for input in self.witness.keccak.iter() {
                let (input_len, input_rlc, output_rlc) =
                    calc_keccak_with_rlc::<F>(input.as_slice(), &challenges);
                let (output_hi, output_lo) = calc_keccak_hi_lo(input.as_slice());
                keccak_test_rows.push(KeccakTestRow {
                    input_len,
                    input_rlc,
                    output_rlc,
                    output_hi: Value::known(F::from_u128(output_hi)),
                    output_lo: Value::known(F::from_u128(output_lo)),
                });
            }

            keccak_test_rows
        }
    }

    fn run_keccak_circuit<F: Field, const TEST_MAX_NUM_ROW: usize>(inputs: Vec<Vec<u8>>) {
        let mut witness = Witness::default();
        witness.keccak = inputs;

        let k = log2_ceil(TEST_MAX_NUM_ROW);
        let circuit = KeccakTestCircuit::<F, TEST_MAX_NUM_ROW>::new(&witness);

        let instance = circuit.instance();
        let prover = MockProver::<F>::run(k, &circuit, instance).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_keccak() {
        let inputs = vec![
            "Hello World".as_bytes().to_vec(),
            "Hello World2".as_bytes().to_vec(),
            "Hello World3".as_bytes().to_vec(),
        ];
        const TEST_MAX_NUM_ROW: usize = 1600;
        run_keccak_circuit::<Fr, TEST_MAX_NUM_ROW>(inputs);
    }

    // test bytecode hash(erc20 bytecode)
    #[test]
    fn test_bytecode_hash() {
        let contract_bytecode = hex::decode("608060405234801561001057600080fd5b50600436106100935760003560e01c8063313ce56711610066578063313ce5671461013457806370a082311461015257806395d89b4114610182578063a9059cbb146101a0578063dd62ed3e146101d057610093565b806306fdde0314610098578063095ea7b3146100b657806318160ddd146100e657806323b872dd14610104575b600080fd5b6100a0610200565b6040516100ad9190610aa9565b60405180910390f35b6100d060048036038101906100cb9190610b64565b610292565b6040516100dd9190610bbf565b60405180910390f35b6100ee6102b5565b6040516100fb9190610be9565b60405180910390f35b61011e60048036038101906101199190610c04565b6102bf565b60405161012b9190610bbf565b60405180910390f35b61013c6102ee565b6040516101499190610c73565b60405180910390f35b61016c60048036038101906101679190610c8e565b6102f7565b6040516101799190610be9565b60405180910390f35b61018a61033f565b6040516101979190610aa9565b60405180910390f35b6101ba60048036038101906101b59190610b64565b6103d1565b6040516101c79190610bbf565b60405180910390f35b6101ea60048036038101906101e59190610cbb565b6103f4565b6040516101f79190610be9565b60405180910390f35b60606003805461020f90610d2a565b80601f016020809104026020016040519081016040528092919081815260200182805461023b90610d2a565b80156102885780601f1061025d57610100808354040283529160200191610288565b820191906000526020600020905b81548152906001019060200180831161026b57829003601f168201915b5050505050905090565b60008061029d61047b565b90506102aa818585610483565b600191505092915050565b6000600254905090565b6000806102ca61047b565b90506102d7858285610495565b6102e2858585610529565b60019150509392505050565b60006012905090565b60008060008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020549050919050565b60606004805461034e90610d2a565b80601f016020809104026020016040519081016040528092919081815260200182805461037a90610d2a565b80156103c75780601f1061039c576101008083540402835291602001916103c7565b820191906000526020600020905b8154815290600101906020018083116103aa57829003601f168201915b5050505050905090565b6000806103dc61047b565b90506103e9818585610529565b600191505092915050565b6000600160008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054905092915050565b600033905090565b610490838383600161061d565b505050565b60006104a184846103f4565b90507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff81146105235781811015610513578281836040517ffb8f41b200000000000000000000000000000000000000000000000000000000815260040161050a93929190610d6a565b60405180910390fd5b6105228484848403600061061d565b5b50505050565b600073ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff160361059b5760006040517f96c6fd1e0000000000000000000000000000000000000000000000000000000081526004016105929190610da1565b60405180910390fd5b600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff160361060d5760006040517fec442f050000000000000000000000000000000000000000000000000000000081526004016106049190610da1565b60405180910390fd5b6106188383836107f4565b505050565b600073ffffffffffffffffffffffffffffffffffffffff168473ffffffffffffffffffffffffffffffffffffffff160361068f5760006040517fe602df050000000000000000000000000000000000000000000000000000000081526004016106869190610da1565b60405180910390fd5b600073ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff16036107015760006040517f94280d620000000000000000000000000000000000000000000000000000000081526004016106f89190610da1565b60405180910390fd5b81600160008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000208190555080156107ee578273ffffffffffffffffffffffffffffffffffffffff168473ffffffffffffffffffffffffffffffffffffffff167f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925846040516107e59190610be9565b60405180910390a35b50505050565b600073ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff160361084657806002600082825461083a9190610deb565b92505081905550610919565b60008060008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020549050818110156108d2578381836040517fe450d38c0000000000000000000000000000000000000000000000000000000081526004016108c993929190610d6a565b60405180910390fd5b8181036000808673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002081905550505b600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff160361096257806002600082825403925050819055506109af565b806000808473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600082825401925050819055505b8173ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef83604051610a0c9190610be9565b60405180910390a3505050565b600081519050919050565b600082825260208201905092915050565b60005b83811015610a53578082015181840152602081019050610a38565b60008484015250505050565b6000601f19601f8301169050919050565b6000610a7b82610a19565b610a858185610a24565b9350610a95818560208601610a35565b610a9e81610a5f565b840191505092915050565b60006020820190508181036000830152610ac38184610a70565b905092915050565b600080fd5b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b6000610afb82610ad0565b9050919050565b610b0b81610af0565b8114610b1657600080fd5b50565b600081359050610b2881610b02565b92915050565b6000819050919050565b610b4181610b2e565b8114610b4c57600080fd5b50565b600081359050610b5e81610b38565b92915050565b60008060408385031215610b7b57610b7a610acb565b5b6000610b8985828601610b19565b9250506020610b9a85828601610b4f565b9150509250929050565b60008115159050919050565b610bb981610ba4565b82525050565b6000602082019050610bd46000830184610bb0565b92915050565b610be381610b2e565b82525050565b6000602082019050610bfe6000830184610bda565b92915050565b600080600060608486031215610c1d57610c1c610acb565b5b6000610c2b86828701610b19565b9350506020610c3c86828701610b19565b9250506040610c4d86828701610b4f565b9150509250925092565b600060ff82169050919050565b610c6d81610c57565b82525050565b6000602082019050610c886000830184610c64565b92915050565b600060208284031215610ca457610ca3610acb565b5b6000610cb284828501610b19565b91505092915050565b60008060408385031215610cd257610cd1610acb565b5b6000610ce085828601610b19565b9250506020610cf185828601610b19565b9150509250929050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602260045260246000fd5b60006002820490506001821680610d4257607f821691505b602082108103610d5557610d54610cfb565b5b50919050565b610d6481610af0565b82525050565b6000606082019050610d7f6000830186610d5b565b610d8c6020830185610bda565b610d996040830184610bda565b949350505050565b6000602082019050610db66000830184610d5b565b92915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b6000610df682610b2e565b9150610e0183610b2e565b9250828201905080821115610e1957610e18610dbc565b5b9291505056fea26469706673582212207ef90879a9819dc308c47292d92690fe9e06d677b6789e505c2e6e06df3af31764736f6c63430008140033").unwrap();
        let inputs = vec![contract_bytecode];

        const TEST_MAX_NUM_ROW: usize = 16000;

        run_keccak_circuit::<Fr, TEST_MAX_NUM_ROW>(inputs);
    }
}
