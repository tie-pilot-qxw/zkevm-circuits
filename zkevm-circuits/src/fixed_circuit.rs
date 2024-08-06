// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::table::FixedTable;
use crate::util::{assign_advice_or_fixed_with_u256, Challenges, SubCircuit, SubCircuitConfig};
use crate::witness::{fixed, Witness};
use eth_types::evm_types::OpcodeId;
use eth_types::{Field, U256};
use halo2_proofs::circuit::{Layouter, Region, Value};
use halo2_proofs::plonk::{Column, ConstraintSystem, Error, Fixed};
use std::marker::PhantomData;

///  Used to determine whether cnt is greater than 15
const OPCODE_CNT_15: usize = 15;

/// Fixed 电路需要的数据列；由一个Tag和3个数据列组成
/// 在Witness中为不同场景预先生成一行行（Row）数据，将它们填入Fixed Table
/// 中作为lookup查询的去向，优化在电路运算过程常见的计算场景（如：8bit范围的与、
/// 或、异或运算）；nbit的数据范围证明：为了在零知识证明中实现范围比较，通常需要
/// 使用额外的技巧和方法，如进行查表，预先将一段范围的数据填入表中，范围比较时将
/// 数据查表，如果在表中，则表示数据在指定范围。
#[derive(Clone, Debug)]
pub struct FixedCircuitConfig<F> {
    tag: Column<Fixed>,
    values: [Column<Fixed>; 3],
    _marker: PhantomData<F>,
}

pub struct FixedCircuitConfigArgs {
    pub fixed_table: FixedTable,
}

impl<F: Field> SubCircuitConfig<F> for FixedCircuitConfig<F> {
    type ConfigArgs = FixedCircuitConfigArgs;

    fn new(
        _meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs { fixed_table }: Self::ConfigArgs,
    ) -> Self {
        let FixedTable { tag, values } = fixed_table;
        Self {
            tag,
            values,
            _marker: PhantomData,
        }
    }
}

impl<F: Field> FixedCircuitConfig<F> {
    /// 对fixed table进行填值
    fn assgin_with_region(&self, region: &mut Region<'_, F>) -> Result<(), Error> {
        // 构造闭包操作，将生成的row数据赋值到表格中指定列的指定位置
        #[rustfmt::skip]
        let assign_row = |row: &fixed::Row, index| -> Result<(), Error> {
            assign_advice_or_fixed_with_u256(region, index, &U256::from(row.tag as u32), self.tag)?;
            assign_advice_or_fixed_with_u256(region, index, &row.value_0.unwrap_or_default(), self.values[0])?;
            assign_advice_or_fixed_with_u256(region, index, &row.value_1.unwrap_or_default(), self.values[1])?;
            assign_advice_or_fixed_with_u256(region, index, &row.value_2.unwrap_or_default(), self.values[2])?;
            Ok(())
        };
        // 1. 构造表格需要的row数据
        // 2. 调用传入的闭包进行赋值
        Self::assign(assign_row)?;
        Ok(())
    }

    fn assign(
        mut assign_row: impl FnMut(&fixed::Row, usize) -> Result<(), Error>,
    ) -> Result<usize, Error> {
        // Create rows with different states required by fixed_table

        // assign opcode
        let mut vec = vec![];
        for opcode in OpcodeId::valid_opcodes() {
            vec.push(fixed::Row {
                tag: fixed::Tag::Bytecode,
                // bytecode
                value_0: Some(U256::from(opcode.as_u8())),
                // cnt
                value_1: Some(U256::from(opcode.data_len())),
                // is_high(cnt > 15), true:1, false:0
                value_2: Some(U256::from((opcode.data_len() > OPCODE_CNT_15) as u8)),
            });
        }
        // assign invalid opcode
        // otherwise the bytecode containing invalid opcodes cannot lookup into this circuit
        for opcode in OpcodeId::invalid_opcodes() {
            vec.push(fixed::Row {
                tag: fixed::Tag::Bytecode,
                // bytecode
                value_0: Some(U256::from(opcode.as_u8())),
                ..Default::default()
            });
        }

        // 生成逻辑运算（And/Or）需要的row数据 ==>  0-255行
        // 为紧凑电路布局, 所以u16复用了逻辑运算的中填写的value_0列数据[0..255]
        let operand_num = 1 << 8;
        for tag in [fixed::Tag::And, fixed::Tag::Or].iter() {
            vec.append(&mut Self::assign_with_tag_value(*tag, operand_num));
        }
        // assign u10 and part of u16
        // tag value_0 value_1 value_2
        //      256    U10_TAG	1
        //      ...	   U10_TAG	...
        //      1279   U10_TAG	1024
        let begin = 1 << 8;
        for i in 0..1 << 10 {
            vec.push(fixed::Row {
                // part of u16
                // 紧凑电路布局，因为Row有3列数据，将后2列数据分配给U10，第一列数据value_0分
                // 配给U16使用，因为在u8的And、Or 逻辑操作中，该列已经填写
                // 了[0..255]范围的数据，因此在与U10复用一行数据时，起始值需要除去已填写的范围,
                // 因此在u10赋值过程中，value_0将添加[256..1279]
                // value_2的值赋值范围是[1..1024],所以为 i+1
                value_0: Some(U256::from(i + begin)),
                value_1: Some(U256::from(fixed::U10_TAG)),
                value_2: Some(U256::from(i + 1)),
                ..Default::default()
            });
        }

        // assign u16
        // 填写u16范围从1 << 10+begin开始，因为在u8的逻辑运算与u10的填写过程中，已经将value_0列填写
        // 了部分数值[0..255], [255..1279]，此处为填写u16范围剩余部分的值[1280..]
        // tag value_0 value_1 value_2
        //      1280
        //      ....
        //      65535
        for i in (1 << 10) + begin..1 << 16 {
            vec.push(fixed::Row {
                value_0: Some(U256::from(i)),
                ..Default::default()
            });
        }

        // Write the data of each row into the corresponding column
        for (i, row) in vec.iter().enumerate() {
            assign_row(row, i)?;
        }

        // return the number of rows
        Ok(vec.len())
    }

    // 生成逻辑运算需要的row数据
    fn assign_with_tag_value(tag: fixed::Tag, operand_num: usize) -> Vec<fixed::Row> {
        let f = match tag {
            fixed::Tag::And => |i, j| i & j,
            fixed::Tag::Or => |i, j| i | j,
            _ => panic!("not known tag {:?}", tag),
        };

        let mut vec = vec![];
        for i in 0..operand_num {
            for j in 0..operand_num {
                let row = fixed::Row {
                    tag: tag,
                    value_0: Some(U256::from(i)),
                    value_1: Some(U256::from(j)),
                    value_2: Some(U256::from(f(i, j))),
                };
                vec.push(row);
            }
        }
        // tag value_0 value_1 value_2
        // And	0	0	0
        // And	0	1	0
        // And	...	...	...
        // And	255	0	0
        // And	255	1	1
        // Or	0	0	0
        // Or	0	1	1
        // Or	...	...	...
        vec
    }
}

/// Fixed circuit是在电路初始化阶段预先向fixed_table填入一些cell数据，
/// 在后续电路运行过程中进行lookup查表操作；
/// 当前fixed_table填入了几种类型的数据：1. evm opcode的信息，
/// 2. 8bit范围内数据的与、或、异或操作结果，3. 10bit、16bit可表示的全量的数据，
/// 用于数据的范围证明。注意，10bit数据我们的数据是1-1024，不是0-1023。16bit数据是0-65535
#[derive(Clone, Default, Debug)]
pub struct FixedCircuit<F: Field> {
    _marker: PhantomData<F>,
}

impl<F: Field> SubCircuit<F> for FixedCircuit<F> {
    type Config = FixedCircuitConfig<F>;
    type Cells = ();

    fn new_from_witness(_witness: &Witness) -> Self {
        FixedCircuit {
            _marker: PhantomData,
        }
    }

    fn synthesize_sub(
        &self,
        config: &Self::Config,
        layouter: &mut impl Layouter<F>,
        _challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "fixed circuit",
            |mut region| config.assgin_with_region(&mut region),
        )
    }

    fn unusable_rows() -> (usize, usize) {
        (0, 0)
    }

    fn num_rows(_witness: &Witness) -> usize {
        let f = |_row: &_, _index| -> Result<(), Error> { Ok(()) };
        FixedCircuitConfig::<F>::assign(f).unwrap()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::table::{FixedTable, LookupEntry};
    use crate::util::log2_ceil;
    use crate::witness::Witness;
    use eth_types::Field;
    use gadgets::util::Expr;
    use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner};
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::halo2curves::bn256::Fr as Fp;
    use halo2_proofs::plonk::{Advice, Circuit, ConstraintSystem, Error, Selector};
    use halo2_proofs::poly::Rotation;

    #[derive(Clone)]
    pub struct FixedTestCircuitConfig<F: Field> {
        pub fixed_circuit: FixedCircuitConfig<F>,
        /// Test data, query the data in different fields belonging
        /// to the corresponding range (u16/u10/u8)
        pub selector: Selector,
        pub test_u16: Column<Advice>,
        pub test_u10: Column<Advice>,
        pub test_u8: Column<Advice>,
        pub challenges: Challenges,
    }

    impl<F: Field> FixedTestCircuitConfig<F> {
        // Assign values to different fields to verify the lookup range query function
        fn assign_region(&self, region: &mut Region<'_, F>) -> Result<(), Error> {
            assign_advice_or_fixed_with_u256(region, 1, &U256::from((1 << 16) - 1), self.test_u16)?; //65535
            assign_advice_or_fixed_with_u256(region, 10, &U256::from(1 << 13), self.test_u16)?; //8192
            self.selector.enable(region, 1)?;
            self.selector.enable(region, 9)?;
            assign_advice_or_fixed_with_u256(region, 1, &U256::from(1 << 10), self.test_u10)?; //1024
            assign_advice_or_fixed_with_u256(region, 9, &U256::from(1 << 9), self.test_u10)?; //512
            assign_advice_or_fixed_with_u256(region, 1, &U256::from((1 << 8) - 1), self.test_u8)?; //255
            assign_advice_or_fixed_with_u256(region, 3, &U256::from(1 << 5), self.test_u8)?; //32
            Ok(())
        }
    }

    #[derive(Clone, Default, Debug)]
    pub struct FixedTestCircuit<F: Field>(FixedCircuit<F>);

    impl<F: Field> Circuit<F> for FixedTestCircuit<F> {
        type Config = FixedTestCircuitConfig<F>;
        type FloorPlanner = SimpleFloorPlanner;
        type Params = ();

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let _dummy = meta.advice_column(); // dummy column in first phase to make challenge not panic
            let challenges = Challenges::construct(meta);
            let fixed_table = FixedTable::construct(meta);
            let config = FixedTestCircuitConfig {
                fixed_circuit: FixedCircuitConfig::new(
                    meta,
                    FixedCircuitConfigArgs { fixed_table },
                ),
                // Create the corresponding column fot tests
                selector: meta.complex_selector(),
                test_u16: meta.advice_column(),
                test_u10: meta.advice_column(),
                test_u8: meta.advice_column(),
                challenges,
            };
            // Add corresponding lookup constraints to verify the correctness
            // of the fixed circuit range query function
            meta.lookup_any("test lookup u16", |meta| {
                let entry = LookupEntry::U16(meta.query_advice(config.test_u16, Rotation::cur()));
                fixed_table.get_lookup_vector(meta, entry)
            });
            meta.lookup_any("test lookup u10", |meta| {
                let entry = LookupEntry::U10(meta.query_advice(config.test_u10, Rotation::cur()));
                let lookup_vec = fixed_table.get_lookup_vector(meta, entry);
                let selector = meta.query_selector(config.selector);
                lookup_vec
                    .into_iter()
                    .map(|(left, right)| {
                        (
                            // 如果selector未启用，则查询默认值1，因为u10的表格中值是从1开始
                            selector.clone() * left + (1.expr() - selector.clone()),
                            right,
                        )
                    })
                    .collect()
            });
            meta.lookup_any("test lookup u8", |meta| {
                let entry = LookupEntry::U8(meta.query_advice(config.test_u8, Rotation::cur()));
                fixed_table.get_lookup_vector(meta, entry)
            });
            config
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let challenges = config.challenges.values(&mut layouter);
            self.0
                .synthesize_sub(&config.fixed_circuit, &mut layouter, &challenges)?;
            layouter.assign_region(
                || "assign test value",
                |mut region| config.assign_region(&mut region),
            )
        }
    }

    impl<F: Field> FixedTestCircuit<F> {
        pub fn new(witness: Witness) -> Self {
            Self(FixedCircuit::new_from_witness(&witness))
        }
    }
    fn test_fixed_circuit(witness: Witness) -> MockProver<Fp> {
        let k = log2_ceil(FixedCircuit::<Fp>::num_rows(&witness));
        let circuit = FixedTestCircuit::<Fp>::new(witness);
        let instance: Vec<Vec<Fp>> = circuit.0.instance();
        let prover = MockProver::<Fp>::run(k, &circuit, instance).unwrap();
        prover
    }

    // when feature `no_fixed_lookup` is on, we skip the test
    #[cfg_attr(
        feature = "no_fixed_lookup",
        ignore = "feature `no_fixed_lookup` is on, we skip the test"
    )]
    #[test]
    fn test_fixed_parser() {
        let witness = Witness::default();
        let prover = test_fixed_circuit(witness);
        prover.assert_satisfied();
    }
}
