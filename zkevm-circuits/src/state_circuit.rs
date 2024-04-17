pub mod multiple_precision_integer;
pub mod ordering;

use self::ordering::{Config as OrderingConfig, LIMB_SIZE};
use crate::constant::LOG_NUM_STATE_TAG;
use crate::table::{FixedTable, StateTable};
use crate::util::{assign_advice_or_fixed_with_u256, Challenges, SubCircuit, SubCircuitConfig};
use crate::witness::state::{Row, Tag};
use crate::witness::Witness;
use eth_types::{Field, U256};
use gadgets::binary_number_with_real_selector::{BinaryNumberChip, BinaryNumberConfig};
use gadgets::util::Expr;
use halo2_proofs::circuit::{Layouter, Region, Value};
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector};
use halo2_proofs::poly::Rotation;
use multiple_precision_integer::{Chip as MpiChip, Config as MpiConfig};
use ordering::{LimbIndex, CALLID_OR_ADDRESS_LIMBS, POINTER_LIMBS, STAMP_LIMBS};
use std::marker::PhantomData;

// state电路布局：
// tag | stamp | value_hi | value_lo | call_id_contract_addr | pointer_hi | pointer_lo | is_write
// stack| 0x8 |   0x0    |    0x1   |         0x1            | None       |    0x1     |   0x1
// stack| 0xb |   0x0    |    0x1   |         0x1            | None       |    0x1     |   0x1
// CallContext| 0xd |   0x0    |    0x1   |        0x0       | None       |    0x9     |   0x1
// 由8列数据组成，标识state 每次操作的内容所处位置以及数据的内容、辅助属性。
// Tag 标识操作的状态位置，如：Stack标识操作栈上数据，CallData标识操作calldata数据, Memory标识操作内存数据
// Stamp 历史操作次数的累积，每次操作后，该值+1；如从栈上弹出个数据后stamp+=1，从内存中读取n个byte，stamp+=n
// value_hi 操作数据的高16byte；一般情况下仅使用低16byte该字段为0；当数据为contract_addr或其它大于16byte的
// 情况，value_hi为高16byte的值
// value_lo 操作数据的低16byte
// pointer 操作的数据所指向的位置；如calldata中读取数据，指向calldata的索引；栈上弹出数据时为该数据在栈上的
// 索引，通常情况仅使用低16byte（pointer_lo）做索引足够，pointer_hi字段为0。当从Storage读取数据时，由于索引比较大，
// 会存在使用pointer_hi的情况
// is_write: 标识当前的操作是写操作还是读操作，写为1，读为0
//
// 为了保证读写一致性，我们需要对所有state电路中的操作进行排序，按照如下顺序排序的：先按tag，再按callid,
// pointer hi, pointer lo, stamp的顺序排序。
// 因此在witness.rs中通过执行所有区块、交易的trace构造完成完整state rows数据后，需要按照上述规则对生成
// 的state rows进行排序，然后在将排序后的内容填入 state circuit中。
// state rows排序使用了ordering.rs和multiple_precision_integer.rs进行实现，因为在电路程序中需要证明
// state rows如实按照排序规则进行排序，因此需要添加合适的约束程序进行保证，当排序与规则不一致时，约束出错。
// 使用multiple_precision_integer.rs对要排序元素进行处理，如将元素拆分为一堆16byte的数据
// 在ordering.rs中，添加排序规则约束，保证state table中所有的元素按照规则进行排列。

#[derive(Clone, Debug)]
pub struct StateCircuitConfig<F> {
    q_enable: Selector,
    /// Type of value, one of stack, memory, storage, call context, call data or return data
    /// A `BinaryNumberConfig` can return the indicator by method `value_equals`
    tag: BinaryNumberConfig<Tag, LOG_NUM_STATE_TAG>,
    /// Stamp that increments for each state operation, unique for each row
    stamp: Column<Advice>,
    /// High 128-bit value of the row
    value_hi: Column<Advice>,
    /// Low 128-bit value of the row
    value_lo: Column<Advice>,
    /// Call id (other types) or contract address (storage type only)
    call_id_contract_addr: Column<Advice>,
    /// High 128-bit of the key (storage type only)
    pointer_hi: Column<Advice>,
    /// Low 128-bit of the key (storage type only) or call context tag
    /// Or stack pointer or memory address or data index (call data and return data)
    pointer_lo: Column<Advice>,
    /// Whether it is write or read, binary value
    is_write: Column<Advice>,
    /// Sort the state and calculate whether the current state is accessed for the first time.
    /// sorted elements(tag, call_id_or_address, pointer_hi/_lo, stamp).
    ordering_config: OrderingConfig,
    /// Elements will be sorted in the state circuit
    sort_keys: SortedElements,
    /// Indicates whether the location is visited for the first time;
    /// 0 if the difference between the state row is Stamp0|Stamp1, otherwise is 1.
    is_first_access: Column<Advice>,
    /// cnt records the count of stamp value, starting from 1, increasing in order.
    cnt: Column<Advice>,
    /// High 128-bit previous value of the row
    value_pre_hi: Column<Advice>,
    /// Low 128-bit previous value of the row
    value_pre_lo: Column<Advice>,
    ///High 128-bit previous committed value  of the row
    committed_value_hi: Column<Advice>,
    ///Low 128-bit previous committed value  of the row
    committed_value_lo: Column<Advice>,
    /// Lookup table for some information，such as value of cell U16/U0/U8 range lookup.
    fixed_table: FixedTable,
    _marker: PhantomData<F>,
}

pub struct StateCircuitConfigArgs {
    pub(crate) q_enable: Selector,
    pub(crate) state_table: StateTable,
    pub(crate) fixed_table: FixedTable,
    /// Challenges
    pub challenges: Challenges,
}

#[derive(Clone, Copy, Debug)]
pub struct SortedElements {
    tag: BinaryNumberConfig<Tag, LOG_NUM_STATE_TAG>,
    call_id_or_address: MpiConfig<U256, CALLID_OR_ADDRESS_LIMBS>,
    pointer_hi: MpiConfig<U256, POINTER_LIMBS>,
    pointer_lo: MpiConfig<U256, POINTER_LIMBS>,
    stamp: MpiConfig<u32, STAMP_LIMBS>,
}

impl<F: Field> SubCircuitConfig<F> for StateCircuitConfig<F> {
    type ConfigArgs = StateCircuitConfigArgs;

    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs {
            q_enable,
            state_table,
            fixed_table,
            challenges,
        }: Self::ConfigArgs,
    ) -> Self {
        let StateTable {
            tag,
            stamp,
            value_hi,
            value_lo,
            call_id_contract_addr,
            pointer_hi,
            pointer_lo,
            is_write,
            cnt,
            value_pre_hi,
            value_pre_lo,
            committed_value_hi,
            committed_value_lo,
        } = state_table;

        let challenges_expr = challenges.exprs(meta);

        // tag | mpi_call_id | mpi_pointer_hi | mpi_pointer_lo | mpi_stamp
        // new sorted element with Advice that will be sorted by the field in state row;
        // 示例：call_id_contract_addr有160bit，所以拆分为10个limb，申请了10个Advice，每个Advice填写一个limb
        // pointer_lo/hi有128bit，拆分为8个limb，申请了8个Advice
        let mpi_call_id = MpiChip::configure(meta, q_enable, call_id_contract_addr, fixed_table);
        let mpi_pointer_hi = MpiChip::configure(meta, q_enable, pointer_hi, fixed_table);
        let mpi_pointer_lo = MpiChip::configure(meta, q_enable, pointer_lo, fixed_table);
        let mpi_stamp = MpiChip::configure(meta, q_enable, stamp, fixed_table);
        let keys = SortedElements {
            tag,
            call_id_or_address: mpi_call_id,
            pointer_hi: mpi_pointer_hi,
            pointer_lo: mpi_pointer_lo,
            stamp: mpi_stamp,
        };
        // Passes the element to be sorted as a parameter to the sorting function
        // 将字段构建好的limb数据传入ordering.rs，约束state rows间的排序满足预定义规则；
        // 因为state circuit中填入的rows已经被提前排好了序，所以可以使用排序规则进行约束，
        // 正确排序的state rows可以通过这些约束。
        let power_of_randomness: [Expression<F>; LIMB_SIZE - 1] =
            challenges_expr.rlc_powers_of_randomness();

        let ordering_config =
            OrderingConfig::new(meta, q_enable, keys, fixed_table, power_of_randomness);
        let config: StateCircuitConfig<F> = Self {
            q_enable,
            tag,
            stamp,
            value_hi,
            value_lo,
            call_id_contract_addr,
            pointer_hi,
            pointer_lo,
            is_write,
            sort_keys: keys,
            ordering_config,
            is_first_access: meta.advice_column(),
            cnt,
            fixed_table,
            value_pre_hi,
            value_pre_lo,
            committed_value_hi,
            committed_value_lo,
            _marker: PhantomData,
        };

        // create custom gate with different column and rotation
        meta.create_gate("STATE_constraint_in_different_region", |meta| {
            let q_enable = meta.query_selector(config.q_enable);
            let is_first_access = meta.query_advice(config.is_first_access, Rotation::cur());
            let stack_condition = config.tag.value_equals(Tag::Stack, Rotation::cur())(meta);
            let memory_condition = config.tag.value_equals(Tag::Memory, Rotation::cur())(meta);
            let _storage_condition = config.tag.value_equals(Tag::Storage, Rotation::cur())(meta);
            let callcontext_condition =
                config.tag.value_equals(Tag::CallContext, Rotation::cur())(meta);
            let calldata_condition = config.tag.value_equals(Tag::CallData, Rotation::cur())(meta);
            let return_condition = config.tag.value_equals(Tag::ReturnData, Rotation::cur())(meta);
            let endpadding_condition =
                config.tag.value_equals(Tag::EndPadding, Rotation::cur())(meta);
            let pointer_hi = meta.query_advice(config.pointer_hi, Rotation::cur());
            let prev_value_hi = meta.query_advice(config.value_hi, Rotation::prev());
            let prev_value_lo = meta.query_advice(config.value_lo, Rotation::prev());
            let value_hi = meta.query_advice(config.value_hi, Rotation::cur());
            let value_lo = meta.query_advice(config.value_lo, Rotation::cur());
            let is_write = meta.query_advice(config.is_write, Rotation::cur());
            let cur_cnt = meta.query_advice(config.cnt, Rotation::cur());
            let prev_cnt = meta.query_advice(config.cnt, Rotation::prev());
            let value_prev_hi_in_cur = meta.query_advice(config.value_pre_hi, Rotation::cur());
            let value_prev_lo_in_cur = meta.query_advice(config.value_pre_lo,Rotation::cur());
            let access_list_storage_condition = config
                .tag
                .value_equals(Tag::SlotInAccessListStorage, Rotation::cur())(
                meta
            );

            // 因为state circuit由每次操作的数据和它对应的属性组成（操作的数据所处位置，offset等）
            // 对于不同位置（stack、memory、storage...）state rows中的字段有不同约束，来保证
            // 满足EVM语义规则。
            // 如：当Tag=memory（即操作的数据位于memory），该内存的位置第一次被操作且操作为读取数据时，
            // 约束读取的数据value_lo必须为0，EVM对于读取未被写入的memory位置时默认返回0
            // 若Tag=stack（即操作的数据位于stack），该位置第一次被操作时，约束操作必须为写操作，因为
            // EVM的栈必须先被写入数据才可以进行读取。
            // 若Tag=CallData（即操作的数据位于calldata），该位置第一次被操作且操作为读取数据时，
            // 约束读取的数据value_lo必须为0，EVM对于读取未被写入的calldata位置时默认返回0
            // 若Tag=ReturnData（即操作的数据位于ReturnData），该位置第一次被操作时，约束操作必须为写操作
            // 若Tag=CallContext，该位置第一次被操作时，约束操作必须为写操作
            let mut vec = vec![
                // is_write = 0/1
                (
                    "is_write",
                    q_enable.clone() * (1.expr() - is_write.clone()) * is_write.clone(),
                ),
                // is_first_access = 0/1
                (
                    "first_access",
                    q_enable.clone()
                        * (1.expr() - is_first_access.clone())
                        * is_first_access.clone(),
                ),
                //1. first_access=1 => is_write=1
                //2. pointer_hi=0
                (
                    "stack_first_access",
                    q_enable.clone()
                        * stack_condition.clone()
                        * is_first_access.clone()
                        * (1.expr() - is_write.clone()),
                ),
                (
                    "stack_pointer_hi",
                    q_enable.clone() * stack_condition * pointer_hi.clone(),
                ),
                //1. first_access=1 & is_write=0 => value=0
                //2. pointer_hi=0
                (
                    "memory_first_access_value_lo",
                    q_enable.clone()
                        * memory_condition.clone()
                        * is_first_access.clone()
                        * (1.expr() - is_write.clone())
                        * value_lo.clone(),
                ),
                (
                    "memory_value_hi",
                    q_enable.clone() * memory_condition.clone() * value_hi.clone(),
                ),
                (
                    "memory_pointer_hi",
                    q_enable.clone() * memory_condition * pointer_hi.clone(),
                ),
                // TODO storage first_access=1 & is_write=0 & MPT check

                //1. first_access=1 => is_write=1
                //2. pointer_hi=0
                (
                    "callcontext_first_access",
                    q_enable.clone()
                        * callcontext_condition.clone()
                        * is_first_access.clone()
                        * (1.expr() - is_write.clone()),
                ),
                (
                    "callcontext_pointer_hi",
                    q_enable.clone() * callcontext_condition.clone() * pointer_hi.clone(),
                ),
                //1. first_access=1 & is_write=0 => value_lo=0
                //2. value_hi=0
                //3. pointer_hi=0
                (
                    "calldata_first_access_write_value_lo",
                    q_enable.clone()
                        * calldata_condition.clone()
                        * is_first_access.clone()
                        * (1.expr() - is_write.clone())
                        * value_lo.clone(),
                ),
                (
                    "calldata_value_hi",
                    q_enable.clone() * calldata_condition.clone() * value_hi.clone(),
                ),
                (
                    "calldata_pointer_hi",
                    q_enable.clone() * calldata_condition * pointer_hi.clone(),
                ),
                //1. first_access=1 => is_write=1
                //2. value_hi=0
                //3. pointer_hi=0
                (
                    "returndata_first_access_write",
                    q_enable.clone()
                        * return_condition.clone()
                        * is_first_access.clone()
                        * (1.expr() - is_write.clone()),
                ),
                (
                    "returndata_value_hi",
                    q_enable.clone() * return_condition.clone() * value_hi.clone(),
                ),
                (
                    "returndata_pointer_hi",
                    q_enable.clone() * return_condition * pointer_hi,
                ),
                (
                    "pre_cnt + 1 = cur_cnt not in endpadding or pre_cnt = cur_cnt in endpadding",
                    q_enable.clone()
                        * (prev_cnt.clone() - cur_cnt.clone() + 1.expr() - endpadding_condition),
                ),
            ];

            let mut index_is_stamp_expr = 0.expr();
            for tag in [LimbIndex::Stamp0, LimbIndex::Stamp1] {
                index_is_stamp_expr = index_is_stamp_expr.clone()
                    + config
                        .ordering_config
                        .first_different_limb
                        .value_equals(tag, Rotation::cur())(meta);
            }
            // 1 - is_first_access === index = Stamp0 | Stamp1
            vec.push((
                "1 - is_first_access === index = Stamp0 | Stamp1",
                q_enable.clone()
                    * (index_is_stamp_expr.clone() + is_first_access.clone() - 1.expr()),
            ));
            // access list storage 不适用这个规则
            vec.push((
                "is_first_access=0 & is_write=0 & not access_list_tag ==> prev_value_lo = cur_value_lo",
                q_enable.clone()
                    * (1.expr() - is_first_access.clone())
                    * (1.expr() - access_list_storage_condition.clone())
                    * (prev_value_lo.clone() - value_lo.clone())
                    * (1.expr() - is_write.clone()),
            ));
            vec.push((
                "is_first_access=0 & is_write=0 & not access_list_tag ==> prev_value_hi = cur_value_hi",
                q_enable.clone()
                    * (1.expr() - is_first_access.clone())
                    * (1.expr() - access_list_storage_condition.clone())
                    * (prev_value_hi.clone() - value_hi.clone())
                    * (1.expr() - is_write.clone()),
            ));

            // tag is access_list_storage_condition
            vec.push((
                "is_first_access=0 & access_list_tag => value_pre_hi in cur = value_hi in prev",
                q_enable.clone()
                    * (1.expr() - is_first_access.clone())
                    * access_list_storage_condition.clone()
                    * (value_prev_hi_in_cur.clone() - prev_value_hi.clone())
            ));

            // todo 要先修复多交易的tx_id
            // 多交易里tag为access_list_tag 的情况时，会出现is_warm的当前行与上一行之间的约束不能满足这个约束。
            // 当正确添加了tx_id后，此时is_first_access应该为1。
            // 可通过multi test复现。
            // vec.push((
            //     "is_first_access=0 & access_list_tag => value_pre_lo in cur = value_lo in prev",
            //     q_enable.clone()
            //         * (1.expr() - is_first_access.clone())
            //         * access_list_storage_condition.clone()
            //         * (value_prev_lo_in_cur.clone() - prev_value_lo.clone())
            // ));

            vec.push((
                "is_first_access=0 & access_list_tag => value_pre_hi in cur = value_hi in prev",
                q_enable.clone()
                    * (1.expr() - is_first_access.clone())
                    * access_list_storage_condition.clone()
                    * (value_prev_hi_in_cur.clone() - prev_value_hi.clone())
            ));

            vec.push((
                "access_list_tag => value_hi = 0",
                q_enable.clone()
                    * access_list_storage_condition.clone()
                    * value_hi.clone()
            ));

            vec.push((
                "access_list_tag => value_lo is bool",
                q_enable.clone()
                    * access_list_storage_condition.clone()
                    * (value_lo.clone() - 1.expr())
                    * value_lo.clone()
            ));

            // todo committed_value、value_pre_in_cur 目前还没加

            vec
        });

        // when feature `no_fixed_lookup` is on, we don't do lookup
        #[cfg(not(feature = "no_fixed_lookup"))]
        meta.lookup_any("STATE_lookup_stack_pointer", |meta| {
            use crate::table::LookupEntry;
            use crate::witness::state;

            // 1<= pointer_lo <=1024 in stack
            let entry = LookupEntry::U10(meta.query_advice(config.pointer_lo, Rotation::cur()));
            let stack_condition = config.tag.value_equals(state::Tag::Stack, Rotation::cur())(meta);
            let lookup_vec = config.fixed_table.get_lookup_vector(meta, entry);
            lookup_vec
                .into_iter()
                .map(|(left, right)| {
                    let q_enable = meta.query_selector(config.q_enable);
                    (q_enable * left * stack_condition.clone(), right)
                })
                .collect()
        });
        // when feature `no_fixed_lookup` is on, we don't do lookup
        #[cfg(not(feature = "no_fixed_lookup"))]
        meta.lookup_any("STATE_lookup_memory_pointer", |meta| {
            use crate::table::LookupEntry;
            use crate::witness::state;

            // 0<= value_lo < 256 in memory
            let entry = LookupEntry::U8(meta.query_advice(config.value_lo, Rotation::cur()));
            let memory_condition =
                config.tag.value_equals(state::Tag::Memory, Rotation::cur())(meta);
            let lookup_vec = config.fixed_table.get_lookup_vector(meta, entry);
            lookup_vec
                .into_iter()
                .map(|(left, right)| {
                    let q_enable = meta.query_selector(config.q_enable);
                    (q_enable * left * memory_condition.clone(), right)
                })
                .collect()
        });

        config
    }
}

impl<F: Field> StateCircuitConfig<F> {
    /// Padding assignment on rows with no data, and fill most columns with 0.
    /// Only first_different_limb and tag columns are assigned the specified value,
    /// EndPadding indicates the tag of padding in this column.
    /// If the value of first_different_limb is Stamp0|Stamp1, the first_access
    /// constraint logics is not enabled.
    /// cnt is equal to the maximum value of stamp + 1.
    fn assign_padding_row(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        cnt: U256,
    ) -> Result<(), Error> {
        assign_advice_or_fixed_with_u256(region, offset, &U256::zero(), self.stamp)?;
        assign_advice_or_fixed_with_u256(region, offset, &U256::zero(), self.value_hi)?;
        assign_advice_or_fixed_with_u256(region, offset, &U256::zero(), self.value_lo)?;
        assign_advice_or_fixed_with_u256(region, offset, &U256::zero(), self.pointer_hi)?;
        assign_advice_or_fixed_with_u256(region, offset, &U256::zero(), self.pointer_lo)?;
        assign_advice_or_fixed_with_u256(
            region,
            offset,
            &U256::zero(),
            self.call_id_contract_addr,
        )?;
        assign_advice_or_fixed_with_u256(region, offset, &U256::zero(), self.is_first_access)?;
        assign_advice_or_fixed_with_u256(region, offset, &U256::zero(), self.is_write)?;
        assign_advice_or_fixed_with_u256(region, offset, &cnt, self.cnt)?;
        assign_advice_or_fixed_with_u256(region, offset, &U256::zero(), self.value_pre_hi)?;
        assign_advice_or_fixed_with_u256(region, offset, &U256::zero(), self.value_pre_lo)?;
        assign_advice_or_fixed_with_u256(region, offset, &U256::zero(), self.committed_value_hi)?;
        assign_advice_or_fixed_with_u256(region, offset, &U256::zero(), self.committed_value_lo)?;
        let tag = BinaryNumberChip::construct(self.tag);
        tag.assign(region, offset, &Tag::EndPadding)?;

        self.sort_keys
            .call_id_or_address
            .assign(region, offset, U256::zero())?;
        self.sort_keys
            .pointer_hi
            .assign(region, offset, U256::zero())?;
        self.sort_keys
            .pointer_lo
            .assign(region, offset, U256::zero())?;
        self.sort_keys.stamp.assign(region, offset, 0)?;
        let first_different_limb =
            BinaryNumberChip::construct(self.ordering_config.first_different_limb);
        first_different_limb.assign(region, offset, &LimbIndex::Stamp0)?;
        assign_advice_or_fixed_with_u256(
            region,
            offset,
            &U256::zero(),
            self.ordering_config.limb_difference,
        )?;
        assign_advice_or_fixed_with_u256(
            region,
            offset,
            &U256::zero(),
            self.ordering_config.limb_difference_inverse,
        )?;

        Ok(())
    }

    #[rustfmt::skip]
    fn assign_row(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        row: &Row,
        cnt: U256,
    ) -> Result<(), Error> {
        let tag = BinaryNumberChip::construct(self.tag);
        tag.assign(region, offset, &row.tag.unwrap_or_default())?;
        assign_advice_or_fixed_with_u256(region, offset, &row.stamp.unwrap_or_default(), self.stamp)?;
        assign_advice_or_fixed_with_u256(region, offset, &row.value_hi.unwrap_or_default(), self.value_hi)?;
        assign_advice_or_fixed_with_u256(region, offset, &row.value_lo.unwrap_or_default(), self.value_lo)?;
        assign_advice_or_fixed_with_u256(region, offset, &row.call_id_contract_addr.unwrap_or_default(), self.call_id_contract_addr)?;
        assign_advice_or_fixed_with_u256(region, offset, &row.pointer_hi.unwrap_or_default(), self.pointer_hi)?;
        assign_advice_or_fixed_with_u256(region, offset, &row.pointer_lo.unwrap_or_default(), self.pointer_lo)?;
        assign_advice_or_fixed_with_u256(region, offset, &row.is_write.unwrap_or_default(), self.is_write)?;
        assign_advice_or_fixed_with_u256(region, offset, &row.value_pre_hi.unwrap_or_default(), self.value_pre_hi)?;
        assign_advice_or_fixed_with_u256(region, offset, &row.value_pre_lo.unwrap_or_default(), self.value_pre_lo)?;
        assign_advice_or_fixed_with_u256(region, offset, &row.committed_value_hi.unwrap_or_default(), self.committed_value_hi)?;
        assign_advice_or_fixed_with_u256(region, offset, &row.committed_value_lo.unwrap_or_default(), self.committed_value_lo)?;
        assign_advice_or_fixed_with_u256(region, offset, &cnt, self.cnt)?;
        // Assign value to the column of elements to be sorted
        self.sort_keys
            .call_id_or_address
            .assign(region, offset, row.call_id_contract_addr.unwrap_or_default())?;
        self.sort_keys
            .pointer_hi
            .assign(region, offset, row.pointer_hi.unwrap_or_default())?;
        self.sort_keys
            .pointer_lo
            .assign(region, offset, row.pointer_lo.unwrap_or_default())?;
        self.sort_keys
            .stamp
            .assign(region, offset, row.stamp.unwrap_or_default().as_u32())?;
        Ok(())
    }

    /// assign values from witness in a region
    pub fn assign_with_region(
        &self,
        region: &mut Region<'_, F>,
        witness: &Witness,
        num_row_incl_padding: usize,
    ) -> Result<(), Error> {
        // Assign data of the status to circuit row with row offset
        let mut cnt = U256::zero();
        // unusable_rows == 1, cnt == 0,
        // when the tag is EndPadding, it is not included in the cnt
        for (offset, row) in witness.state.iter().enumerate() {
            if !matches!(row.tag, Some(Tag::EndPadding) | None) {
                cnt = cnt + 1;
            }
            self.assign_row(region, offset, row, cnt)?;
        }
        // 1. assign ordering with curr and prev state.
        // 2. if and only if the difference with two status not in Stamp*,
        // indicates that the location by the pointer is accessed for the first time,
        for (i, state) in witness.state.iter().enumerate() {
            if i > 0 {
                let prev_row = &witness.state[i - 1];
                let index = self.ordering_config.assign(region, i, state, prev_row)?;
                let is_first_access = !matches!(index, LimbIndex::Stamp0 | LimbIndex::Stamp1);
                // If the location by pointer is accessed for the first time, set the
                // is_first_access column of the current row to 1, otherwise it is 0.
                #[rustfmt::skip]
                assign_advice_or_fixed_with_u256(
                    region,
                    i,
                    &U256::from(if is_first_access { 1 } else { 0 }),
                    self.is_first_access,
                )?;
            }
        }
        // pad the rest rows
        // also assign columns in ordering_config
        for offset in witness.state.len()..num_row_incl_padding {
            self.assign_padding_row(region, offset, cnt)?;
        }
        Ok(())
    }

    /// Annotate and name columns
    pub fn annotate_circuit_in_region(&self, region: &mut Region<F>) {
        region.name_column(|| "STATE_value_hi", self.value_hi);
        region.name_column(|| "STATE_value_lo", self.value_lo);
        region.name_column(|| "STATE_stamp", self.stamp);
        region.name_column(|| "STATE_call_id_contract_addr", self.call_id_contract_addr);
        region.name_column(|| "STATE_pointer_hi", self.pointer_hi);
        region.name_column(|| "STATE_pointer_lo", self.pointer_lo);
        region.name_column(|| "STATE_is_write", self.is_write);
        self.tag
            .annotate_columns_in_region(region, "STATE_config_tag");
        self.sort_keys
            .tag
            .annotate_columns_in_region(region, "STATE_sort_elements_tag");
        self.sort_keys
            .call_id_or_address
            .annotate_columns_in_region(region, "STATE_sore_elements_call_id_or_address");
        self.sort_keys
            .pointer_hi
            .annotate_columns_in_region(region, "STATE_sore_elements_pointer_hi");
        self.sort_keys
            .pointer_lo
            .annotate_columns_in_region(region, "STATE_sore_elements_pointer_lo");
        self.sort_keys
            .stamp
            .annotate_colums_in_region(region, "STATE_sore_elements_stamp");
        self.ordering_config
            .annotate_columns_in_region(region, "STATE_ordering");
    }
}

#[derive(Clone, Default, Debug)]
pub struct StateCircuit<F: Field, const MAX_NUM_ROW: usize> {
    witness: Witness,
    _marker: PhantomData<F>,
}

impl<F: Field, const MAX_NUM_ROW: usize> SubCircuit<F> for StateCircuit<F, MAX_NUM_ROW> {
    type Config = StateCircuitConfig<F>;
    type Cells = ();

    fn new_from_witness(witness: &Witness) -> Self {
        StateCircuit {
            witness: witness.clone(),
            _marker: PhantomData,
        }
    }

    fn synthesize_sub(
        &self,
        config: &Self::Config,
        layouter: &mut impl Layouter<F>,
        _challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        let (num_padding_begin, num_padding_end) = Self::unusable_rows();
        layouter.assign_region(
            || "state circuit",
            |mut region| {
                config.annotate_circuit_in_region(&mut region);
                config.assign_with_region(&mut region, &self.witness, MAX_NUM_ROW)?;
                // sub circuit need to enable selector
                for offset in num_padding_begin..MAX_NUM_ROW - num_padding_end {
                    config.q_enable.enable(&mut region, offset)?;
                }
                Ok(())
            },
        )
    }

    fn unusable_rows() -> (usize, usize) {
        (1, 0)
    }

    fn num_rows(witness: &Witness) -> usize {
        // bytecode witness length plus must-have padding in the end
        Self::unusable_rows().1 + witness.state.len()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::constant::MAX_NUM_ROW;
    use crate::fixed_circuit::{FixedCircuit, FixedCircuitConfig, FixedCircuitConfigArgs};
    use crate::util::{geth_data_test, log2_ceil};
    use crate::witness::Witness;
    use eth_types::bytecode;
    use halo2_proofs::circuit::SimpleFloorPlanner;
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::halo2curves::bn256::Fr as Fp;
    use halo2_proofs::plonk::Circuit;

    #[derive(Clone)]
    pub struct StateTestCircuitConfig<F: Field> {
        pub state_circuit: StateCircuitConfig<F>,
        pub fixed_circuit: FixedCircuitConfig<F>,
        pub challenges: Challenges,
    }

    #[derive(Clone, Default, Debug)]
    pub struct StateTestCircuit<F: Field, const MAX_NUM_ROW: usize> {
        state_circuit: StateCircuit<F, MAX_NUM_ROW>,
        fixed_circuit: FixedCircuit<F>,
    }

    impl<F: Field> SubCircuitConfig<F> for StateTestCircuitConfig<F> {
        type ConfigArgs = ();
        fn new(meta: &mut ConstraintSystem<F>, _args: Self::ConfigArgs) -> Self {
            let q_enable: Selector = meta.complex_selector(); //todo complex?
            let state_table = StateTable::construct(meta, q_enable);
            let fixed_table = FixedTable::construct(meta);
            let challenges = Challenges::construct(meta);
            StateTestCircuitConfig {
                state_circuit: StateCircuitConfig::new(
                    meta,
                    StateCircuitConfigArgs {
                        q_enable,
                        state_table,
                        fixed_table,
                        challenges,
                    },
                ),
                fixed_circuit: FixedCircuitConfig::new(
                    meta,
                    FixedCircuitConfigArgs { fixed_table },
                ),
                challenges,
            }
        }
    }

    impl<F: Field, const MAX_NUM_ROW: usize> Circuit<F> for StateTestCircuit<F, MAX_NUM_ROW> {
        type Config = StateTestCircuitConfig<F>;
        type FloorPlanner = SimpleFloorPlanner;
        fn without_witnesses(&self) -> Self {
            Self::default()
        }
        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            Self::Config::new(meta, ())
        }
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let challenges = config.challenges.values(&mut layouter);
            self.state_circuit
                .synthesize_sub(&config.state_circuit, &mut layouter, &challenges)?;
            // when feature `no_fixed_lookup` is on, we don't do synthesize
            #[cfg(not(feature = "no_fixed_lookup"))]
            self.fixed_circuit
                .synthesize_sub(&config.fixed_circuit, &mut layouter, &challenges)?;
            Ok(())
        }
    }

    impl<F: Field, const MAX_NUM_ROW: usize> StateTestCircuit<F, MAX_NUM_ROW> {
        pub fn new(witness: Witness) -> Self {
            Self {
                state_circuit: StateCircuit::new_from_witness(&witness),
                fixed_circuit: FixedCircuit::new_from_witness(&witness),
            }
        }
    }
    fn test_state_circuit(witness: Witness) -> MockProver<Fp> {
        let k = log2_ceil(MAX_NUM_ROW);
        let circuit = StateTestCircuit::<Fp, MAX_NUM_ROW>::new(witness);
        let prover = MockProver::<Fp>::run(k, &circuit, vec![]).unwrap();
        prover
    }

    #[test]
    fn test_state_parser() {
        let bytecode = bytecode! {
            PUSH1(0x1)
            PUSH1(0x2)
            ADD
        };
        let trace = trace_parser::trace_program(bytecode.to_vec().as_slice(), &[]);
        let witness: Witness = Witness::new(&geth_data_test(
            trace,
            bytecode.to_vec().as_slice(),
            &[],
            false,
            Default::default(),
        ));
        let prover = test_state_circuit(witness);
        prover.assert_satisfied_par();
    }

    #[test]
    fn test_valid_ordering_state() {
        let witness = Witness {
            state: vec![
                Row {
                    tag: Some(Tag::Stack),
                    call_id_contract_addr: Some(1.into()),
                    pointer_lo: Some(8.into()),
                    stamp: Some(10.into()),
                    is_write: Some(1.into()),
                    ..Default::default()
                },
                Row {
                    tag: Some(Tag::Stack),
                    call_id_contract_addr: Some(1.into()),
                    pointer_lo: Some(9.into()),
                    stamp: Some(11.into()),
                    is_write: Some(1.into()),
                    ..Default::default()
                },
                // must have padding row
                Row {
                    tag: Some(Tag::EndPadding),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let prover = test_state_circuit(witness);
        prover.assert_satisfied_par();
    }

    // when feature `no_fixed_lookup` is on, we skip the test
    // this is due to the test relies on lookup the `limb_difference` value in range U16
    #[cfg_attr(
        feature = "no_fixed_lookup",
        ignore = "feature `no_fixed_lookup` is on, we skip the test"
    )]
    #[test]
    fn test_invalid_order() {
        let witness = Witness {
            state: vec![
                Row {
                    tag: Some(Tag::Stack),
                    call_id_contract_addr: Some(1.into()),
                    pointer_lo: Some(9.into()),
                    stamp: Some(10.into()),
                    is_write: Some(1.into()),
                    ..Default::default()
                },
                Row {
                    tag: Some(Tag::Stack),
                    call_id_contract_addr: Some(1.into()),
                    pointer_lo: Some(8.into()),
                    stamp: Some(11.into()),
                    is_write: Some(1.into()),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let prover = test_state_circuit(witness);
        match prover.verify_par() {
            Ok(()) => panic!("should be error"),
            Err(errs) => println!("{:?}", errs),
        };
    }
}
