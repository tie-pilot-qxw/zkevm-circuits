# How to run test

```shell
cargo test super_circuit::tests::test_super_circuit
```

or 
```shell
cargo test
```

also we have tests that ignore intersubcircuit lookups

```shell
cargo test --features no_intersubcircuit_lookup
```

# How to run gen_code
```shell
cargo +nightly-2023-04-24 run --package zkevm-circuits --example gen_code --features gen_code
```
(You can try different nightly version, but latest nightly version cannot produce correct line breaks.)

# Resources

Ding Excel:
https://alidocs.dingtalk.com/i/nodes/amweZ92PV6w9mPBQiy7QmAXeJxEKBD6p

Ding Word:
https://alidocs.dingtalk.com/i/nodes/Obva6QBXJw0B4LqYI1qpOYxY8n4qY5Pr