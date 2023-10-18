# How to run test

## Preparation
Prepare the official `evm` binary. You can compile it from [Geth source code](https://github.com/ethereum/go-ethereum) and use `make evm`. You can also download it from [official website](https://geth.ethereum.org/downloads) with "Geth & Tools". Put the binary in directory `zkevm-circuits`.

After preparation, you can run all tests.

Run one test
```shell
cargo test super_circuit::tests::test_super_circuit
```

or run all tests
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

- Wiki of this repository.
- https://git.code.tencent.com/chainmaker-zk/knowledgebase
