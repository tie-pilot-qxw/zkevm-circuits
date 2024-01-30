# How to run test

## Preparation
Prepare the official `evm` binary. You can compile it from [Geth source code](https://github.com/ethereum/go-ethereum) and use `go run build/ci.go install ./cmd/evm`. You can also download it from [official website](https://geth.ethereum.org/downloads) with "Geth & Tools". Put the binary in directory `zkevm-circuits`.

After preparation, you can run all tests.

Run one test
```shell
cargo test -p zkevm-circuits super_circuit::tests::test_super_circuit
```

or run all tests
```shell
cargo test -p zkevm-circuits
```

## Benchmark

run full super_circuit benchmark(no default features)
```shell
cargo test -p zkevm-circuits --profile bench --no-default-features --features "benches" --bench benchmark_list -- super_circuit  --nocapture
```
run super_circuit with features fast_test
```shell
cargo test -p zkevm-circuits --profile bench --features "benches" --bench benchmark_list -- super_circuit  --nocapture
```
run benchmark with custom round（specify Round through environment variables）
```shell
# round is 10
ROUND=10 cargo test -p zkevm-circuits --profile bench --features "benches" --bench benchmark_list -- super_circuit  --nocapture
```

Note:

```--profile bench```: use the [profile.bench]

```--no-default-features```: disable the default features fast_test 

```--features "benches"```: turning on this features will run multiple rounds.

```--bench src -- super_circuit```: run the super_circuit benchmark



# How to run gen_code
```shell
cargo +nightly-2023-04-24 run --package zkevm-circuits --example gen_code --features gen_code
```
(You can try different nightly version, but latest nightly version cannot produce correct line breaks.)

# Resources

- Wiki of this repository.
- https://git.code.tencent.com/chainmaker-zk/knowledgebase
