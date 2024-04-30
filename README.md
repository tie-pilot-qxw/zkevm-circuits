# How to run test

## Preparation

Prepare the official `evm` binary. You can compile it from [Geth source code](https://github.com/ethereum/go-ethereum)
and use `go run build/ci.go install ./cmd/evm`. You can also download it
from [official website](https://geth.ethereum.org/downloads) with "Geth & Tools". Put the binary in
directory `zkevm-circuits`.

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

### fast_test(small k)

generate proof_params and write to file

```shell
cargo test -p zkevm-circuits --profile bench --bench benchmark_list -- init_proof_params  --nocapture
```

run circuit using proof_params file

```shell
USEFILE=true cargo test -p zkevm-circuits --profile bench --bench benchmark_list -- super_circuit  --nocapture
```

run circuit without proof_params file

```shell
cargo test -p zkevm-circuits --profile bench --bench benchmark_list -- super_circuit  --nocapture
```

### k=19

generate proof_params and write to file

```shell
cargo test -p zkevm-circuits --profile bench --no-default-features --bench benchmark_list -- init_proof_params  --nocapture
```

run circuit using proof_params file

```shell
USEFILE=true cargo test -p zkevm-circuits --profile bench --no-default-features --bench benchmark_list -- super_circuit  --nocapture
```

run circuit without proof_params file

```shell
cargo test -p zkevm-circuits --profile bench --no-default-features --bench benchmark_list -- super_circuit  --nocapture
```

run benchmark with custom round（specify Round through environment variables）

```shell
# round is 10
ROUND=10 cargo test -p zkevm-circuits --profile bench --no-default-features --bench benchmark_list -- super_circuit  --nocapture
```

Note:

```--profile bench```: use the [profile.bench]

```--no-default-features```: disable the default features "fast_test"

```--features "benches"```: turning on this features will run multiple rounds

```--bench benchmark_list -- super_circuit```: run the super_circuit benchmark

### Benchmark data to grafana

when do bench mark test, can use [scripts here](#bench-scripts). if only do bench test, only depends on sysstat,can only
run bench_test script. Tools of reporting bench mark test data , and visualization in grafana are also offered,
dependency can be found [here](#depends-on).

#### <a id="bench_depends">Depends on</a>

1. depends sysstat
2. depends python : python3, pandas, sqlalchemy, pymysql
3. depends mysql : mysql(5.7+), prepare a database, write mysql server, user,passwd in
   scripts/report_system_data/env.json
4. depends grafana(10.3.3) :
    - in grafana ,first add data source. select mysql template, then fill mysql server info using mysql info in
      env.json. the data source name must be same with data source in grafana-bench-config.json, default is bench_test
    - in grafana , import Dashboard using scripts/report_system_data/grafana-bench-config.json

#### <a id="bench_scripts">Bench scripts</a>

1. do benchmark : `cd scripts && ./bench_test.sh $benchmark_list $sample_seconds`
    - $benchmark_list denotes bench test, example can be super_circuit
    - $sample_seconds is sample seconds for cpu/mem stats sampling, example can be 3     
      this command will do bench mark, record bench mark data
2. write benchmark result to
   mysql: `cd scripts && ./record_bench_result_to_db.sh $test_id $log_file $cpu_file $mem_file [$delete_file]`
    - $test_id: common prefix in log_file,cpu_file,mem_file
    - $log_file: log file
    - $cpu_file: cpu sampling file
    - $mem_file: memory sampling file
    - $delete_file: optional param, y denote delete log_file,cpu_file,mem_file;
      this command will process log file, cpu file, mem file ,then write processed data into mysql ,if set optional
      param y, also delete log_file,cpu_file,mem_file;
3. do benchmark and process data, write result to
   mysql: `cd scripts && ./bench_for_grafana.sh $benchmark_list $sample_seconds [$delete_file]`
    - $benchmark_list denotes bench test, example can be super_circuit
    - $sample_seconds is sample seconds for cpu/mem stats sampling, example can be 3
    - $delete_file: optional param, y denote delete log_file,cpu_file,mem_file;    
      this command will do bench mark, record bench mark data, and record stats in mysql

# How to run gen_code

```shell
cargo +nightly-2023-04-24 run --package zkevm-circuits --example gen_code --features gen_code
```

(You can try different nightly version, but latest nightly version cannot produce correct line breaks.)

# Resources

- Wiki of this repository.
- https://git.code.tencent.com/chainmaker-zk/knowledgebase
