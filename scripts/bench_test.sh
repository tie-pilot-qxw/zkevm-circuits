#!/bin/bash

# 用途: 做bench测试,将测试结果写入log文件,系统cpu采样数据写入cpu.stats文件,系统采样内存数据写入mem.stats文件

circuit=$1
interval=$2
if [ -z "$1" ] || [ -z "$2" ];then 
    echo "Error: should denote circuit,interval params"
    exit 1
fi 
time=$(date +%s)
test_id=$circuit-$time

# 打开系统性能采样记录器
./system_record.sh start $test_id $interval
# 开始测试
cargo test -p zkevm-circuits --profile bench --bench benchmark_list -- $circuit  --nocapture >> $test_id.log
# 关闭系统性能采样记录器 
./system_record.sh stop $test_id 

echo "$test_id"

