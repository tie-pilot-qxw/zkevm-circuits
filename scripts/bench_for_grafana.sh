#!/bin/bash
# 用途: 跑bench测试,将测试结果写入mysql数据库,删除跑测试时生成的中间文件

circuit=$1
interval=$2
delete_files=$3
if [ -z "$1" ] || [ -z "$2" ];then 
    echo "Error: should denote circuit,interval params"
    exit 1
fi 
echo_output="$(./bench_test.sh $circuit $interval)"
for line in $echo_output;do 
    test_id=$line
done
current_path=$(pwd)
if [ ! -z "$3" ] ;then
    ./record_bench_result_to_db.sh $test_id "$current_path/$test_id".log "$current_path/$test_id"_cpu.stats "$current_path/$test_id"_mem.stats "$delete_files"
else
    ./record_bench_result_to_db.sh $test_id "$current_path/$test_id".log "$current_path/$test_id"_cpu.stats "$current_path/$test_id"_mem.stats
fi

