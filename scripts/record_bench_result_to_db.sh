#!/bin/bash

# 用途: 解析bench生成的log, cpu_stats, mem_stats 文件,将处理的结果写入mysql数据库后,删除log, cpu_stats, mem_stats 文件
test_id=$1
log_file=$2
cpu_stats_file=$3
mem_stats_file=$4
delete_files=$5
if [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ]|| [ -z "$4" ];then 
    echo "Error: should denote test_id,log_file,cpu_stats_file,mem_stats_file params"
    exit 1
fi 
if [ ! -f "$2" ] || [ ! -f "$3" ] || [ ! -f "$4" ] ;then 
    echo "Error: missed files"
    exit 1
fi
current_path=$(pwd)

# 处理bench,cpu,mem结果,将结果写入到mysql数据库
python3 "$current_path"/report_system_data/report_main.py "$test_id" "$log_file" "$cpu_stats_file" "$mem_stats_file" 

if [ ! -z "$5" ] && [ $delete_files = "y" ];then
    rm "$log_file" "$cpu_stats_file" "$mem_stats_file" 
fi
