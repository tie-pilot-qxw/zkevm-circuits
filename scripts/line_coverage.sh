#!/bin/bash


export RUSTFLAGS="-Cinstrument-coverage"

cargo build

export LLVM_PROFILE_FILE="test_coverage-%p-%m.profraw"

cargo test -p zkevm-circuits 

grcov .. --binary-path ../target/debug/ -s .. -t covdir --branch --ignore-not-existing -o ../target/debug/

python3 line_coverage.py

search_dir=".." 

# 递归查找并删除以".profraw"结尾的文件
find "$search_dir" -type f -name '*.profraw' -exec rm -f {} \;

echo "已删除所有以'.profraw'结尾的文件。"
