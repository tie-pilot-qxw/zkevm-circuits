#!/bin/bash


export RUSTFLAGS="-Cinstrument-coverage"

cargo build

export LLVM_PROFILE_FILE="your_name-%p-%m.profraw"

cargo test -p zkevm-circuits 

python3 line_coverage.py

grcov . --binary-path ./target/debug/ -s . -t covdir --branch --ignore-not-existing -o ./target/debug/coverage/


search_dir="." 

# 递归查找并删除以".profraw"结尾的文件
find "$search_dir" -type f -name '*.profraw' -exec rm -f {} \;

echo "已删除所有以'.profraw'结尾的文件。"
