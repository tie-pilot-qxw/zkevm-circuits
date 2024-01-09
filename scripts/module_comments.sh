#!/bin/bash

dir="../zkevm-circuits/src" # 将此替换为您要搜索的目录

echo "Comment Coverage"
echo

# 使用 find 查找目录中的所有子目录
find "$dir" -type d | while read -r subdir; do
  subdir_name=$(basename "$subdir") # 获取子目录名称（不包括路径）

  # 计算子目录的注释覆盖率
  subdir_cloc_output=$(cloc "$subdir") # 将 cloc 输出存储到变量 subdir_cloc_output 中

  subdir_comment=$(echo "$subdir_cloc_output" | awk '/^SUM:/ {print $4}')
  subdir_code=$(echo "$subdir_cloc_output" | awk '/^SUM:/ {print $5}')


  # 检查是否存在与子目录同名的文件
  same_name_file="$dir/$subdir_name.rs"
  if [[ -f "$same_name_file" ]]; then
    # 计算与子目录同名的文件的注释覆盖率
    file_cloc_output=$(cloc "$same_name_file") # 将 cloc 输出存储到变量 file_cloc_output 中

    file_comment=$(echo "$file_cloc_output" | awk '/^Rust/ {print $4}')
    file_code=$(echo "$file_cloc_output" | awk '/^Rust/ {print $5}')

    # 计算二者的注释覆盖率之和
    total_comment=$((subdir_comment + file_comment))
    total_code=$((subdir_code + file_code))
    total_comment_coverage=$(awk -v comment="$total_comment" -v code="$total_code" 'BEGIN {coverage = comment / (comment + code) * 100; printf("%.2f%%\n", coverage)}')

    echo "$subdir_name module  ==>   $total_comment_coverage"
  fi
done

find "$dir" -maxdepth 1 -type f -name "*.rs" | while read -r other_file; do
  other_file_name=$(basename "$other_file")
  subdir_same_name="$dir/$(basename -s .rs "$other_file_name")"
  # 跳过与子目录同名的文件
  if [[ -d "$subdir_same_name" ]]; then
    continue
  fi


  other_file_name=$(basename "$other_file")
  other_file_cloc_output=$(cloc "$other_file")

  other_file_comment=$(echo "$other_file_cloc_output" | awk '/^Rust/ {print $4}')
  other_file_code=$(echo "$other_file_cloc_output" | awk '/^Rust/ {print $5}')
  other_file_comment_coverage=$(echo "$other_file_cloc_output" | awk '
    /^Rust/ {
      comment = $4;
      code = $5;
      coverage = comment / (comment + code) * 100;
      printf("%.2f%%\n", coverage);
    }
  ')
  other_module=$(basename -s .rs "$other_file_name")
  echo "$other_module module  ==>    $other_file_comment_coverage"
done

