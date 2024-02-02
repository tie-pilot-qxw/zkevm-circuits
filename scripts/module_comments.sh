#!/bin/bash

# Note：如果您的分支有未commit代码，请不要使用该脚本
# 脚本会先删除所有代码文件中的测试代码，然后再计算测试覆盖率，
# 最后使用git恢复被删除的测试代码
# 如果您的分支有代码未commit，在运行脚本过程中会被删除导致无法找回


dir="../zkevm-circuits/src" # 将此替换为您要搜索的目录
PATTERN="mod test {" # Note：文件中的测试需要以test作为模块名，否则无法删除
os_name=$(uname)
echo "Comment Coverage"
echo

# 使用 find 查找目录中的所有子目录
# 计算 子目录模块和模块根文件总的注释覆盖率
find "$dir" -type d | while read -r subdir; do
  subdir_name=$(basename "$subdir") # 获取子目录名称（不包括路径）
  # 删除子目录下所有文件的测试代码
  if [ $os_name = "Darwin" ]; then
    find $subdir -type f -exec sed -i '' "/${PATTERN}/,\$d" {} +
  else
    find $subdir -type f -exec sed -i "/${PATTERN}/,\$d" {} +
  fi  

  # 计算子目录的注释覆盖率
  subdir_cloc_output=$(cloc "$subdir") # 将 cloc 输出存储到变量 subdir_cloc_output 中
  subdir_comment=$(echo "$subdir_cloc_output" | awk '/^SUM:/ {print $4}')
  subdir_code=$(echo "$subdir_cloc_output" | awk '/^SUM:/ {print $5}')


  # 检查是否存在与子目录同名的文件
  same_name_file="$dir/$subdir_name.rs"
  if [[ -f "$same_name_file" ]]; then    
    # 删除文件的测试代码
    if [ $os_name = "Darwin" ]; then
      sed -i '' "/${PATTERN}/,\$d" $same_name_file
    else
      sed -i "/${PATTERN}/,\$d" $same_name_file
    fi    
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

# 计算含有根文件模块的注释覆盖率
find "$dir" -maxdepth 1 -type f -name "*.rs" | while read -r other_file; do
  other_file_name=$(basename "$other_file")
  subdir_same_name="$dir/$(basename -s .rs "$other_file_name")"
  # 跳过与子目录同名的文件
  if [[ -d "$subdir_same_name" ]]; then
    continue
  fi
  # 删除文件的测试代码
  if [ $os_name = "Darwin" ]; then
    sed -i '' "/${PATTERN}/,\$d" $other_file
  else
    sed -i  "/${PATTERN}/,\$d" $other_file
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

# 恢复文件中删除的测试代码
git restore ../zkevm-circuits/src