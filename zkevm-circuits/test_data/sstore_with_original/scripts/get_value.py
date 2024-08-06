# Copyright (C) SAFIT. All rights reserved.
# Copyright (C) BABEC. All rights reserved.
# Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
#
# SPDX-License-Identifier: Apache-2.0

import json
import subprocess

def read_json(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        return json.load(file)

# 使用方法：
# 按照正常的处理逻辑，首先出块，然后获取最新区块里的trace等等信息，然后执行该脚本即可。
# 1.修改以下变量:
#   - block_number: 按照执行习惯，我们一般获取到trace时，已经出了一个新区块，这里的编号应该为最新区块的上一个区块
#   - file1_path: tx_receipt.json文件的路径，用于获取合约地址
#   - file2_path: 执行trace的文件路径
#   - file3_path: bytecode.json文件的路径，用于更新storage信息
# 2. 运行 `python3 get_value.py` 即可

block_number = '0x2'  # 请根据实际情况修改
file1_path = '../trace/tx_receipt.json'
file2_path = '../trace/second_invoke.json'
file3_path = '../trace/bytecode.json'
def execute_curl(to_value, stack_value):
    data = '{"jsonrpc":"2.0", "method": "eth_getStorageAt", "params": ["%s", "%s", "%s"], "id": 1}' % (to_value, stack_value, block_number)
    try:
        result = subprocess.run(["curl", "localhost:8545", "-X", "POST", "--data", data], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        result_json = json.loads(result.stdout)
        return result_json.get('result')  # 返回解析得到的result字段
    except subprocess.CalledProcessError as e:
        print(f'命令执行出错: {e.stderr}')
        return None

def process_files(file1, file2, file3):
    data1 = read_json(file1)
    data2 = read_json(file2)
    data3 = read_json(file3)

    to_value = data1.get('result', {}).get('to', '未找到对应值')

    # 初始化一个空字典来收集所有storage的键值对
    storage_dict = {}
    for log in data2.get('result', {}).get('structLogs', []):
        if log.get('op') == 'SSTORE' and log.get('stack'):
            stack_value = log['stack'][-1]
            curl_result = execute_curl(to_value, stack_value)
            if curl_result:
                # 直接使用stack_value作为键，curl_result作为值添加到字典中
                storage_dict[stack_value] = curl_result

    updated = False
    for item in data3['result']:
        if item.get('contract_addr') == to_value:
            item['storage'] = storage_dict  # 直接将字典分配给storage
            updated = True
            break

    if updated:
        with open(file3, 'w', encoding='utf-8') as file:
            json.dump(data3, file, indent=4)
        print(f"已经将storage信息更新到{file3}文件中。")
    else:
        print(f"未找到匹配的contract_addr为{to_value}的条目，未进行更新。")

process_files(file1_path, file2_path, file3_path)
