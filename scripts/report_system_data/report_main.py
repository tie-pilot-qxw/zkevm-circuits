# Copyright (C) SAFIT. All rights reserved.
# Copyright (C) BABEC. All rights reserved.
# Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
#
# SPDX-License-Identifier: Apache-2.0

import argparse, json
import datetime
import report_bench as bench_r 
import report_system as report_s
# import sqlite3
import pandas as pd 
import pymysql
from sqlalchemy import create_engine
env = json.load(open('./report_system_data/env.json'))

def main():
    parser = argparse.ArgumentParser('BenchmarkResults',
                                     "python3 report_main.py super_circuit-1706871711 super_circuit-1706871711.log super_circuit-1706871711_cpu.stats super_circuit-1706871711_mem.stats",
                                     'write data to prometheus')
    parser.add_argument('test_id')
    parser.add_argument('log_file')
    parser.add_argument('cpu_stats')
    parser.add_argument('mem_stats')
    args = parser.parse_args()
    (test_id, log_file, cpu_stats, mem_stats) = (args.test_id, args.log_file, args.cpu_stats, args.mem_stats)
    print(test_id, log_file, cpu_stats, mem_stats)

    # 解析cpu和memory的数据
    d_cpu_stats, d_mem_stats, d_sys_stat = report_s.calc_stats(cpu_stats, mem_stats)
    # 解析bench结果
    d_bench_result = bench_r.log_processor(test_id,log_file)

    mysql_str = f'mysql+pymysql://{env["mysql_user"]}:{env["mysql_pwd"]}@{env["mysql_server"]}'
    print(mysql_str)
    engine = create_engine(mysql_str)
    # 写入bench数据  
    write_bench_result_to_sql(test_id, d_bench_result, d_sys_stat, engine)
    # 写入cpu数据
    write_cpu_to_sql(test_id, d_cpu_stats, engine)
    # 写入mem数据
    write_mem_to_sql(test_id, d_mem_stats, engine)
    return 

def write_mem_to_sql(test_id, d_mem_stats, engine):
    table = 'testresults_memory_time'
    d_mem_stats['dummy'] = d_mem_stats['timestamp'].apply(lambda x: f'{False}')
    d_mem_stats['test_id'] = d_mem_stats['timestamp'].apply(lambda x: f'{test_id}')
    d_mem_stats.to_sql(table,engine,if_exists='append',index=False)
    return 


def write_cpu_to_sql(test_id, d_cpu_stats, engine):
    table = 'testresults_cpu_time'
    d_cpu_stats['dummy'] = d_cpu_stats['timestamp'].apply(lambda x: f'{False}')
    d_cpu_stats['test_id'] = d_cpu_stats['timestamp'].apply(lambda x: f'{test_id}')
    d_cpu_stats.to_sql(table,engine,if_exists='append',index=False)    
    return 

def write_bench_result_to_sql(test_id, d_bench_result, d_sys_stat, engine):
    try:
        r = {
            'test_id':              test_id,
            'degree':               d_bench_result['degree'],
            'max_num_row':          d_bench_result['max_num_row'],
            'witness_gen':          d_bench_result['witness_gen'],
            'circuit_create':       d_bench_result['circuit_create'],
            'setup_gen':            d_bench_result['setup_gen'],
            'verify_proof':         d_bench_result['verify_proof'],
            'create_proof':         d_bench_result['create_proof'],
            'result':               d_bench_result['result'],
            'max_ram':              d_sys_stat['max_ram'],
            'cpu_all_Average':      d_sys_stat['cpu_all_Average'],
            'cpu_all_Max':          d_sys_stat['cpu_all_Max'],
            'cpu_count':            d_sys_stat['cpu_count'],
            'test_date':            datetime.datetime.now().date(),
        }
    except Exception as e:
        print("write_bench_result_to_sql parse failed",e)
    
    bench_datas = pd.DataFrame([r])
    bench_datas = bench_datas.set_index('test_date')
    bench_datas.to_sql('testresults_circuit_benchmark',engine,if_exists='append')
    return 

if __name__ == '__main__':
    main()  


