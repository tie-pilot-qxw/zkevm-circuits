#!/bin/bash

# 用途：从某个时间开始统计CPU和内存的数据，统计结束后自动生成CSV文件，用于后续Python进行数据分析
# 前提：提前安装sysstat，并且已经开启了sysstat监控
# 使用：在benchmark之前，执行: ./system_record.sh start
#      在benchmark结束后，执行： ./system_record.sh stop
# 执行stop后在当前目录下生成 cpu.stats, mem.stats
# 之后Python脚本读取上述文件，用于解析数据。

function start_sar {
    # 删除之前的数据文件
    rm -f ./sa_cpu
    rm -f ./sa_mem

    # 在后台运行sar命令收集CPU使用情况，输出到sa_cpu文件
    # 目前设置30s统计一次
    sar -o sa_cpu 30 >/dev/null 2>&1 &
    # 记录sar命令的PID，以便稍后可以停止它
    echo $! > sar_cpu.pid

    # 在后台运行sar命令收集内存使用情况，输出到sa_mem文件
    sar -r -o sa_mem 30 >/dev/null 2>&1 &
    # 记录sar命令的PID，以便稍后可以停止它
    echo $! > sar_mem.pid

    echo "sar data collection started."
}

function stop_sar {
    # 读取并杀死之前记录的sar进程
    if [ -f sar_cpu.pid ]; then
        kill -9 $(cat sar_cpu.pid)
        rm -f sar_cpu.pid
    fi

    if [ -f sar_mem.pid ]; then
        kill -9 $(cat sar_mem.pid)
        rm -f sar_mem.pid
    fi

    echo "sar data collection stopped."

    # 使用sadf处理数据并追加到文件
    if [ -f sa_cpu ]; then
        sadf -d -t sa_cpu >> cpu.stats
        # 追加保持格式一致
	      sadf -d | grep 'LINUX-RESTART' >> cpu.stats
	      rm -f sa_cpu
    fi

    if [ -f sa_mem ]; then
        sadf -d -t -- -r sa_mem >> mem.stats
        # 追加保证格式一致
	      sadf -d | grep 'LINUX-RESTART' >> mem.stats
	      rm -f sa_mem
    fi


    echo "Data has been processed and appended to cpu.stats and mem.stats."
}

case "$1" in
    start)
        start_sar
        ;;
    stop)
        stop_sar
        ;;
    *)
        echo "Usage: $0 {start|stop}"
        exit 1
esac
