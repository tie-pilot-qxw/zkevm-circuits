#!/bin/bash

# 用途：从某个时间开始统计CPU和内存的数据，统计结束后自动生成CSV文件，用于后续Python进行数据分析
# 前提：提前安装sysstat，并且已经开启了sysstat监控
# 使用：在benchmark之前，执行: ./system_record.sh start <prefix> <interval>  ex: ./system_record.sh start super 30
#      在benchmark结束后，执行： ./system_record.sh stop <prefix>
# 执行stop后在当前目录下生成 cpu.stats, mem.stats
# 之后Python脚本读取上述文件，用于解析数据。
# 注：为了避免测试结果不正确及其他问题，尽量避免并行执行该脚本

prefix=$2
interval=$3

function start_sar {
    # 删除之前的数据文件
    rm -f ./${prefix}_sa_cpu
    rm -f ./${prefix}_sa_mem

    # 在后台运行sar命令收集CPU使用情况，输出到sa_cpu文件
    # 目前设置30s统计一次
    sar -o ${prefix}_sa_cpu ${interval} >/dev/null 2>&1 &
    # 记录sar命令的PID，以便稍后可以停止它
    echo $! > ${prefix}_sar_cpu.pid

    # 在后台运行sar命令收集内存使用情况，输出到sa_mem文件
    sar -r -o ${prefix}_sa_mem ${interval} >/dev/null 2>&1 &
    # 记录sar命令的PID，以便稍后可以停止它
    echo $! > ${prefix}_sar_mem.pid

    echo "sar data collection started."
}

function stop_sar {
    # 读取并杀死之前记录的sar进程
    if [ -f ${prefix}_sar_cpu.pid ]; then
        kill -9 $(cat ${prefix}_sar_cpu.pid)
        rm -f ${prefix}_sar_cpu.pid
    fi

    if [ -f ${prefix}_sar_mem.pid ]; then
        kill -9 $(cat ${prefix}_sar_mem.pid)
        rm -f ${prefix}_sar_mem.pid
    fi

    echo "sar data collection stopped."

    # 使用sadf处理数据并追加到文件
    if [ -f ${prefix}_sa_cpu ]; then
        sadf -d -t ${prefix}_sa_cpu >> ${prefix}_cpu.stats
        # 追加保持格式一致
	      sadf -d | grep 'LINUX-RESTART' >> ${prefix}_cpu.stats
	      rm -f ${prefix}_sa_cpu
    fi

    if [ -f ${prefix}_sa_mem ]; then
        sadf -d -t -- -r ${prefix}_sa_mem >> ${prefix}_mem.stats
        # 追加保证格式一致
	      sadf -d | grep 'LINUX-RESTART' >> ${prefix}_mem.stats
	      rm -f ${prefix}_sa_mem
    fi

    echo "Data has been processed and appended to ${prefix}_cpu.stats and ${prefix}_mem.stats."
}

# 检查命令和必要的参数
if [ -z "$1" ]; then
    echo "Error: No command provided."
    echo "Usage: $0 {start|stop} <prefix> <interval>"
    exit 1
fi

if [ -z "$2" ]; then
    echo "Error: No prefix provided."
    echo "Usage: $0 {start|stop} <prefix> <interval>"
    exit 1
fi

# 当执行start命令时，检查interval参数
if [ "$1" = "start" ] && [ -z "$3" ]; then
    echo "Error: No interval provided for start."
    echo "Usage: $0 start <prefix> <interval>"
    exit 1
fi

case "$1" in
    start)
        start_sar
        ;;
    stop)
        stop_sar
        ;;
    *)
        echo "first param not start or stop"
        exit 1
esac
