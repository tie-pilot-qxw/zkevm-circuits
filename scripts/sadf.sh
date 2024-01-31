#!/bin/bash

# 来源：scroll的sadf脚本，可以用于采集周期性的数据给grafana
# 用途：该脚本直接扫描Centos7目录下的/var/log/sa目录下的文件，会收集统计过的所有数据

# sysstat是一个软件包，包含监测系统性能及效率的一组工具，这些工具对于我们收集系统性能数据，比如：CPU 使用率、硬盘和网络吞吐数据
# ubuntu使用：(https://blog.51cto.com/u_11529070/6508307), centos同理，yum安装
# 1.安装sysstat
# 2.修改/etc/default/sysstat文件，将ENABLED="false"改为ENABLED="true"
# 3.sudo systemctl enable --now sysstat.service
# 4.修改定时任务，可以改为每分钟一次
# 记录的日志路径centos路径为:/var/log/sa, ubuntu路径为/var/log/sysstat

# sadf 可以将sar的统计结果转换为其他格式，如json，csv等；

sleep 5
# sar开头的文件一般是使用sar命令输出的统计文件，这里我们只需要saXX文件即可，
# 当开启了sysstat以后，一般会生成saXX文件，XX代表日期，如sa01，sa02等，这些文件是二进制文件，
# sar 可以统计cpu，内存等信息， 也可以当做查看信息的工具；
sudo rm -f /var/log/sa/sar*
# 查找 /var/log/sysstat/ 目录下所有的文件（不包括目录），并计算它们的数量
sacount=$(sudo find /var/log/sa/ -type f | wc -l)

# sadf -d 代表当天数据，会筛选/var/log/sysstat中当天的saXX文件，sadf -1 -d就表示输出前一天的saXX文件
previousdays=$(expr 1 - $sacount)
while [ $previousdays -lt 0 ]
do
  # 使用 sadf 命令收集前 previousdays 天的CPU使用情况，并以特定格式追加到文件 cpu.stats， -d 选项指示 sadf 以（CSV）格式输出数据。
  sadf $previousdays -d -t >> cpu.stats
  # 收集内存使用情况并暗战CSV格式追加到 mem.stats 文件
  sadf $previousdays -d -t -- -r >> mem.stats
  (( previousdays++ ))
done

# 当天数据
sadf -d >> cpu.stats
sadf -d -- -r >> mem.stats