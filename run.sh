#!/bin/bash
# 启动Redis服务器
redis-server /etc/redis/redis.conf &
# 启动Python DNS服务进程
python3 /app/dns.py &
# 启动主Python应用程序进程
python3 /app/main.py &
# just keep this script running
while [[ true ]]; do
    sleep 1
done