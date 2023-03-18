FROM nginx

# 将当前目录下的 python 脚本复制到容器中的 /app 目录
COPY main.py /app/main.py

# 将前端文件复制到容器中的 /usr/share/nginx/html 目录
COPY index.html /usr/share/nginx/html

# 将 nginx 配置文件复制到容器中的 /etc/nginx/conf.d/default.conf
COPY nginx.conf /etc/nginx/nginx.conf

# 将Python依赖包复制到容器中
#COPY requirements.txt /app/requirements.txt
RUN apt-get update && \
    apt-get install -y python3-pip redis-server && \
    pip3 install --no-cache-dir flask redis requests aiohttp && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

#RUN apt-get update && \
#    apt-get install -y python3-pip redis-server && \
#    pip3 install --no-cache-dir flask redis requests && \
#    apt-get clean && \
#    rm -rf /var/lib/apt/lists/*

# 暴露容器的端口
EXPOSE 4395

# 启动 Nginx 和 Python 应用程序
CMD ["/bin/bash", "-c", "redis-server & python3 /app/main.py & nginx -g 'daemon off;'"]
