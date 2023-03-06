FROM nginx:latest

# 将当前目录下的 python 脚本复制到容器中的 /data 目录
COPY main.py /app/main.py

# 将前端文件复制到容器中的 /usr/share/nginx/html 目录
COPY index.html /usr/share/nginx/html

# 将 nginx 配置文件复制到容器中的 /etc/nginx/conf.d/default.conf
COPY nginx.conf /etc/nginx/nginx.conf

RUN apt-get update && apt-get install -y python3-pip && \
    pip3 install flask && \
    pip3 install --no-cache-dir requests && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# 暴露容器的端口
EXPOSE 80 

# 启动 Nginx 和 Python 应用程序
CMD ["/bin/bash", "-c", "python3 /app/main.py & nginx -g 'daemon off;'"]

