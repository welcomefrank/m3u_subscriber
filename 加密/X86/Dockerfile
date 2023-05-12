FROM nginx
# 创建目录
RUN mkdir -p /app/ini /app/img /app/secret /app/slices
COPY ./*.exe /app/
COPY ./ini/*.ini /app/ini/
COPY ./list/*.list /app/secret/
COPY ./list/*.yml /app/secret/
COPY ./bitcoin.png /app/img/
# 将前端文件复制到容器中的 /usr/share/nginx/html 目录
COPY index.html /usr/share/nginx/html
# 将 nginx 配置文件复制到容器中的 /etc/nginx/conf.d/default.conf
COPY nginx.conf /etc/nginx/nginx.conf

RUN apt-get update && \
    apt-get install -yqq --no-install-recommends  redis-server ffmpeg && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# 暴露容器的端口 22771-web 22770-dns 22772-redis
EXPOSE 22771 22770 22772
# 启动多个程序进程
COPY run.sh /app/run.sh
COPY redis.conf /etc/redis/redis.conf
RUN chmod 777 /app/run.sh
RUN chmod 777 /app/main.exe
RUN chmod 777 /app/dns.exe
CMD ["/bin/bash", "-c", "/app/run.sh"]