# 第一阶段：编译Python依赖包
FROM python:3-alpine as builder

RUN apk add --no-cache build-base libffi-dev

WORKDIR /app

COPY requirements.txt .

RUN pip install --user --no-cache-dir -r requirements.txt


# 第二阶段：构建最终镜像
FROM alpine:latest

RUN apk add --no-cache redis ffmpeg bash python3

EXPOSE 22771 22770 22772

WORKDIR /app

COPY --from=builder /root/.local /root/.local

ENV PATH=/root/.local/bin:$PATH

COPY ./*.py /app/
COPY ./ini/*.ini /app/ini/
COPY ./list/*.list /app/secret/
COPY ./list/*.yml /app/secret/

COPY ./bitcoin.png /app/img/
COPY index.html /app/templates/index.html
# 将Python依赖包复制到容器中
COPY run.sh /app/run.sh
COPY redis.conf /etc/redis/redis.conf

RUN mkdir -p /app/slices \
    && chmod -R 777 /app \
    && chmod +x run.sh main.py dns.py

CMD ["bash", "run.sh"]

# 启动 Nginx 和 Python 应用程序
#CMD ["/bin/bash", "-c", "redis-server & python3 /app/dns.py & python3 /app/main.py & nginx -g 'daemon off;'"]

