FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /srv

COPY requirements.txt /srv/requirements.txt
RUN pip install --no-cache-dir -r /srv/requirements.txt

COPY app /srv/app

# 认证状态（撤销 + nonce 消费）SQLite 所在目录；compose 挂载命名卷覆盖。
RUN mkdir -p /data

# 单进程 asyncio 反向代理
CMD ["python", "-m", "app.main"]
