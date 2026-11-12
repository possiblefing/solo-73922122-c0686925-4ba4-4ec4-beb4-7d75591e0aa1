"""
本地日志接收端（模拟真实后台）。

职责：
  * 接收 POST /events 并完整落库“实际收到的请求”（原始头、正文、来自哪条 TCP 连接），
    用于演示代理是否真的把走私请求挡在外面；
  * 提供查询 / 清空接口与 /docs 演示 API（FastAPI 自动文档）；
  * 支持 X-Demo-Delay 秒级延迟，用于演示代理 2 秒超时与连接池容量；
  * 所有响应一律使用 Content-Length 成帧（代理只信任该成帧方式）。
"""

from __future__ import annotations

import asyncio
import os
import time
from collections import deque
from typing import Optional

from fastapi import FastAPI, Request, Response
from pydantic import BaseModel, Field

MAX_STORED = int(os.environ.get("UPSTREAM_MAX_STORED", "200"))

app = FastAPI(
    title="日志接收端（上游）",
    description="探针事件上报的模拟后台，记录代理转发上来的**实际请求**，用于验证反走私效果。",
    version="1.0.0",
)


class Store:
    def __init__(self) -> None:
        self.records: deque[dict] = deque(maxlen=MAX_STORED)
        self.lock = asyncio.Lock()
        self.counter = 0

    async def add(self, record: dict) -> int:
        async with self.lock:
            self.counter += 1
            record["seq"] = self.counter
            self.records.append(record)
            return self.counter

    async def snapshot(self) -> list[dict]:
        async with self.lock:
            return list(self.records)

    async def clear(self) -> int:
        async with self.lock:
            n = len(self.records)
            self.records.clear()
            return n


STORE = Store()


class EventIn(BaseModel):
    # 演示用：结构故意宽松，重点是代理层的 HTTP 分帧安全而非业务校验。
    event: Optional[str] = Field(default=None, description="事件名")
    payload: Optional[dict | list | str | int | float | bool] = Field(
        default=None, description="任意事件负载")


@app.middleware("http")
async def record_request(request: Request, call_next):
    # 演示延迟头：让上游慢一点，触发代理 2 秒总限时 / 观察连接池排队。
    delay = 0.0
    raw_delay = request.headers.get("x-demo-delay")
    if raw_delay:
        try:
            delay = max(0.0, min(10.0, float(raw_delay)))
        except ValueError:
            delay = 0.0

    body = await request.body()
    received_at = time.time()
    if delay:
        await asyncio.sleep(delay)

    # 同一条 TCP 连接上的第 N 个请求（uvicorn 每次连接复用同一 socket 对端）。
    peername = request.scope.get("client") or ("?", 0)
    conn_key = f"{peername[0]}:{peername[1]}"

    record = {
        "received_at": received_at,
        "method": request.method,
        "path": request.url.path,
        "http_version": request.scope.get("http_version"),
        "client_tcp": conn_key,
        # 关键证据：上游逐字看到的头与正文。代理重建后这里应只有一个 Content-Length。
        "headers": {k.decode("latin1"): v.decode("latin1")
                    for k, v in request.headers.raw},
        "body_bytes": len(body),
        "body_text": body.decode("utf-8", "replace"),
        "delay_seconds": delay,
    }
    seq = await STORE.add(record)
    request.state.record_seq = seq

    response: Response = await call_next(request)
    response.headers["X-Upstream-Conn"] = conn_key
    response.headers["X-Upstream-Seq"] = str(seq)
    return response


@app.post("/events", status_code=202)
async def ingest_events(request: Request, event: EventIn | None = None) -> dict:
    """接收探针事件。代理只允许把 POST /events 转发到这里。

    `event` 仅用于在 /docs 中展示请求体 schema；实际落库以中间件读到的
    原始字节为准（证据需要逐字还原代理重建后的 Content-Length 正文）。
    """
    seq = request.state.record_seq
    return {"accepted": True, "seq": seq, "stored_total": STORE.counter}


@app.get("/events", summary="查看上游实际收到的请求")
async def list_events(limit: int = 50) -> dict:
    items = await STORE.snapshot()
    return {"count": len(items), "items": items[-limit:]}


@app.delete("/events", summary="清空已记录请求（演示前重置证据）")
async def clear_events() -> dict:
    removed = await STORE.clear()
    return {"cleared": removed}


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}
