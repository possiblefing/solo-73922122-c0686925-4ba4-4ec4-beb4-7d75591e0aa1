"""
本地日志接收端（模拟真实后台）。

职责：
  * 接收 POST /events 并完整落库“实际收到的请求”（原始头、正文、来自哪条 TCP 连接），
    用于演示代理是否真的把走私请求挡在外面；
  * 提供查询 / 清空接口与 /docs 演示 API（FastAPI 自动文档）；
  * 管理 API（/admin/*）：凭 ADMIN_KEY 永久撤销探针、查询撤销状态与 nonce 消费状态，
    状态写入与代理共享的 SQLite（compose 挂同一命名卷）；
  * 支持 X-Demo-Delay 秒级延迟，用于演示代理 2 秒超时与连接池容量；
  * 所有响应一律使用 Content-Length 成帧（代理只信任该成帧方式）。
"""

from __future__ import annotations

import asyncio
import hmac
import os
import re
import time
from collections import deque
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from pydantic import BaseModel, Field

from .admin_db import (
    is_revoked,
    list_revoked,
    nonce_status,
    open_admin_db,
    revoke_probe,
)
from .config import ConfigError, load_config

MAX_STORED = int(os.environ.get("UPSTREAM_MAX_STORED", "200"))
AUTH_DB_PATH = os.environ.get("AUTH_DB_PATH", "/data/auth.db")

try:
    CONFIG = load_config()
except ConfigError as exc:  # 配置缺失时保持演示服务可启动，但管理 API 不可用
    CONFIG = None
    print(f"[upstream] 警告：探针配置加载失败（管理 API 将拒绝请求）：{exc}")

app = FastAPI(
    title="日志接收端（上游）",
    description=(
        "探针事件上报的模拟后台，记录代理转发上来的**实际请求**，用于验证反走私效果。\n\n"
        "另在 `/admin` 标签下提供凭密钥的探针管理 API（永久撤销、状态查询），"
        "状态持久化在与代理共享的 SQLite 中。"
    ),
    version="2.0.0",
)


@app.on_event("startup")
def _open_db() -> None:
    app.state.admin_db = open_admin_db(AUTH_DB_PATH)


@app.on_event("shutdown")
def _close_db() -> None:
    app.state.admin_db.close()


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


# --------------------------------------------------------------------------- #
# 管理 API 鉴权依赖
# --------------------------------------------------------------------------- #


def require_admin(x_admin_key: Optional[str] = Header(default=None)) -> None:
    """凭启动配置中的管理密钥鉴权；常量时间比较，防止计时侧信道。"""
    if CONFIG is None or not CONFIG.admin_key:
        raise HTTPException(status_code=503,
                            detail="admin API not configured on this instance")
    if x_admin_key is None or not hmac.compare_digest(
            x_admin_key, CONFIG.admin_key):
        raise HTTPException(status_code=401, detail="invalid admin key")


# --------------------------------------------------------------------------- #
# 管理 API（/docs 中可直接操作，标签：探针管理）
# --------------------------------------------------------------------------- #


class RevokeResponse(BaseModel):
    probe_id: str
    revoked: bool
    already_revoked: bool
    revoked_at: float


class ProbeStatusResponse(BaseModel):
    probe_id: str
    known: bool
    revoked: bool


@app.get("/admin/probes",
         tags=["探针管理"],
         summary="列出启动配置中的探针及撤销状态",
         dependencies=[Depends(require_admin)])
async def admin_list_probes() -> dict:
    conn = app.state.admin_db
    known = sorted(CONFIG.probes)
    return {
        "probes": [
            {"probe_id": pid, "revoked": is_revoked(conn, pid)}
            for pid in known
        ],
        "revoked_rows": list_revoked(conn),
    }


@app.get("/admin/probes/{probe_id}",
         tags=["探针管理"],
         summary="查询单个探针状态（是否在配置中、是否已撤销）",
         dependencies=[Depends(require_admin)])
async def admin_probe_status(probe_id: str) -> ProbeStatusResponse:
    return ProbeStatusResponse(
        probe_id=probe_id,
        known=CONFIG is not None and probe_id in CONFIG.probes,
        revoked=is_revoked(app.state.admin_db, probe_id),
    )


@app.post("/admin/probes/{probe_id}/revoke",
          tags=["探针管理"],
          status_code=200,
          summary="永久撤销探针（幂等；排队/建连中未写出的上报也会被代理拒绝）",
          dependencies=[Depends(require_admin)],
          response_model=RevokeResponse)
async def admin_revoke_probe(probe_id: str) -> RevokeResponse:
    if CONFIG is None or probe_id not in CONFIG.probes:
        # 不允许凭空撤销配置外的 ID，避免把拼写错误写成永久状态。
        raise HTTPException(status_code=404, detail="unknown probe id")
    already = is_revoked(app.state.admin_db, probe_id)
    is_new = revoke_probe(app.state.admin_db, probe_id)
    assert is_new == (not already)
    row = app.state.admin_db.execute(
        "SELECT revoked_at FROM revoked_probes WHERE probe_id = ?",
        (probe_id,),
    ).fetchone()
    return RevokeResponse(
        probe_id=probe_id,
        revoked=True,
        already_revoked=already,
        revoked_at=row[0],
    )


@app.get("/admin/nonces/{probe_id}/{nonce}",
         tags=["探针管理"],
         summary="查询某探针的 nonce 是否已被持久消费（重启后仍可查）",
         dependencies=[Depends(require_admin)])
async def admin_nonce_status(probe_id: str, nonce: str) -> dict:
    if not re.fullmatch(r"[0-9a-f]{32}", nonce):
        raise HTTPException(status_code=400,
                            detail="nonce must be 32 lowercase hex chars")
    return nonce_status(app.state.admin_db, probe_id, nonce)


# --------------------------------------------------------------------------- #
# 事件取证
# --------------------------------------------------------------------------- #


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
        # 关键证据：上游逐字看到的头与正文。代理重建后这里应只有一个 Content-Length，
        # 且 X-Probe-* 认证头已被代理剥离。
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
    return {"status": "ok", "auth_db": AUTH_DB_PATH,
            "probes_configured": 0 if CONFIG is None else len(CONFIG.probes)}
