"""
HTTP/1.1 反向代理（asyncio + h11，单进程）

职责：
  * 仅放行 POST /events，其余请求拒绝并关闭入站连接；
  * 完整校验入站帧格式（重复 Content-Length、TE/CL 并存、非法分块、正文超限等），
    校验通过后丢弃原始分帧，重建单一 Content-Length 再转发；
  * HMAC-SHA256 探针认证：头格式/时间窗口/签名先验，通过后在“首次写出前”
    完成撤销复核与 nonce 原子持久消费，重放与已撤销探针一律拒绝；
  * 固定上游，连接池容量 2，每条连接同一时刻只处理一笔；
  * 从发送起总限 2 秒；超时 / 客户端断连即销毁上游连接，迟到响应不会交给下一调用者；
  * 只有完整收齐带 Content-Length 的响应才把连接归还连接池。

nonce 一旦消费即不重发：消费发生在任何上游字节写出之前，之后的上游失败
只回 5xx，绝不自动重试（避免同一事件被写出两次）。

h11 是 sans-IO 解析器：它只负责字节 <-> 事件，所有 IO 与策略由本模块实现。
"""

from __future__ import annotations

import asyncio
import copy
import logging
import os
import time
from dataclasses import dataclass
from typing import Optional

import h11

from .auth_store import (
    AuthStore,
    NonceAlreadyConsumed,
    ProbeRevoked,
)
from .config import ConfigError, load_config
from .hmac_auth import (
    AUTH_HEADERS,
    AuthReject,
    verify_request,
)

# --------------------------------------------------------------------------- #
# 常量与配置
# --------------------------------------------------------------------------- #

MAX_BODY = 64 * 1024                      # 单请求正文硬上限 64 KiB
POOL_CAPACITY = 2                         # 上游连接池容量
UPSTREAM_TIMEOUT = 2.0                    # 从发送起总限时 2 秒
IDLE_TIMEOUT = 30.0                       # 入站连接空闲超时（防僵死占用）
READ_QUEUE_HWM = 8                        # 入站字节块队列高水位（背压）
READ_QUEUE_LWM = 2
READ_BLOCK = 65536

UPSTREAM_HOST = os.environ.get("UPSTREAM_HOST", "upstream")
UPSTREAM_PORT = int(os.environ.get("UPSTREAM_PORT", "8000"))
LISTEN_HOST = os.environ.get("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8080"))
# 与管理端（upstream 服务）共享的 SQLite 文件，compose 中挂同一命名卷。
AUTH_DB_PATH = os.environ.get("AUTH_DB_PATH", "/data/auth.db")
# nonce 记录保留期，仅用于后台清理；安全窗口由 30 秒时间戳偏差保证。
NONCE_RETENTION_SECONDS = int(os.environ.get("NONCE_RETENTION_SECONDS", "3600"))
PRUNE_INTERVAL_SECONDS = int(os.environ.get("PRUNE_INTERVAL_SECONDS", "600"))

# RFC 7230 §6.1 逐跳头，禁止被代理转发；另含常见的非标准 Proxy-Connection。
HOP_BY_HOP = frozenset(
    b"""
    connection keep-alive proxy-authenticate proxy-authorization te trailer
    transfer-encoding upgrade proxy-connection content-length host
    """.split()
)

log = logging.getLogger("smuggling-guard-proxy")


# --------------------------------------------------------------------------- #
# 自定义异常
# --------------------------------------------------------------------------- #


class RejectRequest(Exception):
    """入站请求未通过校验。status 为回给客户端的 HTTP 状态码，连接随后关闭。"""

    def __init__(self, status: int, reason: str):
        super().__init__(reason)
        self.status = status
        self.reason = reason


class ClientGone(Exception):
    """客户端在请求处理完成前断连。"""


class UpstreamError(Exception):
    """上游通信失败（连接、协议、对端关闭等）。"""


class CloseAfterReply(Exception):
    """错误响应已发送，只需关闭入站连接，不再写第二份响应。"""


# --------------------------------------------------------------------------- #
# 上游连接与连接池
# --------------------------------------------------------------------------- #


@dataclass
class UpstreamConn:
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    conn: h11.Connection
    busy: bool = False
    closed: bool = False
    requests_served: int = 0

    def close(self) -> None:
        """销毁连接。调用后该对象永远不会再回到池中。"""
        if self.closed:
            return
        self.closed = True
        try:
            self.writer.close()
        except OSError:
            pass
        # h11 状态同步清理，防止迟到事件残留（连接本身被丢弃，不会复用）。
        try:
            self.conn.send(h11.ConnectionClosed())
        except h11.LocalProtocolError:
            pass


class UpstreamPool:
    """容量固定为 2 的上游连接池；每条连接由 busy 保证同一时刻仅处理一笔。"""

    def __init__(self, host: str, port: int, capacity: int = POOL_CAPACITY):
        self._host = host
        self._port = port
        self._capacity = capacity
        self._idle: list[UpstreamConn] = []
        self._active = 0
        self._cond = asyncio.Condition()

    async def acquire(self) -> UpstreamConn:
        # 最多按容量次数尝试，避免空闲连接被对端静默关闭时反复拿到死连接。
        for _ in range(self._capacity + 1):
            uc = await self._take_slot()
            if uc is not None:
                # 活性预检：对端若已半关闭，reader 会立刻 EOF。
                if not uc.closed and not uc.reader.at_eof():
                    uc.busy = True
                    return uc
                await self.destroy(uc)  # 死连接销毁并补名额，继续尝试
                continue
            # 无空闲连接且池未满：在锁外新建，避免慢连接阻塞条件变量。
            try:
                reader, writer = await asyncio.open_connection(
                    self._host, self._port)
            except OSError as exc:
                async with self._cond:
                    self._active -= 1
                    self._cond.notify()
                raise UpstreamError(f"connect upstream failed: {exc}") from exc
            return UpstreamConn(reader, writer, h11.Connection(h11.CLIENT),
                                busy=True)
        raise UpstreamError("pool exhausted while recovering dead connections")

    async def _take_slot(self) -> Optional[UpstreamConn]:
        async with self._cond:
            while True:
                if self._idle:
                    return self._idle.pop()
                if self._active < self._capacity:
                    self._active += 1
                    return None
                await self._cond.wait()

    async def release(self, uc: UpstreamConn) -> None:
        """完整成功交换后归还；损坏 / 已关闭的连接直接销毁。"""
        uc.busy = False
        if uc.closed:
            async with self._cond:
                self._active -= 1
                self._cond.notify()
            return
        async with self._cond:
            self._idle.append(uc)
            self._cond.notify()

    async def destroy(self, uc: UpstreamConn) -> None:
        """失败路径：销毁连接并腾出池名额。"""
        uc.close()
        async with self._cond:
            self._active -= 1
            self._cond.notify()

    async def aclose(self) -> None:
        async with self._cond:
            for uc in self._idle:
                uc.close()
            self._idle.clear()


# --------------------------------------------------------------------------- #
# 上游交换：重建 Content-Length 转发，且只接受 Content-Length 成帧的响应
# --------------------------------------------------------------------------- #


async def exchange_upstream(
    pool: UpstreamPool,
    uc: UpstreamConn,
    method: bytes,
    target: bytes,
    headers: list[tuple[bytes, bytes]],
    body: bytes,
    strip_auth: bool = False,
) -> tuple[int, list[tuple[bytes, bytes]], bytes]:
    """在一条已获取的上游连接上完成一次完整的请求/响应交换。

    任何异常都意味着该连接可能处于帧错位状态，调用方必须销毁它，
    从而保证“迟到响应”绝不会被后续调用者读到。

    strip_auth=True 时剥离 HMAC 认证头：签名材料只在代理侧使用，
    上游业务服务看不到任何凭据材料。
    """
    # 重建单一 Content-Length，彻底剥离入站分块/歧义分帧。
    drop = HOP_BY_HOP | (AUTH_HEADERS if strip_auth else frozenset())
    out_headers = [(k, v) for k, v in headers if k.lower() not in drop]
    out_headers.append((b"content-length", str(len(body)).encode("ascii")))
    out_headers.append((b"host", f"{UPSTREAM_HOST}:{UPSTREAM_PORT}".encode("ascii")))

    try:
        uc.writer.write(uc.conn.send(h11.Request(
            method=method, target=target, headers=out_headers)))
        if body:
            uc.writer.write(uc.conn.send(h11.Data(data=body)))
        uc.writer.write(uc.conn.send(h11.EndOfMessage()))
        await uc.writer.drain()
    except (OSError, h11.LocalProtocolError) as exc:
        raise UpstreamError(f"send upstream failed: {exc}") from exc

    # ---- 读取完整响应 -----------------------------------------------------
    status_code: Optional[int] = None
    resp_headers: list[tuple[bytes, bytes]] = []
    chunks: list[bytes] = []
    saw_response = False

    while True:
        event = await _up_next_event(uc)

        if isinstance(event, h11.InformationalResponse):
            # 1xx 属于请求处理过程中的临时状态，代理不向上游之外的语义做承诺，直接忽略。
            continue

        if isinstance(event, h11.Response):
            saw_response = True
            status_code = event.status_code
            resp_headers = list(event.headers)
            continue

        if isinstance(event, h11.Data):
            chunks.append(bytes(event.data))
            continue

        if isinstance(event, h11.EndOfMessage):
            break

        if event is h11.ConnectionClosed:
            raise UpstreamError("upstream closed before complete response")

    if not saw_response or status_code is None:
        raise UpstreamError("upstream produced no response")

    # 只信任 Content-Length 成帧：chunked / 无长度 / 重复长度一律不复用连接。
    cl_headers = [v for k, v in resp_headers if k.lower() == b"content-length"]
    te_headers = [v for k, v in resp_headers if k.lower() == b"transfer-encoding"]
    if te_headers or len(cl_headers) != 1:
        raise UpstreamError("upstream response is not Content-Length framed")
    try:
        declared = int(cl_headers[0].decode("ascii"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise UpstreamError("upstream sent malformed Content-Length") from exc

    payload = b"".join(chunks)
    if declared != len(payload):
        raise UpstreamError("upstream Content-Length does not match body")

    uc.requests_served += 1
    try:
        uc.conn.start_next_cycle()
    except h11.LocalProtocolError as exc:
        raise UpstreamError(f"upstream connection not reusable: {exc}") from exc
    return status_code, resp_headers, payload


async def _up_read(uc: UpstreamConn, n: int = READ_BLOCK) -> bytes:
    try:
        data = await uc.reader.read(n)
    except (ConnectionError, OSError) as exc:
        raise UpstreamError(f"read upstream failed: {exc}") from exc
    return data


async def _up_next_event(uc: UpstreamConn):
    """驱动 h11 CLIENT 连接解析下一个事件。"""
    while True:
        try:
            event = uc.conn.next_event()
        except h11.RemoteProtocolError as exc:
            raise UpstreamError(f"upstream protocol error: {exc}") from exc
        if event is h11.NEED_DATA:
            data = await _up_read(uc)
            try:
                uc.conn.receive_data(data)
            except h11.RemoteProtocolError as exc:
                raise UpstreamError(f"upstream protocol error: {exc}") from exc
            continue
        return event


# --------------------------------------------------------------------------- #
# 入站校验
# --------------------------------------------------------------------------- #


def validate_framing(headers: list[tuple[bytes, bytes]]) -> tuple[bool, Optional[int]]:
    """校验请求头的分帧声明。

    返回 (是否 chunked, Content-Length 值)。任何歧义 / 非法形式都抛 RejectRequest，
    调用方拒绝并关闭连接，请求体不会被继续读取、更不会到达上游。
    """
    cl_values = [v for k, v in headers if k.lower() == b"content-length"]
    te_values = [v for k, v in headers if k.lower() == b"transfer-encoding"]

    # 1) 重复 Content-Length（含单头逗号分隔的多个值）——走私经典入口。
    if len(cl_values) > 1 or any(b"," in v for v in cl_values):
        raise RejectRequest(400, "duplicate Content-Length")
    cl: Optional[int] = None
    if cl_values:
        raw = cl_values[0].strip()
        # 只接受纯非负十进制整数；h11 本身也会拒绝负号/非数字，这里显式给出策略。
        if not raw.isdigit():
            raise RejectRequest(400, "malformed Content-Length")
        cl = int(raw)

    # 2) TE 与 CL 并存——RFC 7230 §3.3.3 要求必须拒绝（h11 0.16 不会自动拒绝！）。
    if te_values and cl is not None:
        raise RejectRequest(400, "Transfer-Encoding and Content-Length both present")

    # 3) 重复 TE 头，或不是 chunked（gzip/identity/压缩链等都不接受）。
    if len(te_values) > 1:
        raise RejectRequest(400, "duplicate Transfer-Encoding")
    if te_values:
        if te_values[0].strip().lower() != b"chunked":
            raise RejectRequest(400, "only Transfer-Encoding: chunked is accepted")
        return True, None

    # 无 TE 无 CL：按空正文处理（POST /events 允许空体）。
    return False, cl


# --------------------------------------------------------------------------- #
# 入站连接（低层 Protocol + 字节队列，便于及时发现断连与背压）
# --------------------------------------------------------------------------- #


_EOF = object()


async def _silent_await_cancel(task: asyncio.Task) -> None:
    """取消任务并吞掉 CancelledError；已完成则取回结果避免未取异常告警。"""
    if task.done():
        try:
            task.result()
        except Exception:  # noqa: BLE001 - 清理路径，结果无意义
            pass
        return
    task.cancel()
    try:
        await task
    except (asyncio.CancelledError, Exception):  # noqa: BLE001
        pass


class InboundProtocol(asyncio.Protocol):
    def __init__(self, pool: UpstreamPool, config, store: AuthStore):
        self._pool = pool
        self._config = config
        self._store = store
        self._h11 = h11.Connection(
            h11.SERVER, max_incomplete_event_size=MAX_BODY)
        self._queue: asyncio.Queue = asyncio.Queue(READ_QUEUE_HWM)
        self._transport: Optional[asyncio.Transport] = None
        self._peer = "?"
        self._closed_event = asyncio.Event()
        self._idle_task: Optional[asyncio.Task] = None
        self._main_task: Optional[asyncio.Task] = None
        self._graceful_eof = False  # reject() 已优雅半关闭时，结束回调不再硬关闭

    # ---- asyncio.Protocol 回调 ------------------------------------------- #

    def connection_made(self, transport: asyncio.Transport) -> None:
        self._transport = transport
        self._peer = "%s:%s" % transport.get_extra_info("peername")[:2]
        self._idle_task = asyncio.create_task(self._idle_watchdog())
        # 主处理协程：Protocol 只负责把字节塞进队列，解析与转发由 run() 驱动。
        self._main_task = asyncio.create_task(self.run())
        self._main_task.add_done_callback(self._main_done)
        log.info("inbound connected %s", self._peer)

    def _main_done(self, task: asyncio.Task) -> None:
        if not task.cancelled() and task.exception() is not None:
            log.exception("inbound task crashed %s", task.exception())
        # 优雅半关闭（write_eof）已排队时不能再 close，否则内核会用 RST 顶替 FIN。
        if self._graceful_eof:
            return
        if self._transport is not None and not self._transport.is_closing():
            self._transport.close()

    def data_received(self, data: bytes) -> None:
        # 队列高水位背压：暂停读取，等主循环消费到低水位再恢复。
        self._queue.put_nowait(data)
        if self._queue.qsize() >= READ_QUEUE_HWM:
            self._transport.pause_reading()

    def eof_received(self) -> Optional[bool]:
        self._queue.put_nowait(_EOF)
        return None  # 交由 connection_lost 关闭

    def connection_lost(self, exc: Optional[Exception]) -> None:
        self._closed_event.set()
        self._queue.put_nowait(_EOF)
        if self._idle_task:
            self._idle_task.cancel()

    async def _idle_watchdog(self) -> None:
        try:
            await asyncio.sleep(IDLE_TIMEOUT)
            log.warning("idle timeout %s", self._peer)
            self._transport.close()
        except asyncio.CancelledError:
            pass

    # ---- 字节读取与 h11 驱动 --------------------------------------------- #

    async def _fill(self) -> None:
        item = await self._queue.get()
        if item is _EOF:
            try:
                self._h11.receive_data(b"")
            except h11.RemoteProtocolError:
                pass
            return
        try:
            self._h11.receive_data(item)
        except h11.RemoteProtocolError as exc:
            raise RejectRequest(400, f"protocol error: {exc}") from exc
        # 消费到低水位以下后恢复读取，形成背压闭环。
        if self._transport is not None and not self._transport.is_reading() \
                and self._queue.qsize() <= READ_QUEUE_LWM:
            self._transport.resume_reading()

    async def next_event(self):
        while True:
            try:
                event = self._h11.next_event()
            except h11.RemoteProtocolError as exc:
                raise RejectRequest(400, f"protocol error: {exc}") from exc
            if event is h11.NEED_DATA:
                await self._fill()
                continue
            if event is h11.PAUSED:  # 理论上 SERVER 角色不会出现，防御性处理
                await asyncio.sleep(0)
                continue
            return event

    def _send(self, data: bytes) -> None:
        if self._transport is None or self._transport.is_closing():
            raise ClientGone("client transport closed")
        try:
            self._transport.write(data)
        except (ConnectionError, OSError) as exc:
            raise ClientGone(str(exc)) from exc

    # ---- 回包 / 拒绝 ------------------------------------------------------ #

    def send_simple(self, status: int, message: bytes, keep_alive: bool) -> None:
        headers = [
            (b"content-type", b"text/plain; charset=utf-8"),
            (b"content-length", str(len(message)).encode("ascii")),
            (b"connection", b"keep-alive" if keep_alive else b"close"),
        ]
        self._send(self._h11.send(h11.Response(status_code=status, headers=headers)))
        if message:
            self._send(self._h11.send(h11.Data(data=message)))
        self._send(self._h11.send(h11.EndOfMessage()))

    async def reject(self, status: int, reason: str) -> None:
        """拒绝并关闭：尽力回一个错误响应，刷新后半关闭，保证客户端能读到。"""
        log.warning("reject %s status=%s reason=%s", self._peer, status, reason)
        try:
            # 注意：send(Response) 本身就返回状态行+响应头字节，必须写出去，
            # 只 send(EndOfMessage) 会让客户端收到一个没有响应的空连接。
            self._send(self._h11.send(h11.Response(
                status_code=status,
                headers=[
                    (b"content-type", b"text/plain; charset=utf-8"),
                    (b"content-length", b"0"),
                    (b"connection", b"close"),
                ],
            )))
            self._send(self._h11.send(h11.EndOfMessage()))
            # 让出事件循环，确保 transport 把缓冲字节交付内核后再半关闭（FIN）。
            # 不能 pause_reading：那会触发 connection_lost，使 run() 的 finally
            # 抢先硬关闭并 RST 掉刚写的错误响应。
            await asyncio.sleep(0)
            # 1 秒后兜底硬关闭，防止对端不配合导致连接悬挂。
            loop = asyncio.get_running_loop()
            loop.call_later(1.0, self._hard_close)
            if self._transport.can_write_eof():
                self._graceful_eof = True
                self._transport.write_eof()
            else:
                self._hard_close()
        except (h11.LocalProtocolError, ClientGone, OSError, RuntimeError):
            self._hard_close()

    def _hard_close(self) -> None:
        if self._transport is not None and not self._transport.is_closing():
            try:
                self._transport.close()
            except OSError:
                pass

    # ---- 主处理循环 ------------------------------------------------------- #

    async def run(self) -> None:
        try:
            await self._loop()
        except ClientGone:
            log.info("client gone %s", self._peer)
        except CloseAfterReply:
            # 错误响应已经写出，这里只保证连接关闭。
            pass
        except RejectRequest as exc:
            await self.reject(exc.status, exc.reason)
        except Exception:
            log.exception("fatal inbound error %s", self._peer)
            if self._transport is not None and not self._transport.is_closing():
                self._transport.close()
        finally:
            if not self._graceful_eof and self._transport is not None \
                    and not self._transport.is_closing():
                self._transport.close()

    async def _loop(self) -> None:
        while True:
            request = await self.next_event()
            if isinstance(request, h11.ConnectionClosed):
                return

            assert isinstance(request, h11.Request)
            method = request.method
            target = request.target
            headers = list(request.headers)

            # 路由白名单：仅 POST /events，其余一律拒绝并关闭。
            if target != b"/events":
                raise RejectRequest(404, f"path not allowed: {target.decode('ascii', 'replace')}")
            if method != b"POST":
                raise RejectRequest(405, f"method not allowed: {method.decode('ascii', 'replace')}")

            chunked, declared_cl = validate_framing(headers)

            # Expect: 100-continue —— 仅在分帧校验通过后才放行继续发送正文。
            if any(k.lower() == b"expect" and b"100-continue" in v.lower()
                   for k, v in headers):
                self._send(self._h11.send(
                    h11.InformationalResponse(status_code=100, headers=[])))

            # 声明长度已知且超限，可在读取前直接拒绝，避免浪费带宽。
            if not chunked and declared_cl is not None and declared_cl > MAX_BODY:
                raise RejectRequest(413, f"body exceeds {MAX_BODY} bytes")

            body = await self._read_body(chunked, declared_cl)
            log.info(
                "validated request %s target=/events bytes=%d chunked=%s",
                self._peer, len(body), chunked,
            )

            # 无状态认证：头格式、时间戳窗口（±30s）、HMAC 签名。
            # 此处失败一律不触碰 nonce 表——认证拒绝不消费 nonce。
            try:
                auth_ctx = verify_request(
                    headers, body, self._config.probes)
            except AuthReject as exc:
                raise RejectRequest(exc.status, exc.reason) from exc

            # 早期撤销检查：让已撤销探针的请求不必排队即可快速失败。
            # 真正的权威检查在 nonce 消费事务里（首次写出前再复核一次）。
            if await self._store.is_revoked(auth_ctx.probe_id):
                raise RejectRequest(403, "probe has been revoked")

            keep_alive = _wants_keep_alive(request.http_version, headers)
            await self._forward(headers, body, keep_alive, auth_ctx)

            if not keep_alive:
                return
            self._h11.start_next_cycle()

    async def _read_body(self, chunked: bool, declared_cl: Optional[int]) -> bytes:
        """完整读取并校验正文；支持 TCP 分片与流水线（h11 缓冲下一请求字节）。"""
        buf = bytearray()
        while True:
            event = await self.next_event()
            if isinstance(event, h11.EndOfMessage):
                break
            if not isinstance(event, h11.Data):
                raise RejectRequest(400, "unexpected event while reading body")
            buf.extend(event.data)
            if len(buf) > MAX_BODY:
                raise RejectRequest(413, f"body exceeds {MAX_BODY} bytes")
        # 非 chunked 且带 CL：h11 已按长度截断，这里做双保险确认。
        if not chunked and declared_cl is not None and len(buf) != declared_cl:
            raise RejectRequest(400, "truncated or mismatched Content-Length body")
        # 反走私关键检查：当前请求完整结束后，区分“合法流水线缓冲”与“走私残片”。
        self._reject_smuggled_tail()
        return bytes(buf)

    def _reject_smuggled_tail(self) -> None:
        """请求体结束后，h11 内部若残留字节，必须能解析成下一条合法请求。

        合法流水线（含跨 TCP 段的半截下一请求前缀）放行；任何无法成帧的
        残片（CL.TE/TE.CL 走私、夹带后台请求等）一律拒绝并关闭连接。
        探测在 h11 连接的深拷贝上进行，主连接状态不被修改。
        """
        try:
            buffer = bytes(self._h11._receive_buffer)  # noqa: SLF001
        except AttributeError:
            return
        if not buffer.strip(b"\r\n"):
            return  # 仅空行前导，容忍
        probe = copy.deepcopy(self._h11)
        try:
            probe.send(h11.Response(
                status_code=200,
                headers=[(b"content-length", b"0")]))
            probe.send(h11.EndOfMessage())
            probe.start_next_cycle()
            event = probe.next_event()
        except (h11.RemoteProtocolError, h11.LocalProtocolError) as exc:
            raise RejectRequest(
                400, f"trailing bytes not forming valid next request: {exc}")
        # Request = 完整的下一请求（流水线）；NEED_DATA = 半截前缀，等更多字节。
        if not isinstance(event, h11.Request) and event is not h11.NEED_DATA:
            raise RejectRequest(
                400, "unexpected trailing bytes after request body")

    # ---- 转发 ------------------------------------------------------------- #

    async def _acquire_abortable(self) -> UpstreamConn:
        """获取上游连接；等待期间客户端断连则立即中止，不再占用池名额。"""
        acquired = asyncio.create_task(self._pool.acquire())
        closed = asyncio.create_task(self._closed_event.wait())
        try:
            await asyncio.wait({acquired, closed}, return_when=asyncio.FIRST_COMPLETED)
        except asyncio.CancelledError:
            acquired.cancel()
            closed.cancel()
            raise
        if not acquired.done():
            acquired.cancel()
            raise ClientGone("client closed while waiting for upstream slot")
        closed.cancel()
        if acquired.exception() is not None:
            raise UpstreamError(str(acquired.exception()))
        return acquired.result()

    async def _forward(
        self,
        headers: list[tuple[bytes, bytes]],
        body: bytes,
        keep_alive: bool,
        auth_ctx,
    ) -> None:
        # 排队/建连可能耗时；先拿到上游连接，再在“首次写出前”做权威门控。
        # 若等待期间探针被撤销，下面的事务会发现 revoked 并拒绝（403），
        # 已获取的连接原样归还池（门控通过前不写任何字节）。
        uc = await self._acquire_abortable()
        gate_passed = False
        try:
            try:
                # 单事务：撤销复核 + nonce 持久消费。COMMIT 后 SQLite 写锁
                # 立即释放，之后的网络等待不持有任何数据库写锁。
                await self._store.consume_nonce(
                    auth_ctx.probe_id, auth_ctx.nonce, auth_ctx.timestamp)
            except NonceAlreadyConsumed as exc:
                # 重放：nonce 此前已消费，本次不重复消费、不写出。
                raise RejectRequest(
                    409, "nonce already consumed (replay)") from exc
            except ProbeRevoked as exc:
                # 排队/建连期间被永久撤销：尚未写出，拒绝。
                raise RejectRequest(403, "probe has been revoked") from exc
            except Exception as exc:  # noqa: BLE001 - 存储故障 fail-closed
                log.exception("auth store failure %s", self._peer)
                raise RejectRequest(
                    503, "authentication state unavailable") from exc
            gate_passed = True

            # nonce 已持久消费：从此刻起任何失败都不得重发，直接回 5xx。
            # 2 秒预算从首次向上游写出开始计时。
            deadline = time.monotonic() + UPSTREAM_TIMEOUT
            exchange_task = asyncio.create_task(exchange_upstream(
                self._pool, uc, b"POST", b"/events", headers, body,
                strip_auth=True))
            closed_task = asyncio.create_task(self._closed_event.wait())
            timed_out = False
            try:
                try:
                    async with asyncio.timeout(UPSTREAM_TIMEOUT):
                        await asyncio.wait(
                            {exchange_task, closed_task},
                            return_when=asyncio.FIRST_COMPLETED)
                except (asyncio.TimeoutError, TimeoutError):
                    timed_out = True
            finally:
                closed_task.cancel()

            # 1) 客户端先断连：取消交换、销毁上游连接后向上抛 ClientGone。
            if not exchange_task.done() and self._closed_event.is_set():
                exchange_task.cancel()
                await _silent_await_cancel(exchange_task)
                await self._pool.destroy(uc)
                raise ClientGone("client closed during upstream exchange")

            # 2) 交换自身先完成（成功或上游错误），优先采用它的结果。
            if exchange_task.done() and not timed_out:
                try:
                    status, resp_headers, payload = exchange_task.result()
                except UpstreamError as exc:
                    # 不重试：nonce 已消费，重试可能导致同一事件被写出两次。
                    await self._pool.destroy(uc)
                    log.warning(
                        "upstream ERROR after nonce consumed %s: %s; "
                        "no retry (nonce not replayed)", self._peer, exc)
                    await self._reply_error(
                        502, b"bad gateway\n", keep_alive=False)
                    raise CloseAfterReply("502 sent; close inbound") from exc
                # 交换恰好完成与客户端断连同拍：响应无法送达，连接仍销毁。
                if self._closed_event.is_set():
                    await self._pool.destroy(uc)
                    raise ClientGone("client closed right after exchange")
                await self._pool.release(uc)
                self._reply_upstream(status, resp_headers, payload, keep_alive)
                return

            # 3) 超时：取消交换并销毁，迟到响应随连接丢弃；同样不重试。
            if timed_out:
                await _silent_await_cancel(exchange_task)
                await self._pool.destroy(uc)
                elapsed = (time.monotonic()
                           - (deadline - UPSTREAM_TIMEOUT)) * 1000
                log.warning(
                    "upstream TIMEOUT %s elapsed=%.0fms conn destroyed; "
                    "nonce stays consumed (no replay)", self._peer, elapsed)
                await self._reply_error(
                    504, b"upstream timeout\n", keep_alive=False)
                raise CloseAfterReply("504 sent; close inbound")

            # 理论不可达：两任务都未完成且未超时。防御性按上游错误处理。
            await _silent_await_cancel(exchange_task)
            await self._pool.destroy(uc)
            raise CloseAfterReply("unexpected wait state; close inbound")
        finally:
            if not gate_passed:
                # 门控失败（撤销/重放/库故障）：连接上未写出任何请求字节，
                # 可安全归还池供其他探针使用；客户端断连则连接由获取方释放名额。
                if not uc.closed:
                    await self._pool.release(uc)

    def _reply_upstream(
        self,
        status: int,
        headers: list[tuple[bytes, bytes]],
        payload: bytes,
        keep_alive: bool,
    ) -> None:
        clean = [(k, v) for k, v in headers if k.lower() not in HOP_BY_HOP]
        clean.append((b"content-length", str(len(payload)).encode("ascii")))
        clean.append((b"connection", b"keep-alive" if keep_alive else b"close"))
        self._send(self._h11.send(h11.Response(
            status_code=status, headers=clean)))
        if payload:
            self._send(self._h11.send(h11.Data(data=payload)))
        self._send(self._h11.send(h11.EndOfMessage()))

    async def _reply_error(self, status: int, message: bytes,
                           keep_alive: bool) -> None:
        try:
            self.send_simple(status, message, keep_alive)
        except (ClientGone, h11.LocalProtocolError, OSError):
            pass


def _wants_keep_alive(http_version: bytes,
                      headers: list[tuple[bytes, bytes]]) -> bool:
    if http_version == b"1.0":
        return any(k.lower() == b"connection" and b"keep-alive" in v.lower()
                   for k, v in headers)
    # HTTP/1.1 默认保持，除非显式 close。
    return not any(k.lower() == b"connection" and b"close" in v.lower()
                   for k, v in headers)


# --------------------------------------------------------------------------- #
# 入口
# --------------------------------------------------------------------------- #


async def _prune_loop(store: AuthStore) -> None:
    """周期清理过期 nonce 行；清理失败只记日志，不影响数据转发。"""
    while True:
        await asyncio.sleep(PRUNE_INTERVAL_SECONDS)
        try:
            removed = await store.prune()
            if removed:
                log.info("pruned %d expired nonce rows", removed)
        except Exception:  # noqa: BLE001
            log.exception("nonce prune failed")


async def serve() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    try:
        config = load_config()
    except ConfigError as exc:
        log.error("配置错误，拒绝启动：%s", exc)
        raise SystemExit(2) from exc

    store = AuthStore(AUTH_DB_PATH, NONCE_RETENTION_SECONDS)
    pool = UpstreamPool(UPSTREAM_HOST, UPSTREAM_PORT, POOL_CAPACITY)
    loop = asyncio.get_running_loop()
    prune_task = asyncio.create_task(_prune_loop(store))

    server = await loop.create_server(
        lambda: InboundProtocol(pool, config, store),
        LISTEN_HOST, LISTEN_PORT)
    addr = server.sockets[0].getsockname()
    log.info(
        "proxy listening on %s, upstream=%s:%s, pool=%d, timeout=%.1fs, "
        "probes=%d, auth_db=%s",
        addr, UPSTREAM_HOST, UPSTREAM_PORT, POOL_CAPACITY, UPSTREAM_TIMEOUT,
        len(config.probes), AUTH_DB_PATH)

    try:
        async with server:
            await server.serve_forever()
    finally:
        prune_task.cancel()
        await pool.aclose()
        store.close()


def main() -> None:
    try:
        asyncio.run(serve())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
