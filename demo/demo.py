#!/usr/bin/env python3
"""
反走私代理演示客户端（仅标准库，原始字节操作）。

运行：
    python3 demo/demo.py
可选环境变量：
    PROXY_HOST   默认 127.0.0.1
    PROXY_PORT   默认 8080
    UPSTREAM_URL 默认 http://127.0.0.1:8000

演示内容：
  1. 分片发送的合法 POST /events（逐字节 / 小块 TCP 分片）
  2. 同连接流水线两个合法请求
  3. chunked 请求（代理应重建单一 Content-Length）
  4. 五种 HTTP 请求走私 / 畸形分帧攻击（全部应被拒绝并断连，且不到达上游）
  5. 延迟响应：上游慢 2.5s，代理 2s 超时回 504 并销毁连接，后续请求仍正常
  6. 连接池容量 2：3 个并发慢请求体现两车道
最后直接拉取上游“实际收到的请求”清单作为证据。
"""

from __future__ import annotations

import json
import os
import socket
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

PROXY_HOST = os.environ.get("PROXY_HOST", "127.0.0.1")
PROXY_PORT = int(os.environ.get("PROXY_PORT", "8080"))
UPSTREAM_URL = os.environ.get("UPSTREAM_URL", "http://127.0.0.1:8000")

PASS = "PASS"
FAIL = "FAIL"


@dataclass
class Report:
    results: list[tuple[str, bool, str]] = field(default_factory=list)

    def add(self, name: str, ok: bool, detail: str) -> None:
        self.results.append((name, ok, detail))
        mark = "✅" if ok else "❌"
        print(f"  {mark} {name}: {detail}")

    def summary(self) -> int:
        passed = sum(1 for _, ok, _ in self.results if ok)
        print(f"\n==== 结果汇总：{passed}/{len(self.results)} 通过 ====")
        return 0 if passed == len(self.results) else 1


# --------------------------------------------------------------------------- #
# 原始 socket 工具
# --------------------------------------------------------------------------- #


def connect() -> socket.socket:
    s = socket.create_connection((PROXY_HOST, PROXY_PORT), timeout=5)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return s


def send_splintered(sock: socket.socket, data: bytes,
                    size: int = 3) -> None:
    """模拟 TCP 分片：把完整报文切成小块逐块发送，块间让出事件循环时间。"""
    for i in range(0, len(data), size):
        sock.sendall(data[i:i + size])
        time.sleep(0.002)


def read_response(sock: socket.socket, max_bytes: int = 65536) -> bytes:
    """按 Content-Length 精确读取一个完整 HTTP 响应；不依赖连接关闭。

    若对端在任何字节到达前就关闭（极端 RST），返回空串由调用方判定。
    """
    sock.settimeout(5)
    buf = b""
    # 阶段 1：读到完整头部
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            return buf
        buf += chunk
        if len(buf) > max_bytes:
            return buf
    head, rest = buf.split(b"\r\n\r\n", 1)
    cl = 0
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            cl = int(line.split(b":", 1)[1].strip())
    # 阶段 2：按 CL 补齐正文（可能已随头部一起到达）
    while len(rest) < cl:
        chunk = sock.recv(min(4096, cl - len(rest)))
        if not chunk:
            break
        rest += chunk
    return head + b"\r\n\r\n" + rest[:cl]


def status_of(raw: bytes) -> int | None:
    if not raw:
        return None
    try:
        # 形如 "HTTP/1.1 202 "（h11 原因短语可能为空，结尾带空格）
        parts = raw.split(b"\r\n", 1)[0].split(b" ")
        return int(parts[1])
    except (IndexError, ValueError):
        return None


def expect_closed(sock: socket.socket) -> bool:
    """确认对端已关闭：读到 EOF 或收到 RST；超时未关才视为失败。"""
    sock.settimeout(3)
    try:
        data = sock.recv(4096)
        # 若错误响应之后仍有残余字节，继续读到 EOF 为止。
        while data:
            data = sock.recv(4096)
        return True
    except socket.timeout:
        return False
    except OSError:
        return True   # RST 同样证明连接已被销毁
    finally:
        try:
            sock.close()
        except OSError:
            pass


def http_get(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=5) as resp:
        return json.loads(resp.read().decode())


def http_delete(url: str) -> dict:
    req = urllib.request.Request(url, method="DELETE")
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read().decode())


def upstream_snapshot(limit: int = 500) -> list[dict]:
    return http_get(f"{UPSTREAM_URL}/events?limit={limit}")["items"]


def events_seen(snapshot: list[dict]) -> tuple[int, int]:
    """返回 (POST /events 条数, 非 /events 路径条数)，后者是走私成功的铁证。"""
    n_events = sum(1 for it in snapshot if it["path"] == "/events"
                   and it["method"] == "POST")
    n_other = sum(1 for it in snapshot if it["path"] != "/events")
    return n_events, n_other


# --------------------------------------------------------------------------- #
# 演示场景
# --------------------------------------------------------------------------- #


def case_splintered(report: Report) -> None:
    print("\n[1] 分片发送的合法请求（每 3 字节一个 TCP 段）")
    body = json.dumps({"event": "splintered", "ok": True}).encode()
    req = (
        b"POST /events HTTP/1.1\r\n"
        b"Host: probe.local\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    )
    before, _ = events_seen(upstream_snapshot())
    s = connect()
    send_splintered(s, req, size=3)
    raw = read_response(s)
    after, other = events_seen(upstream_snapshot())
    ok = status_of(raw) == 202 and after == before + 1
    report.add("分片合法请求被正常转发", ok,
               f"status={status_of(raw)}, 上游 /events 新增 {after - before} 条")
    s.close()


def case_pipeline(report: Report) -> None:
    print("\n[2] 同连接流水线（一条 TCP 上连续两个合法请求）")
    b1 = json.dumps({"event": "pipeline-1"}).encode()
    b2 = json.dumps({"event": "pipeline-2"}).encode()
    req = (
        b"POST /events HTTP/1.1\r\nHost: p\r\nContent-Length: "
        + str(len(b1)).encode() + b"\r\n\r\n" + b1
        + b"POST /events HTTP/1.1\r\nHost: p\r\nContent-Length: "
        + str(len(b2)).encode() + b"\r\n\r\n" + b2
    )
    before, _ = events_seen(upstream_snapshot())
    s = connect()
    s.sendall(req)
    raw1 = read_response(s)
    raw2 = read_response(s)
    raw = raw1 + raw2
    after, _ = events_seen(upstream_snapshot())
    # h11 不生成原因短语，状态行为 "HTTP/1.1 202 "，因此按状态码计数。
    count = sum(1 for raw in (raw1, raw2) if status_of(raw) == 202)
    ok = count == 2 and after == before + 2
    report.add("流水线两请求均独立处理", ok,
               f"202 响应数={count}, 上游 /events 新增 {after - before} 条")
    s.close()


def case_chunked(report: Report) -> None:
    print("\n[3] chunked 请求（代理应重建单一 Content-Length 再转发）")
    body = json.dumps({"event": "chunked-body", "n": 42}).encode()
    chunk = (
        b"POST /events HTTP/1.1\r\n"
        b"Host: p\r\nTransfer-Encoding: chunked\r\n\r\n"
        + hex(len(body))[2:].encode() + b"\r\n" + body + b"\r\n0\r\n\r\n"
    )
    before_items = upstream_snapshot()
    before_seqs = {it["seq"] for it in before_items}
    s = connect()
    # 再叠加分片，验证“分块 + TCP 分片”组合。
    send_splintered(s, chunk, size=5)
    raw = read_response(s)
    after_items = upstream_snapshot()
    # 按正文精确取回本请求对应的上游记录，避免被演示自身的 GET 查询干扰。
    new_records = [it for it in after_items if it["seq"] not in before_seqs]
    last = next((it for it in new_records
                 if it["body_text"] == body.decode()), None)
    if last is None:
        report.add("chunked 被重建为单一 Content-Length", False,
                   f"上游未找到本请求，新增记录={len(new_records)} 条")
        s.close()
        return
    cl = last["headers"].get("content-length")
    has_te = "transfer-encoding" in last["headers"]
    ok = (status_of(raw) == 202 and cl == str(len(body)) and not has_te
          and last["body_bytes"] == len(body))
    report.add("chunked 被重建为单一 Content-Length", ok,
               f"上游收到 Content-Length={cl!r}, 残留 TE={has_te}")
    s.close()


SMUGGLE_CASES = [
    (
        "重复 Content-Length",
        b"POST /events HTTP/1.1\r\nHost: p\r\n"
        b"Content-Length: 4\r\nContent-Length: 9\r\n\r\nGOOD\r\nBAD-BODY",
    ),
    (
        "单头逗号分隔双 CL",
        b"POST /events HTTP/1.1\r\nHost: p\r\n"
        b"Content-Length: 4, 9\r\n\r\nGOOD\r\nBAD",
    ),
    (
        "TE 与 CL 并存（TE.CL）",
        b"POST /events HTTP/1.1\r\nHost: p\r\n"
        b"Content-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"0\r\n\r\nSMUGGLED",
    ),
    (
        "非法分块大小",
        b"POST /events HTTP/1.1\r\nHost: p\r\n"
        b"Transfer-Encoding: chunked\r\n\r\nZZZ\r\nxxxx",
    ),
    (
        "正文超过 64KiB",
        b"POST /events HTTP/1.1\r\nHost: p\r\n"
        b"Content-Length: 65537\r\n\r\n" + b"A" * (64 * 1024 + 1),
    ),
    (
        "CL.TE 经典走私（夹带后台请求）",
        (
            b"POST /events HTTP/1.1\r\nHost: p\r\n"
            b"Content-Length: 42\r\n\r\n"
            b"0\r\n\r\n"
            b"POST /admin HTTP/1.1\r\nHost: p\r\n"
            b"Content-Length: 0\r\n\r\n"
        ),
    ),
]


def case_smuggling(report: Report) -> None:
    print("\n[4] 请求走私 / 畸形分帧攻击（应全部拒绝并断连，且不到达上游）")
    for name, payload in SMUGGLE_CASES:
        before_events, before_other = events_seen(upstream_snapshot())
        s = connect()
        try:
            s.sendall(payload)
            raw = read_response(s)
            status = status_of(raw)
            closed = expect_closed(s)
        except OSError:
            raw, status, closed = b"", None, True
        after_events, after_other = events_seen(upstream_snapshot())
        delta_events = after_events - before_events
        delta_other = after_other - before_other
        ok = (status in (400, 413) or status is None) and closed \
            and delta_events == 0 and delta_other == 0
        report.add(f"拦截：{name}", ok,
                   f"status={status}, 连接关闭={closed}, "
                   f"上游新增事件={delta_events}, 走私到其他路径={delta_other}")


def case_timeout(report: Report) -> None:
    print("\n[5] 延迟响应：上游 sleep 2.5s，代理 2s 总限时回 504 并销毁连接")
    body = json.dumps({"event": "slow"}).encode()
    req = (
        b"POST /events HTTP/1.1\r\nHost: p\r\n"
        b"X-Demo-Delay: 2.5\r\nContent-Length: "
        + str(len(body)).encode() + b"\r\n\r\n" + body
    )
    s = connect()
    t0 = time.monotonic()
    s.sendall(req)
    raw = read_response(s)
    elapsed = time.monotonic() - t0
    closed = expect_closed(s)
    # 代理侧预算固定 2.00s；客户端计时还包含建连与 FIN 读取，故窗口放宽。
    ok = status_of(raw) == 504 and 1.8 <= elapsed <= 2.8 and closed
    report.add("2 秒超时回 504 且关闭连接", ok,
               f"status={status_of(raw)}, 耗时={elapsed:.2f}s（代理预算 2.00s）, 关闭={closed}")

    # 迟到响应不得交给下一调用者：新建连接做一笔正常请求，必须干净成功。
    # 注意：被超时的 slow 请求可能在 2.5s 后仍到达上游，因此按 body 精确比对，
    # 只认 after-timeout 这条，不认迟到的 slow 记录。
    before_items = upstream_snapshot()
    body2 = json.dumps({"event": "after-timeout"}).encode()
    req2 = (
        b"POST /events HTTP/1.1\r\nHost: p\r\nContent-Length: "
        + str(len(body2)).encode() + b"\r\n\r\n" + body2
    )
    s2 = connect()
    s2.sendall(req2)
    raw2 = read_response(s2)
    after_items = upstream_snapshot()
    before_seqs = {it["seq"] for it in before_items}
    new_items = [it for it in after_items if it["seq"] not in before_seqs]
    clean = any(it["body_text"] == body2.decode() and
                it["headers"].get("content-length") == str(len(body2))
                for it in new_items)
    ok2 = status_of(raw2) == 202 and clean
    report.add("超时后新连接请求不受迟到响应污染", ok2,
               f"status={status_of(raw2)}, 干净新请求到达={clean}, "
               f"期间新增记录={len(new_items)} 条（迟到 slow 不计）")
    s2.close()


def case_pool(report: Report) -> None:
    print("\n[6] 上游连接池容量 2：3 个并发 0.8s 延迟请求（应呈现两车道）")
    body = json.dumps({"event": "pool"}).encode()
    req = (
        b"POST /events HTTP/1.1\r\nHost: p\r\nX-Demo-Delay: 0.8\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    )

    def one_request() -> int | None:
        sock = connect()
        try:
            sock.sendall(req)
            raw = read_response(sock)
            return status_of(raw)
        finally:
            sock.close()

    t0 = time.monotonic()
    # 线程仅用于并发触发 socket，代理本身是单进程 asyncio。
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool_exec:
        statuses = list(pool_exec.map(lambda _: one_request(), range(3)))
    elapsed = time.monotonic() - t0
    # 两车道：前两笔 ~0.8s 完成，第三笔排队后 ~1.6s 完成；
    # 线程调度与本机抖动下放宽到 2.4s，但绝不可能是 3 条并行（那将 ~0.8s）。
    ok = statuses == [202, 202, 202] and 1.4 <= elapsed <= 2.4
    report.add("池容量=2，第三笔排队而非开第三条连接", ok,
               f"statuses={statuses}, 总耗时={elapsed:.2f}s（两车道预期约 1.6s）")


def case_routing(report: Report) -> None:
    print("\n[7] 路由白名单：GET / 与 POST /admin 必须被拒绝")
    before_events, before_other = events_seen(upstream_snapshot())
    for raw_req, name in [
        (b"GET / HTTP/1.1\r\nHost: p\r\n\r\n", "GET /"),
        (b"POST /admin HTTP/1.1\r\nHost: p\r\nContent-Length: 0\r\n\r\n",
         "POST /admin"),
    ]:
        s = connect()
        s.sendall(raw_req)
        raw = read_response(s)
        closed = expect_closed(s)
        ok = status_of(raw) in (404, 405) and closed
        report.add(f"拒绝非白名单请求：{name}", ok,
                   f"status={status_of(raw)}, 关闭={closed}")
    after_events, after_other = events_seen(upstream_snapshot())
    report.add("被拒绝请求未到达上游",
               after_events == before_events and after_other == before_other,
               f"新增事件={after_events - before_events}, "
               f"新增其他路径={after_other - before_other}")


def show_upstream_evidence() -> None:
    print("\n[证据] 上游实际收到的请求（最新 8 条）")
    data = http_get(f"{UPSTREAM_URL}/events?limit=8")
    for item in data["items"]:
        cl = item["headers"].get("content-length", "-")
        te = item["headers"].get("transfer-encoding", "-")
        print(f"  #{item['seq']:<3} {item['method']} {item['path']} "
              f"tcp={item['client_tcp']} CL={cl} TE={te} "
              f"body={item['body_bytes']}B  {item['body_text'][:48]!r}")
    print(f"  上游累计收到 {data['count']} 条（走私尝试条数应为 0 条 /events 之外记录）")


def main() -> int:
    print(f"目标代理 {PROXY_HOST}:{PROXY_PORT}，上游 {UPSTREAM_URL}")
    try:
        cleared = http_delete(f"{UPSTREAM_URL}/events")
        print(f"已清空上游历史记录：{cleared}")
    except urllib.error.URLError as exc:
        print(f"无法连接上游 {UPSTREAM_URL}：{exc}")
        return 2

    report = Report()
    for fn in (case_splintered, case_pipeline, case_chunked, case_smuggling,
               case_timeout, case_pool, case_routing):
        try:
            fn(report)
        except OSError as exc:
            report.add(fn.__name__, False, f"网络异常：{exc}")
    show_upstream_evidence()
    return report.summary()


if __name__ == "__main__":
    raise SystemExit(main())
