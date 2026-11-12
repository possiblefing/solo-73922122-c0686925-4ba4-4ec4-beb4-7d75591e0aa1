#!/usr/bin/env python3
"""
反走私 + HMAC 探针认证演示客户端（仅标准库，原始字节操作）。

运行：
    python3 demo/demo.py
可选环境变量：
    PROXY_HOST   默认 127.0.0.1
    PROXY_PORT   默认 8080
    UPSTREAM_URL 默认 http://127.0.0.1:8000 （管理 API 与取证查询）
    PROBE_ID     默认 probe-demo-1
    PROBE_SECRET 默认取 config/probes.json 中 probe-demo-1 的密钥
    ADMIN_KEY    默认取 config/probes.json 中的 admin_key

演示内容：
  A. 本地 HMAC 签名：合法签名 202、坏签名/过期时间戳 401、认证拒绝不消费 nonce
  B. 并发重放：8 个同 ID 同 nonce 并发，仅 1 笔 202，其余 409
  C. 排队撤销：两笔慢请求占满容量 2 的连接池，排队中的第三笔在管理端
     永久撤销后被 403，已写出的两笔正常 202
  D. 分帧防护回归：分片 / 流水线 / chunked 重建 / 六类走私畸形 / 路由白名单
  E. 连接池与 2 秒超时回归
最后直接拉取上游“实际收到的请求”清单作为证据。
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import hmac
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

# 与 config/probes.json 的演示固定凭据保持一致；生产环境通过环境变量覆盖。
PROBE_ID = os.environ.get("PROBE_ID", "probe-demo-1")
PROBE_SECRET = os.environ.get(
    "PROBE_SECRET",
    "e0f2be38031fa26a36ddf2d8044cef7e8a4385fd00416e6157ca3dbeba52c07d",
).encode("utf-8")
ADMIN_KEY = os.environ.get(
    "ADMIN_KEY", "c4cd8d7e77a88e9ed7b22d8f14b19587")

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
# HMAC 签名（与代理 proxy/app/hmac_auth.py 的验签逻辑严格对应）
# --------------------------------------------------------------------------- #


def sign_headers(body: bytes, probe_id: str = PROBE_ID,
                 secret: bytes = PROBE_SECRET, ts: int | None = None,
                 nonce: str | None = None) -> tuple[dict[str, str], str]:
    """返回 (认证头字典, nonce)。签名原文四行以 LF 连接。"""
    ts = int(time.time()) if ts is None else ts
    nonce = os.urandom(16).hex() if nonce is None else nonce
    body_digest = hashlib.sha256(body).hexdigest()
    message = f"{probe_id}\n{ts}\n{nonce}\n{body_digest}".encode("utf-8")
    signature = hmac.new(secret, message, hashlib.sha256).hexdigest()
    return {
        "X-Probe-Id": probe_id,
        "X-Timestamp": str(ts),
        "X-Nonce": nonce,
        "X-Signature": signature,
    }, nonce


# --------------------------------------------------------------------------- #
# 原始 socket 工具
# --------------------------------------------------------------------------- #


def connect() -> socket.socket:
    s = socket.create_connection((PROXY_HOST, PROXY_PORT), timeout=5)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return s


def build_raw_request(body: bytes, auth: dict | None,
                      extra: dict | None = None,
                      path: str = "/events", method: str = "POST") -> bytes:
    head = (f"{method} {path} HTTP/1.1\r\nHost: probe.local\r\n"
            f"Content-Length: {len(body)}\r\n")
    for k, v in (auth or {}).items():
        head += f"{k}: {v}\r\n"
    for k, v in (extra or {}).items():
        head += f"{k}: {v}\r\n"
    return head.encode("ascii") + b"\r\n" + body


def send_splintered(sock: socket.socket, data: bytes,
                    size: int = 3) -> None:
    for i in range(0, len(data), size):
        sock.sendall(data[i:i + size])
        time.sleep(0.002)


def read_response(sock: socket.socket, max_bytes: int = 65536) -> bytes:
    sock.settimeout(5)
    buf = b""
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
        parts = raw.split(b"\r\n", 1)[0].split(b" ")
        return int(parts[1])
    except (IndexError, ValueError):
        return None


def expect_closed(sock: socket.socket) -> bool:
    sock.settimeout(3)
    try:
        data = sock.recv(4096)
        while data:
            data = sock.recv(4096)
        return True
    except socket.timeout:
        return False
    except OSError:
        return True
    finally:
        try:
            sock.close()
        except OSError:
            pass


def signed_request(body: bytes, extra: dict | None = None,
                   auth_override: dict | None = None) -> int | None:
    auth = auth_override or sign_headers(body)[0]
    s = connect()
    try:
        s.sendall(build_raw_request(body, auth, extra))
        return status_of(read_response(s))
    except OSError:
        return None
    finally:
        try:
            s.close()
        except OSError:
            pass


def http_json(method: str, url: str, headers: dict | None = None) -> tuple[int, dict]:
    req = urllib.request.Request(url, method=method,
                                 headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode() or "{}")


def upstream_snapshot(limit: int = 500) -> list[dict]:
    return http_json("GET", f"{UPSTREAM_URL}/events?limit={limit}")[1]["items"]


def events_seen(snapshot: list[dict]) -> tuple[int, int]:
    n_events = sum(1 for it in snapshot if it["path"] == "/events"
                   and it["method"] == "POST")
    n_other = sum(1 for it in snapshot if it["path"] != "/events")
    return n_events, n_other


# --------------------------------------------------------------------------- #
# A. 本地 HMAC 签名
# --------------------------------------------------------------------------- #


def case_local_signing(report: Report) -> None:
    print("\n[A] 本地 HMAC-SHA256 签名")
    body = json.dumps({"event": "local-signing"}).encode()

    # A1 合法签名
    status = signed_request(body)
    report.add("合法签名上报 -> 202", status == 202, f"status={status}")

    # A2 坏签名
    bad_auth, _ = sign_headers(body)
    bad_auth["X-Signature"] = "0" * 64
    status = signed_request(body, auth_override=bad_auth)
    report.add("错误签名 -> 401", status == 401, f"status={status}")

    # A3 过期时间戳（120 秒前，超过 ±30s 窗口）
    stale_auth, _ = sign_headers(body, ts=int(time.time()) - 120)
    status = signed_request(body, auth_override=stale_auth)
    report.add("过期时间戳 -> 401", status == 401, f"status={status}")

    # A4 篡改正文后签名失效
    auth4, _ = sign_headers(body)
    s = connect()
    tampered = body + b" "
    s.sendall(build_raw_request(tampered, auth4))
    status = status_of(read_response(s))
    s.close()
    report.add("正文与签名摘要不符 -> 401", status == 401, f"status={status}")

    # A5 认证拒绝不消费 nonce：同一 nonce 先错后对，第二次应成功
    body5 = json.dumps({"event": "nonce-not-burned"}).encode()
    auth5, nonce5 = sign_headers(body5)
    wrong = dict(auth5)
    wrong["X-Signature"] = "f" * 64
    st1 = signed_request(body5, auth_override=wrong)
    good = sign_headers(body5, nonce=nonce5)[0]
    st2 = signed_request(body5, auth_override=good)
    report.add("认证拒绝不消费 nonce（401 后同 nonce 正确签名 202）",
               st1 == 401 and st2 == 202, f"{st1} -> {st2}")


# --------------------------------------------------------------------------- #
# B. 并发重放
# --------------------------------------------------------------------------- #


def case_concurrent_replay(report: Report) -> None:
    print("\n[B] 并发重放防护（同探针同 nonce，仅一次可写出）")
    body = json.dumps({"event": "replay-me"}).encode()
    auth, nonce = sign_headers(body)
    before, _ = events_seen(upstream_snapshot())

    def one_shot(_) -> int | None:
        s = connect()
        try:
            s.sendall(build_raw_request(body, auth))
            return status_of(read_response(s))
        except OSError:
            return None
        finally:
            try:
                s.close()
            except OSError:
                pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        statuses = list(pool.map(one_shot, range(8)))
    n_202 = statuses.count(202)
    n_409 = statuses.count(409)
    report.add("8 并发同 nonce：恰好 1 笔 202，7 笔 409",
               n_202 == 1 and n_409 == 7, f"statuses={statuses}")

    # 串行再重放一次，仍然 409
    again = signed_request(body, auth_override=auth)
    report.add("事后串行重放同 nonce -> 409", again == 409,
               f"status={again}")

    after, other = events_seen(upstream_snapshot())
    report.add("重放流量未额外到达上游",
               after - before == 1 and other == 0,
               f"上游新增 /events={after - before}, 其他路径={other}")

    # 管理端可查到该 nonce 已被持久消费
    code, doc = http_json(
        "GET", f"{UPSTREAM_URL}/admin/nonces/{PROBE_ID}/{nonce}",
        headers={"X-Admin-Key": ADMIN_KEY})
    report.add("管理 API 可查 nonce 已持久消费",
               code == 200 and doc.get("consumed") is True, str(doc))


# --------------------------------------------------------------------------- #
# C. 排队撤销
# --------------------------------------------------------------------------- #


def case_queued_revocation(report: Report) -> None:
    print("\n[C] 排队中永久撤销（已写出可完成，未写出一律拒绝）")
    # 用独立探针演示，撤销它不影响其他场景；先确认/执行撤销幂等接口。
    probe = "probe-demo-2"
    secret = os.environ.get(
        "PROBE2_SECRET",
        "74a09645004c61099a4862606ba07d744aeb319e0029f713bb6a0b0d11fe11b5",
    ).encode()
    body = json.dumps({"event": "queued-revoke"}).encode()
    slow = {"X-Demo-Delay": "1"}  # 上游处理 1s，足以占满容量 2 的池

    def slow_shot(i: int) -> int | None:
        auth = sign_headers(body, probe_id=probe, secret=secret)[0]
        s = connect()
        try:
            if i == 2:
                time.sleep(0.3)  # 第三笔稍后发出，确保进入排队
            s.sendall(build_raw_request(body, auth, slow))
            return status_of(read_response(s, timeout=8))
        except OSError:
            return None
        finally:
            try:
                s.close()
            except OSError:
                pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(slow_shot, i) for i in range(3)]
        time.sleep(0.5)  # 前两笔已占满池并写往上游，第三笔排队中
        # 凭管理密钥永久撤销（幂等）
        code, doc = http_json(
            "POST",
            f"{UPSTREAM_URL}/admin/probes/{probe}/revoke",
            headers={"X-Admin-Key": ADMIN_KEY})
        revoke_ok = code == 200 and doc.get("revoked") is True
        statuses = [f.result() for f in futures]

    report.add("管理 API 永久撤销成功", revoke_ok, f"http={code} {doc}")
    report.add("已写出的两笔完成 202",
               statuses[:2].count(202) == 2, f"statuses={statuses}")
    report.add("排队中未写出的一笔被 403",
               statuses[2] == 403, f"statuses={statuses}")

    # 撤销后新请求（全新 nonce）同样 403
    new_auth = sign_headers(body, probe_id=probe, secret=secret)[0]
    st = signed_request(body, auth_override=new_auth)
    report.add("撤销后新上报 -> 403", st == 403, f"status={st}")

    # 管理 API 鉴权：错误密钥 401
    code, _ = http_json(
        "GET", f"{UPSTREAM_URL}/admin/probes",
        headers={"X-Admin-Key": "wrong-key"})
    report.add("管理 API 错误密钥 -> 401", code == 401, f"http={code}")


# --------------------------------------------------------------------------- #
# D. 分帧防护回归（畸形帧在认证之前就被拒，合法帧带签名）
# --------------------------------------------------------------------------- #


def case_framing_regression(report: Report) -> None:
    print("\n[D] 分帧防护回归（分片 / 流水线 / chunked / 走私 / 路由）")

    # D1 分片 + 合法签名
    body = json.dumps({"event": "splintered-signed"}).encode()
    req = build_raw_request(body, sign_headers(body)[0])
    before, _ = events_seen(upstream_snapshot())
    s = connect()
    send_splintered(s, req, size=3)
    status = status_of(read_response(s))
    s.close()
    after, _ = events_seen(upstream_snapshot())
    report.add("分片合法签名请求 -> 202",
               status == 202 and after == before + 1,
               f"status={status}, 上游新增 {after - before}")

    # D2 同连接流水线两个签名请求
    b1 = json.dumps({"event": "pipe-1"}).encode()
    b2 = json.dumps({"event": "pipe-2"}).encode()
    req = (build_raw_request(b1, sign_headers(b1)[0])
           + build_raw_request(b2, sign_headers(b2)[0]))
    s = connect()
    s.sendall(req)
    r1 = status_of(read_response(s))
    r2 = status_of(read_response(s))
    s.close()
    report.add("流水线两签名请求均 202",
               r1 == 202 and r2 == 202, f"{r1}/{r2}")

    # D3 chunked 重建：h11 校验分帧后剥离 TE，认证按去帧正文验签
    body3 = json.dumps({"event": "chunked-signed"}).encode()
    auth3, _ = sign_headers(body3)
    chunk = (
        b"POST /events HTTP/1.1\r\nHost: p\r\nTransfer-Encoding: chunked\r\n"
        + b"".join(f"{k}: {v}\r\n".format(k=k, v=v).encode()
                   for k, v in auth3.items())
        + b"\r\n" + hex(len(body3))[2:].encode() + b"\r\n" + body3
        + b"\r\n0\r\n\r\n"
    )
    before_items = upstream_snapshot()
    before_seqs = {it["seq"] for it in before_items}
    s = connect()
    send_splintered(s, chunk, size=5)
    status = status_of(read_response(s))
    s.close()
    new_records = [it for it in upstream_snapshot()
                   if it["seq"] not in before_seqs]
    rec = next((it for it in new_records
                if it["body_text"] == body3.decode()), None)
    ok = (status == 202 and rec is not None
          and rec["headers"].get("content-length") == str(len(body3))
          and "transfer-encoding" not in rec["headers"])
    report.add("chunked 签名请求被重建为单一 Content-Length", ok,
               f"status={status}, 记录={rec is not None}")

    # D4 走私/畸形：分帧层直接拒绝，无需有效签名，且不到达上游
    smuggle_cases = [
        ("重复 Content-Length",
         b"POST /events HTTP/1.1\r\nHost: p\r\n"
         b"Content-Length: 4\r\nContent-Length: 9\r\n\r\nGOOD\r\nBAD-BODY"),
        ("TE 与 CL 并存",
         b"POST /events HTTP/1.1\r\nHost: p\r\n"
         b"Content-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n"
         b"0\r\n\r\nSMUGGLED"),
        ("非法分块大小",
         b"POST /events HTTP/1.1\r\nHost: p\r\n"
         b"Transfer-Encoding: chunked\r\n\r\nZZZ\r\nxxxx"),
        ("正文超过 64KiB",
         b"POST /events HTTP/1.1\r\nHost: p\r\n"
         b"Content-Length: 65537\r\n\r\n" + b"A" * (64 * 1024 + 1)),
        ("CL.TE 夹带 /admin",
         b"POST /events HTTP/1.1\r\nHost: p\r\nContent-Length: 42\r\n\r\n"
         b"0\r\n\r\nPOST /admin HTTP/1.1\r\nHost: p\r\n"
         b"Content-Length: 0\r\n\r\n"),
    ]
    for name, payload in smuggle_cases:
        before_e, before_o = events_seen(upstream_snapshot())
        s = connect()
        try:
            s.sendall(payload)
            st = status_of(read_response(s))
            closed = expect_closed(s)
        except OSError:
            st, closed = None, True
        after_e, after_o = events_seen(upstream_snapshot())
        ok = (st in (400, 413) or st is None) and closed \
            and after_e == before_e and after_o == before_o
        report.add(f"分帧拦截：{name}", ok,
                   f"status={st}, 关闭={closed}, 上游新增=0")

    # D5 路由白名单
    s = connect()
    s.sendall(b"GET / HTTP/1.1\r\nHost: p\r\n\r\n")
    st = status_of(read_response(s))
    closed = expect_closed(s)
    report.add("非白名单 GET / 被拒并断连",
               st in (404, 405) and closed, f"status={st}")


# --------------------------------------------------------------------------- #
# E. 连接池容量与 2 秒超时（签名请求）
# --------------------------------------------------------------------------- #


def case_pool_and_timeout(report: Report) -> None:
    print("\n[E] 连接池容量 2 与发送起 2 秒期限")
    body = json.dumps({"event": "pool"}).encode()
    req_auth = sign_headers(body)[0]

    def one() -> int | None:
        s = connect()
        try:
            s.sendall(build_raw_request(body, req_auth,
                                        {"X-Demo-Delay": "0.8"}))
            return status_of(read_response(s, timeout=8))
        except OSError:
            return None
        finally:
            try:
                s.close()
            except OSError:
                pass

    t0 = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        statuses = list(pool.map(lambda _: one(), range(3)))
    elapsed = time.monotonic() - t0
    report.add("容量 2：3 笔 0.8s 并发呈两车道（约 1.6s）",
               statuses == [202, 202, 202] and 1.3 <= elapsed <= 2.6,
               f"statuses={statuses}, 耗时={elapsed:.2f}s")

    slow_body = json.dumps({"event": "slow"}).encode()
    s = connect()
    t0 = time.monotonic()
    s.sendall(build_raw_request(
        slow_body, sign_headers(slow_body)[0], {"X-Demo-Delay": "2.5"}))
    st = status_of(read_response(s, timeout=6))
    elapsed = time.monotonic() - t0
    closed = expect_closed(s)
    report.add("上游 2.5s 慢响应：代理 2s 回 504 并断连",
               st == 504 and 1.8 <= elapsed <= 2.8 and closed,
               f"status={st}, 耗时={elapsed:.2f}s")


def show_evidence() -> None:
    print("\n[证据] 上游实际收到的请求（最新 8 条；认证头应已被代理剥离）")
    data = http_json("GET", f"{UPSTREAM_URL}/events?limit=8")[1]
    for item in data["items"]:
        leak = [k for k in item["headers"]
                if k.startswith("x-probe") or k in ("x-signature",
                                                    "x-nonce", "x-timestamp")]
        print(f"  #{item['seq']:<3} {item['method']} {item['path']} "
              f"CL={item['headers'].get('content-length', '-')} "
              f"body={item['body_bytes']}B 认证头泄漏={leak or '无'} "
              f"{item['body_text'][:40]!r}")


def main() -> int:
    print(f"目标代理 {PROXY_HOST}:{PROXY_PORT}，上游/管理端 {UPSTREAM_URL}")
    try:
        print("清空上游历史记录：", http_json("DELETE", f"{UPSTREAM_URL}/events"))
        # 演示自恢复：若 probe-demo-2 上次已被撤销，给出提示（撤销是永久的）。
        code, doc = http_json(
            "GET", f"{UPSTREAM_URL}/admin/probes",
            headers={"X-Admin-Key": ADMIN_KEY})
        if code != 200:
            print(f"管理 API 不可用（http={code}），撤销相关演示可能失败：{doc}")
        else:
            print("探针当前状态：",
                  [(p["probe_id"], "已撤销" if p["revoked"] else "正常")
                   for p in doc["probes"]])
    except urllib.error.URLError as exc:
        print(f"无法连接上游 {UPSTREAM_URL}：{exc}")
        return 2

    report = Report()
    for fn in (case_local_signing, case_concurrent_replay,
               case_queued_revocation, case_framing_regression,
               case_pool_and_timeout):
        try:
            fn(report)
        except OSError as exc:
            report.add(fn.__name__, False, f"网络异常：{exc}")
    show_evidence()
    note = ("\n注意：probe-demo-2 已被永久撤销（演示预期）。重跑本脚本前如需恢复，"
            "请执行 docker compose down -v 并重新 up（清除共享 SQLite 卷）。")
    print(note)
    return report.summary()


if __name__ == "__main__":
    raise SystemExit(main())
