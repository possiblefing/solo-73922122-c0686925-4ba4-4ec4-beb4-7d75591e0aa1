"""
HMAC-SHA256 探针认证（签名、解析、校验，纯函数无 IO）。

请求头（均为 ASCII）：
  X-Probe-Id    探针 ID，须存在于启动配置
  X-Timestamp   Unix 秒时间戳（十进制整数）
  X-Nonce       32 位小写十六进制随机串
  X-Signature   64 位小写十六进制 HMAC-SHA256

签名原文（四行，以 LF 连接，无尾随换行）：
    <ID> \\n <timestamp> \\n <nonce> \\n <sha256(去除 HTTP 分帧后的正文) 的小写 hex>

HMAC 密钥取启动配置中该 ID 对应的密钥原文 UTF-8 字节。
所有比较使用 hmac.compare_digest，防止计时侧信道。
"""

from __future__ import annotations

import hashlib
import hmac
import re
import time
from dataclasses import dataclass

from .auth_store import SKEW_SECONDS

HEADER_PROBE_ID = b"x-probe-id"
HEADER_TIMESTAMP = b"x-timestamp"
HEADER_NONCE = b"x-nonce"
HEADER_SIGNATURE = b"x-signature"

# 转发到上游前必须剥离的认证头：上游只接收事件，不接触凭据材料。
AUTH_HEADERS = frozenset(
    {HEADER_PROBE_ID, HEADER_TIMESTAMP, HEADER_NONCE, HEADER_SIGNATURE}
)

_NONCE_RE = re.compile(r"^[0-9a-f]{32}$")
_SIGNATURE_RE = re.compile(r"^[0-9a-f]{64}$")
_PROBE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}$")


class AuthReject(Exception):
    """认证失败。status 为响应码（401/403/409），reason 用于日志与响应体。"""

    def __init__(self, status: int, reason: str):
        super().__init__(reason)
        self.status = status
        self.reason = reason


@dataclass(frozen=True)
class AuthContext:
    probe_id: str
    timestamp: int
    nonce: str


def build_signing_string(probe_id: str, timestamp: int | str,
                         nonce: str, body: bytes) -> bytes:
    """构造签名原文：ID LF ts LF nonce LF body 的 SHA-256 小写 hex。"""
    digest = hashlib.sha256(body).hexdigest()
    return f"{probe_id}\n{timestamp}\n{nonce}\n{digest}".encode("utf-8")


def sign(probe_id: str, secret: bytes, timestamp: int | str,
         nonce: str, body: bytes) -> str:
    """探针端签名工具（演示脚本与本服务自测共用同一实现语义）。"""
    message = build_signing_string(probe_id, timestamp, nonce, body)
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def _first_header(headers: list[tuple[bytes, bytes]],
                  name: bytes) -> bytes | None:
    """取第一个同名头；重复认证头按缺失/畸形处理（拒绝），避免头注入歧义。"""
    matches = [v for k, v in headers if k.lower() == name]
    if len(matches) != 1:
        return None
    return matches[0]


def parse_auth_headers(headers: list[tuple[bytes, bytes]]) -> tuple[str, int, str, str]:
    """解析并做格式校验；任何缺失/重复/非法格式一律 401，且不消费 nonce。"""
    raw_id = _first_header(headers, HEADER_PROBE_ID)
    raw_ts = _first_header(headers, HEADER_TIMESTAMP)
    raw_nonce = _first_header(headers, HEADER_NONCE)
    raw_sig = _first_header(headers, HEADER_SIGNATURE)
    if raw_id is None or raw_ts is None or raw_nonce is None or raw_sig is None:
        raise AuthReject(401, "missing or duplicated auth headers")

    try:
        probe_id = raw_id.decode("ascii")
        nonce = raw_nonce.decode("ascii")
        sig = raw_sig.decode("ascii")
        ts_text = raw_ts.decode("ascii")
    except UnicodeDecodeError as exc:
        raise AuthReject(401, "auth headers must be ASCII") from exc

    if not _PROBE_ID_RE.match(probe_id):
        raise AuthReject(401, "malformed probe id")
    if not re.fullmatch(r"-?\d{1,11}", ts_text):
        raise AuthReject(401, "malformed timestamp")
    try:
        timestamp = int(ts_text)
    except ValueError as exc:
        raise AuthReject(401, "malformed timestamp") from exc
    if not _NONCE_RE.match(nonce):
        raise AuthReject(401, "nonce must be 32 lowercase hex chars")
    if not _SIGNATURE_RE.match(sig):
        raise AuthReject(401, "signature must be 64 lowercase hex chars")
    return probe_id, timestamp, nonce, sig


def verify_request(
    headers: list[tuple[bytes, bytes]],
    body: bytes,
    probes: dict[str, bytes],
    now: float | None = None,
) -> AuthContext:
    """完整的无状态认证（不含 nonce 持久化与撤销库检查）。

    顺序：头格式 -> 探针存在 -> 时间窗口 -> 签名。
    任何失败都不触碰 nonce 表，因此天然满足“认证拒绝不消费 nonce”。
    """
    probe_id, timestamp, nonce, sig = parse_auth_headers(headers)

    secret = probes.get(probe_id)
    if secret is None:
        # 未知 ID 与签名错误统一 401，不向攻击者区分“ID 是否存在”。
        raise AuthReject(401, "unknown probe or bad credentials")

    current = time.time() if now is None else now
    if abs(current - timestamp) > SKEW_SECONDS:
        raise AuthReject(401,
                         f"timestamp skew exceeds {SKEW_SECONDS}s")

    expected = sign(probe_id, secret, timestamp, nonce, body)
    if not hmac.compare_digest(expected, sig):
        raise AuthReject(401, "signature mismatch")

    return AuthContext(probe_id=probe_id, timestamp=timestamp, nonce=nonce)
