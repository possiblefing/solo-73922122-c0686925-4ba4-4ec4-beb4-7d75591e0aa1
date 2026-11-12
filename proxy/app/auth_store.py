"""
认证状态持久化（SQLite）：探针撤销表 + nonce 消费表。

设计约束（对应平台安全需求）：
  * nonce 消费必须持久化：进程重启后同一 nonce 依旧无法再次写出；
  * “同探针同 nonce 并发仅一次可写出”：由 nonces 表的
    UNIQUE(probe_id, nonce) 约束 + BEGIN IMMEDIATE 单事务原子性保证；
  * 认证拒绝不消费 nonce：所有失败路径在 INSERT 之前返回；
  * 网络等待不持 SQLite 写锁：consume 成功后立即 COMMIT 并释放事务锁，
    之后才向上游发送请求（见 main.py 的调用顺序）；
  * 撤销是永久的：revoked 表只增不删，重启后依然生效。

实现说明：
  单进程 asyncio 代理内所有协程运行在同一线程，sqlite3 调用均为单语句级
  短事务（毫秒级、无网络 IO），直接同步执行即可；threading.RLock 串行化
  “撤销检查 + nonce 消费”临界区，跨进程（管理端/多实例）则由 SQLite
  的 UNIQUE 约束与 WAL 并发模型兜底。事务在进入任何网络等待前 COMMIT，
  因此网络等待期间不持有任何 SQLite 写锁。
"""

from __future__ import annotations

import logging
import os
import sqlite3
import threading
import time

log = logging.getLogger("smuggling-guard-proxy.auth")

# 时间戳有效期：|now - ts| <= 30 秒
SKEW_SECONDS = 30
# nonce 记录保留期：远大于时间戳窗口即可，后台任务周期性清理过期行。
DEFAULT_RETENTION_SECONDS = 3600

_SCHEMA = """
CREATE TABLE IF NOT EXISTS revoked_probes (
    probe_id   TEXT PRIMARY KEY,
    revoked_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS consumed_nonces (
    probe_id   TEXT NOT NULL,
    nonce      TEXT NOT NULL,
    ts         INTEGER NOT NULL,
    consumed_at REAL NOT NULL,
    PRIMARY KEY (probe_id, nonce)
);
"""


class NonceAlreadyConsumed(Exception):
    """同探针同 nonce 已被消费（重放）。调用方回 409，且不再重复写库。"""


class ProbeRevoked(Exception):
    """临界区内发现探针已被永久撤销，调用方回 403。"""


class AuthStore:
    def __init__(
        self,
        db_path: str,
        retention_seconds: int = DEFAULT_RETENTION_SECONDS,
    ) -> None:
        self._db_path = db_path
        self._retention = retention_seconds
        # 本进程临界区锁；SQLite 自身的 UNIQUE 约束再兜底跨进程并发。
        self._lock = threading.RLock()
        self._conn = self._connect()
        self._init_schema()

    # ---- 连接与 schema --------------------------------------------------- #

    def _connect(self) -> sqlite3.Connection:
        parent = os.path.dirname(os.path.abspath(self._db_path))
        os.makedirs(parent, exist_ok=True)
        # 单线程事件循环内使用；不跨线程共享该连接，保持默认 same-thread 保护。
        conn = sqlite3.connect(
            self._db_path,
            timeout=5.0,            # WAL 下写冲突时的 busy 等待
            isolation_level=None,   # 显式事务，避免隐式 BEGIN 长期持锁
        )
        # WAL：允许管理端写撤销的同时代理继续读；NORMAL 同步在 WAL 下安全。
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_schema(self) -> None:
        self._conn.executescript(_SCHEMA)

    def close(self) -> None:
        self._conn.close()

    # ---- 撤销 ------------------------------------------------------------ #

    async def is_revoked(self, probe_id: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM revoked_probes WHERE probe_id = ?",
            (probe_id,),
        ).fetchone()
        return row is not None

    # ---- nonce 消费 ------------------------------------------------------ #

    def _consume_sync(self, probe_id: str, nonce: str, ts: int) -> None:
        """单事务内完成撤销复核 + nonce 持久消费，COMMIT 后立即释放写锁。"""
        with self._lock:
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                revoked = self._conn.execute(
                    "SELECT 1 FROM revoked_probes WHERE probe_id = ?",
                    (probe_id,),
                ).fetchone()
                if revoked is not None:
                    self._conn.execute("ROLLBACK")
                    raise ProbeRevoked(
                        f"probe revoked during consume: {probe_id}")
                self._conn.execute(
                    "INSERT INTO consumed_nonces "
                    "(probe_id, nonce, ts, consumed_at) VALUES (?, ?, ?, ?)",
                    (probe_id, nonce, ts, time.time()),
                )
                self._conn.execute("COMMIT")
            except sqlite3.IntegrityError as exc:
                # UNIQUE(probe_id, nonce) 冲突 = 重放；认证拒绝不重复消费。
                self._rollback()
                raise NonceAlreadyConsumed(str(exc)) from exc
            except sqlite3.Error:
                # 存储故障时宁可不写出（fail-closed），回滚后交给上层回 503。
                self._rollback()
                raise

    def _rollback(self) -> None:
        try:
            self._conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass

    async def consume_nonce(self, probe_id: str, nonce: str, ts: int) -> None:
        """消费成功返回；重放抛 NonceAlreadyConsumed；已撤销抛 ProbeRevoked。

        调用方必须在本方法返回成功之后、且不再访问本连接的情况下，
        才进入上游网络等待，确保网络等待期间不持有 SQLite 写锁。
        """
        self._consume_sync(probe_id, nonce, ts)

    async def nonce_exists(self, probe_id: str, nonce: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM consumed_nonces WHERE probe_id = ? AND nonce = ?",
            (probe_id, nonce),
        ).fetchone()
        return row is not None

    # ---- 维护 ------------------------------------------------------------ #

    async def prune(self) -> int:
        with self._lock:
            cutoff = time.time() - self._retention
            cur = self._conn.execute(
                "DELETE FROM consumed_nonces WHERE consumed_at < ?", (cutoff,))
            return cur.rowcount
