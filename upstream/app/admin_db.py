"""
管理端共享 SQLite 访问（与代理进程同一文件、同一 schema）。

只承担两类永久状态：
  * revoked_probes：永久撤销表（只增不删，重启生效）；
  * consumed_nonces：代理写入的 nonce 消费记录，本模块只读，用于审计查询。

写操作同样是短事务，COMMIT 后立即释放锁；代理在 WAL 模式下不会被
管理端的写操作阻塞读取。
"""

from __future__ import annotations

import os
import sqlite3
import time

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


def open_admin_db(db_path: str) -> sqlite3.Connection:
    parent = os.path.dirname(os.path.abspath(db_path))
    os.makedirs(parent, exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=5.0, isolation_level=None)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.executescript(_SCHEMA)
    return conn


def revoke_probe(conn: sqlite3.Connection, probe_id: str) -> bool:
    """永久撤销。返回 True 表示本次新撤销，False 表示此前已撤销（幂等）。"""
    before = conn.execute(
        "SELECT 1 FROM revoked_probes WHERE probe_id = ?", (probe_id,)
    ).fetchone()
    if before is not None:
        return False
    conn.execute(
        "INSERT INTO revoked_probes (probe_id, revoked_at) VALUES (?, ?)",
        (probe_id, time.time()),
    )
    return True


def is_revoked(conn: sqlite3.Connection, probe_id: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM revoked_probes WHERE probe_id = ?", (probe_id,)
    ).fetchone() is not None


def list_revoked(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute(
        "SELECT probe_id, revoked_at FROM revoked_probes ORDER BY revoked_at"
    ).fetchall()
    return [{"probe_id": pid, "revoked_at": ts} for pid, ts in rows]


def nonce_status(conn: sqlite3.Connection, probe_id: str, nonce: str) -> dict:
    row = conn.execute(
        "SELECT ts, consumed_at FROM consumed_nonces "
        "WHERE probe_id = ? AND nonce = ?",
        (probe_id, nonce),
    ).fetchone()
    if row is None:
        return {"probe_id": probe_id, "nonce": nonce, "consumed": False}
    return {
        "probe_id": probe_id,
        "nonce": nonce,
        "consumed": True,
        "timestamp": row[0],
        "consumed_at": row[1],
    }
