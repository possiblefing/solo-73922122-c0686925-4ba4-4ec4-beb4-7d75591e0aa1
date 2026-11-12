"""
探针凭据与平台配置（启动时固定）——上游管理端副本。

与 proxy/app/config.py 保持同一套环境变量约定，compose 中两服务注入
相同的 PROBE_KEYS / ADMIN_KEY，因此管理端看到的探针清单与代理一致。
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass


@dataclass(frozen=True)
class PlatformConfig:
    probes: dict[str, bytes]
    admin_key: str


class ConfigError(RuntimeError):
    """启动配置非法。"""


def _parse_probe_keys_env(raw: str) -> dict[str, bytes]:
    probes: dict[str, bytes] = {}
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        if "=" not in item:
            raise ConfigError(
                f"PROBE_KEYS 条目缺少 '='：{item!r}，格式应为 id=secret")
        pid, secret = item.split("=", 1)
        pid = pid.strip()
        if not pid or not secret:
            raise ConfigError(f"PROBE_KEYS 存在空 ID 或空密钥：{item!r}")
        if pid in probes:
            raise ConfigError(f"PROBE_KEYS 中探针 ID 重复：{pid}")
        probes[pid] = secret.encode("utf-8")
    return probes


def load_config() -> PlatformConfig:
    path = os.environ.get("PROBE_CONFIG_FILE")
    if path:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                doc = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            raise ConfigError(f"无法读取探针配置文件 {path}: {exc}") from exc
        if not isinstance(doc, dict) or not isinstance(doc.get("probes"), dict):
            raise ConfigError("配置文件必须包含对象类型的 probes 字段")
        probes: dict[str, bytes] = {}
        for pid, secret in doc["probes"].items():
            if not isinstance(pid, str) or not pid:
                raise ConfigError("探针 ID 必须是非空字符串")
            if not isinstance(secret, str) or not secret:
                raise ConfigError(f"探针 {pid} 的密钥必须是非空字符串")
            if pid in probes:
                raise ConfigError(f"配置文件中探针 ID 重复：{pid}")
            probes[pid] = secret.encode("utf-8")
        admin_key = str(doc.get("admin_key", "")).strip()
    else:
        raw = os.environ.get("PROBE_KEYS", "")
        probes = _parse_probe_keys_env(raw)
        admin_key = os.environ.get("ADMIN_KEY", "").strip()

    if not probes:
        raise ConfigError(
            "未配置任何探针凭据：请设置 PROBE_CONFIG_FILE 或 PROBE_KEYS")
    return PlatformConfig(probes=probes, admin_key=admin_key)
