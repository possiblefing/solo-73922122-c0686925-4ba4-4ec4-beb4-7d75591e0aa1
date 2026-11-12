"""
探针凭据与平台配置（启动时固定）。

探针 ID -> 密钥的映射只在进程启动时加载一次，运行期不可增改；
撤销状态与 nonce 消费记录走持久化存储（见 auth_store.py），不放在本模块。

配置来源（二选一，文件优先）：
  1. 环境变量 PROBE_CONFIG_FILE 指向的 JSON 文件：
       {
         "probes": {"probe-1": "hex-or-utf8-secret", ...},
         "admin_key": "管理 API 密钥"
       }
  2. 环境变量 PROBE_KEYS="id1=secret1,id2=secret2"（不含逗号/等号的简单场景）
     管理密钥单独取 ADMIN_KEY 环境变量。

管理 API 部署在带 /docs 的上游服务中，其启动配置必须与本模块看到的
探针清单一致（compose 中通过同一环境变量注入）。
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass


@dataclass(frozen=True)
class PlatformConfig:
    # 探针 ID -> HMAC 密钥（UTF-8 字节），启动固定
    probes: dict[str, bytes]
    # 管理 API 密钥（明文 UTF-8）；为空表示管理端必须自行拒绝所有调用
    admin_key: str


class ConfigError(RuntimeError):
    """启动配置非法：缺凭据、重复 ID、空密钥等，直接阻止进程启动。"""


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
    """从环境加载平台配置；探针表为空视为致命配置错误。"""
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
