# 反走私 + HMAC 探针认证反向代理（asyncio + h11）

单进程 Python asyncio 反向代理，部署在探针接入层，只放行 `POST /events` 上报，
在请求到达上游之前完成两层防护：

1. **HTTP/1.1 分帧安全校验**，阻断请求走私（Request Smuggling）；
2. **HMAC-SHA256 探针认证 + 持久化 nonce 防重放 + 可永久撤销**，
   确保只有合法探针的上报能被写出，截获的报文无法重放。

附带本地日志接收端（含 `/docs` 可操作的管理与演示 API）与可直接运行的
字节级演示脚本，整个环境可用 Docker Compose 一键启动。

## 目录结构

```
.
├── docker-compose.yml          # 一键启动 proxy + upstream（共享 SQLite 命名卷）
├── config/
│   └── probes.json             # 探针 ID->密钥 与管理密钥（启动固定，演示凭据）
├── proxy/
│   ├── Dockerfile
│   ├── requirements.txt        # 仅依赖 h11
│   └── app/
│       ├── main.py             # 反向代理（分帧防护 + 认证门控 + 连接池/超时）
│       ├── config.py           # 启动配置加载（探针表/管理密钥）
│       ├── hmac_auth.py        # 签名原文构造、头解析、验签（纯函数）
│       └── auth_store.py       # SQLite：撤销表 + nonce 消费表（WAL）
├── upstream/
│   ├── Dockerfile
│   ├── requirements.txt        # fastapi + uvicorn
│   └── app/
│       ├── main.py             # 取证接收端 + /admin 管理 API（/docs 可操作）
│       ├── config.py           # 与代理同构的启动配置
│       └── admin_db.py         # 共享 SQLite 的撤销/查询访问
└── demo/
    └── demo.py                 # 仅标准库：本地签名 / 并发重放 / 排队撤销 / 分帧回归
```

## 快速开始

```bash
docker compose up --build
```

| 入口 | 地址 | 说明 |
| --- | --- | --- |
| 代理（唯一对外业务入口） | http://localhost:8080 | 只接受带 HMAC 认证的 `POST /events` |
| 上游日志接收端 | http://localhost:8000/events | 查看上游**实际收到**的请求 |
| 管理与演示 API 文档 | http://localhost:8000/docs | Swagger UI，可直接调用撤销等接口 |
| OpenAPI | http://localhost:8000/openapi.json | 机器可读接口描述 |

另开终端运行演示（仅用标准库，无需安装依赖）：

```bash
python3 demo/demo.py
# 代理/上游不在本机默认地址时：
PROXY_PORT=8080 UPSTREAM_URL=http://127.0.0.1:8000 python3 demo/demo.py
```

> 演示会永久撤销 `probe-demo-2`（这是预期行为，撤销不可恢复）。
> 重跑前如需还原初始状态：`docker compose down -v && docker compose up --build`。

## 认证协议

### 请求头（均为 ASCII）

| 头 | 含义 | 规则 |
| --- | --- | --- |
| `X-Probe-Id` | 探针 ID | 必须存在于启动配置 |
| `X-Timestamp` | Unix 秒时间戳 | 十进制整数，与服务端偏差绝对值 ≤ 30 秒 |
| `X-Nonce` | 随机数 | 恰好 32 位小写十六进制 |
| `X-Signature` | 签名 | 恰好 64 位小写十六进制 HMAC-SHA256 |

### 签名原文

四行以 **LF（`\n`）** 连接、无尾随换行：

```
<探针ID>
<时间戳>
<nonce>
<去除 HTTP 分帧后正文的 SHA-256 小写十六进制摘要>
```

HMAC 密钥为启动配置中该 ID 对应密钥的 UTF-8 字节。本地签名示例（`demo/demo.py`
中的实现与代理 `proxy/app/hmac_auth.py` 严格对应）：

```python
import hashlib, hmac, os, time
probe_id, secret = "probe-demo-1", b"<配置中的密钥>"
body = b'{"event":"hello"}'
ts = int(time.time())
nonce = os.urandom(16).hex()                       # 32 位小写 hex
digest = hashlib.sha256(body).hexdigest()
message = f"{probe_id}\n{ts}\n{nonce}\n{digest}".encode()
signature = hmac.new(secret, message, hashlib.sha256).hexdigest()
headers = {"X-Probe-Id": probe_id, "X-Timestamp": str(ts),
           "X-Nonce": nonce, "X-Signature": signature}
```

### 代理的处理顺序与状态码

```
路由/分帧校验（404/405/400/413）          不触碰 nonce 表
        │  完整读取“去帧后正文”
        ▼
头格式 → 探针存在 → ±30s 时间窗 → HMAC 验签   任一失败 401，不消费 nonce
        ▼
早期撤销检查（快速失败）                    已撤销 403
        ▼
获取容量 2 的上游连接（可能排队/建连）
        ▼
单事务门控（首次写出前）：撤销复核 + nonce 原子持久消费
        ├─ 已撤销        → 403（连接未写字节，归还连接池）
        ├─ nonce 已消费  → 409 重放（不重复消费、不写出）
        └─ 存储故障      → 503（fail-closed）
        ▼ COMMIT，立即释放 SQLite 写锁
向上游写出（剥离全部 X-Probe-*/X-Signature 头，重建单一 Content-Length）
        ├─ 成功 → 透传上游响应
        └─ 失败/超时 → 502/504，不重试（nonce 已消费，绝不重发）
```

## 需求到实现的映射

| 需求 | 实现位置与行为 |
| --- | --- |
| HMAC-SHA256 认证，ID→密钥启动固定 | `config.py` 启动加载 `config/probes.json`/`PROBE_KEYS`，运行期不可变；`hmac_auth.sign/verify_request` |
| 头携带 ID/秒级时间戳/32 位 hex nonce/签名 | `hmac_auth.parse_auth_headers` 严格格式与重复头校验 |
| 签名原文 = ID LF ts LF nonce LF 正文 sha256 hex | `hmac_auth.build_signing_string`；常量时间比较 `hmac.compare_digest` |
| 时间偏差 ≤ 30 秒 | `SKEW_SECONDS=30`，`abs(now-ts) > 30` 即 401 |
| 首次写出前核对时间/撤销/nonce 并持久消费 nonce | 时间与签名在收体后即验；权威撤销复核 + nonce 消费在 `_forward` 单事务内、任何上游字节写出前完成 |
| 同探针同 nonce 并发仅一次可写出 | `consumed_nonces` 表 `PRIMARY KEY(probe_id, nonce)` + `BEGIN IMMEDIATE`，冲突抛 `NonceAlreadyConsumed` → 409 |
| 消费后失败不重发 | nonce 消费后移除了原“失败重试一次”逻辑，上游错误只回 502/504，同 nonce 再来仍是 409 |
| 重启不得重放 | nonce 落 SQLite（WAL），新进程打开同一库即见历史消费记录 |
| 永久撤销 API，凭配置管理密钥 | 上游 `/admin/probes/{id}/revoke`，`X-Admin-Key` 常量时间校验；`revoked_probes` 只增不删 |
| 撤销后排队/建连中未写出的也拒绝，已写出可完成 | 门控事务在获取连接后、写出前复核撤销；已在途交换不回滚，正常返回 |
| 认证拒绝不消费 nonce | 所有 401/403 路径在 INSERT 之前返回；重放 409 也不重复写库 |
| 沿用分帧防护 | 原 `validate_framing`/`_reject_smuggled_tail` 等逻辑不变，且在认证之前执行 |
| 容量 2、发送起 2 秒期限 | `UpstreamPool` 容量 2；`_forward` 用 `asyncio.timeout(2.0)` 包住完整上游交换 |
| 网络等待不持 SQLite 写锁 | 事务在发起上游连接 IO 前 COMMIT 并释放；SQLite 调用均为短事务 |
| 可实际启动的 Compose，/docs 可操作 | `docker compose up --build`；管理接口在 `/docs` 的“探针管理”标签下 |

## 持久化与并发模型

```
                config/probes.json（只读挂载，启动固定）
                   │                          │
        ┌──────────▼─────────┐      ┌─────────▼──────────┐
        │ proxy（asyncio）   │      │ upstream（FastAPI）│
        │ 验签 / nonce 消费  │      │ /admin 撤销/查询   │
        └──────────┬─────────┘      └─────────┬──────────┘
                   │   共享命名卷 auth-data    │
                   ▼                           ▼
              /data/auth.db（SQLite WAL）
   revoked_probes（只增）   consumed_nonces（UNIQUE(probe,nonce)）
```

- **WAL 模式**：管理端写撤销与代理读/写不互斥，`busy_timeout=5000` 兜底；
- 代理内所有 SQLite 访问为毫秒级短事务，临界区由进程内锁串行化，
  跨进程一致性由 `UNIQUE` 约束与事务原子性保证；
- nonce 行有保留期（默认 1 小时），后台任务周期清理；安全窗口本身由
  30 秒时间戳偏差保证，清理不影响防重放正确性。

## 管理 API（均需请求头 `X-Admin-Key`）

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/admin/probes` | 列出配置内探针及撤销状态 |
| GET | `/admin/probes/{probe_id}` | 查询单探针是否在配置中、是否已撤销 |
| POST | `/admin/probes/{probe_id}/revoke` | 永久撤销（幂等），返回 `already_revoked` |
| GET | `/admin/nonces/{probe_id}/{nonce}` | 查询某 nonce 是否已被持久消费 |

错误密钥返回 401；撤销配置外的 ID 返回 404（不写入永久状态）。

## 演示脚本覆盖的断言

- **A 本地签名**：合法 202、坏签名/过期时间戳/篡改正文 401、认证拒绝不消费 nonce；
- **B 并发重放**：8 个同 ID 同 nonce 并发恰好 1 笔 202、7 笔 409，事后串行重放仍 409，
  并通过管理 API 验证 nonce 已持久消费；
- **C 排队撤销**：两笔慢请求占满容量 2 的池，第三笔排队期间永久撤销 →
  前两笔 202、第三笔 403，撤销后新上报一律 403，错误管理密钥 401；
- **D 分帧回归**：分片/流水线/chunked 重建/五类走私畸形/路由白名单；
- **E 池与超时**：3 笔 0.8s 并发呈两车道（约 1.6s），2.5s 慢响应在 2s 处回 504。

## 本地无 Docker 开发运行

```bash
# 上游
pip install -r upstream/requirements.txt
( cd upstream && PROBE_CONFIG_FILE=../config/probes.json \
  AUTH_DB_PATH=./auth.db uvicorn app.main:app --host 127.0.0.1 --port 8000 )

# 代理（另开终端，AUTH_DB_PATH 指向同一文件）
pip install -r proxy/requirements.txt
( cd proxy && UPSTREAM_HOST=127.0.0.1 UPSTREAM_PORT=8000 \
  PROBE_CONFIG_FILE=../config/probes.json AUTH_DB_PATH=../auth.db \
  python -m app.main )
```

## 设计取舍

- **门控放在获取连接之后、首次写出之前**：既满足“首次写出前核对”，又能让
  排队/建连期间发生的撤销在真正写库时被事务复核捕获；门控失败的连接未写过
  任何字节，可安全归还连接池；
- **消费即不重试**：原代理首笔失败重试一次的策略在认证体系下会造成同一事件
  两次写出，因此移除，改为确定性 5xx，由探针凭新 nonce 重新上报；
- **认证头不转发上游**：`exchange_upstream(strip_auth=True)` 剥离全部
  `X-Probe-*`/`X-Signature`，上游只接收事件本身；
- **密钥只在启动配置中**：运行期没有任何增改探针密钥的接口，撤销是唯一的
  运行期身份变更，且永久落库；
- 入站仍使用低层 `asyncio.Protocol` 以便在上游交换进行中即时发现客户端断连；
  h11 只做无状态解析，TE+CL、尾余走私、响应成帧等安全策略均显式写在代码里。
