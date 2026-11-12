# HTTP 请求走私防护反向代理（asyncio + h11）

单进程 Python asyncio 反向代理，部署在探针接入层，只放行 `POST /events` 上报，
在请求到达上游之前完成 **HTTP/1.1 分帧安全校验**，阻断请求走私
（Request Smuggling）。附带本地日志接收端（含 `/docs` 演示 API）与可直接
运行的字节级演示脚本。

## 目录结构

```
.
├── docker-compose.yml          # 一键启动 proxy + upstream
├── proxy/
│   ├── Dockerfile
│   ├── requirements.txt        # 仅依赖 h11
│   └── app/main.py             # 反向代理（核心，约 800 行，零 Web 框架）
├── upstream/
│   ├── Dockerfile
│   ├── requirements.txt        # fastapi + uvicorn
│   └── app/main.py             # 日志接收端，记录“实际收到的请求”作为证据
└── demo/
    └── demo.py                 # 仅标准库：分片 / 走私 / 延迟 / 连接池演示
```

## 快速开始

```bash
docker compose up --build
```

| 入口 | 地址 | 说明 |
| --- | --- | --- |
| 代理（唯一对外业务入口） | http://localhost:8080 | 只接受 `POST /events` |
| 上游日志接收端 | http://localhost:8000/events | 查看上游**实际收到**的请求 |
| 上游演示 API 文档 | http://localhost:8000/docs | FastAPI Swagger UI |
| OpenAPI | http://localhost:8000/openapi.json | 机器可读接口描述 |

另开终端运行演示：

```bash
python3 demo/demo.py
# 代理/上游不在本机默认地址时：
PROXY_PORT=8080 UPSTREAM_URL=http://127.0.0.1:8000 python3 demo/demo.py
```

## 安全策略与需求映射

| 需求 | 实现位置与行为 |
| --- | --- |
| 仅开放 `POST /events` | `InboundProtocol._loop`：路径/方法白名单，其余回 404/405 并关闭连接 |
| 接收 Content-Length 或 chunked | h11 负责成帧解析，`validate_framing` 负责策略校验 |
| 支持 TCP 分片 | 低层 `asyncio.Protocol` + 字节队列，h11 是 sans-IO 解析器，分片对它透明 |
| 支持同连接流水线 | h11 缓冲下一请求；`_reject_smuggled_tail` 区分合法流水线与走私残片 |
| 重复 Content-Length 拒绝 | h11 直接报 `conflicting Content-Length`，代理回 400 关闭 |
| TE 与 CL 并存拒绝 | **h11 0.16 不会自动拒绝**，`validate_framing` 显式拦截（RFC 7230 §3.3.3） |
| 非法分块拒绝 | h11 报 `illegal chunk header`，代理回 400 关闭 |
| 正文超过 64 KiB 拒绝 | 声明超限在读前回 413；实际超限在读循环中回 413 |
| 拒绝的请求不到达上游 | 全部校验与完整收体发生在获取上游连接**之前** |
| 重建单一 Content-Length | `exchange_upstream` 剥离所有逐跳头与原始分帧，追加唯一 `content-length` |
| CL.TE / TE.CL 夹带 | `_reject_smuggled_tail`：请求结束后深拷贝 h11 状态重解析尾余字节，不能成帧即 400 |
| 连接池容量 2 | `UpstreamPool`：`_active` 上限 2，条件变量排队 |
| 每连接同时只处理一笔 | `UpstreamConn.busy` + 池获取/释放互斥，同一连接不会并发复用 |
| 只信任 CL 响应才归还 | chunked/无 CL/CL 不符的响应抛 `UpstreamError`，连接销毁而非入池 |
| 从发送起总限 2 秒 | `_forward` 用统一截止时刻 `asyncio.timeout`，重试也不突破预算 |
| 超时销毁连接 | 超时取消交换任务并 `pool.destroy`，迟到响应随 socket 一起丢弃 |
| 客户端断连销毁连接 | 交换与 `closed_event` 竞速，断连即取消并销毁，绝不把响应留给下一调用者 |

### 为什么 `_reject_smuggled_tail` 能区分流水线与走私

h11 在按 Content-Length 截断当前请求后，会把多出来的字节留在内部缓冲区。
代理在请求完整结束后：

1. 缓冲区只有空白 CRLF → 容忍；
2. 深拷贝 h11 连接并模拟“已回响应、进入下一周期”，尝试重解析缓冲：
   - 得到 `Request` → 合法流水线（第二个完整请求），放行；
   - 得到 `NEED_DATA` → 跨 TCP 段的半截下一请求前缀，继续等；
   - 抛 `RemoteProtocolError`（如 `illegal request line: b't-Length: 0'`）
     → 走私残片，回 400 并关闭，第二个“后台请求”永远不会被转发。

## 连接池与超时语义

```
客户端 ──入站连接──> InboundProtocol (h11 SERVER)
                         │  完整校验 + 完整收体（<=64KiB）
                         ▼
                     UpstreamPool（容量 2，条件变量排队）
                         │  acquire → busy 标记
                         ▼
                     UpstreamConn (h11 CLIENT) ──> upstream:8000
                         │
        成功且响应为单一 Content-Length → release 回池
        超时 / 断连 / 协议错误 / 非 CL 响应 → destroy，永不回池
```

- **2 秒预算从首次向上游发送开始计时**，覆盖发送、上游处理、完整响应读取；
- 超时后连接立即销毁，即使上游 2.5 秒后才把响应发回来，字节也只进入一个
  已关闭的 socket，不会被池里的下一个调用者读到；
- 空闲池化连接若被对端静默关闭，取出时有 `at_eof()` 预检；首笔交换失败
  还允许在剩余 2 秒预算内用全新连接重试一次。

## 演示脚本输出说明（15 项断言）

1. **分片合法请求**：每 3 字节一个 TCP 段，正常 202；
2. **流水线**：一条 TCP 连接上连续两个请求，各自独立响应；
3. **chunked 重建**：上游收到的只剩一个 `Content-Length`，无 `Transfer-Encoding`；
4. **六类走私/畸形**：重复 CL、逗号双 CL、TE+CL、坏分块、64KiB 超限、
   CL.TE 夹带 `/admin` —— 全部 400/413 并断连，上游新增记录为 0；
5. **延迟响应**：上游 sleep 2.5s，代理 2.00s 回 504 并销毁，后续新请求干净；
6. **池容量**：3 个 0.8s 并发请求总耗时约 1.6s（两车道，第三笔排队）；
7. **路由白名单**：`GET /`、`POST /admin` 回 404 并断连，上游无记录。

脚本最后直接拉取 `GET /events` 打印上游实收请求清单（含原始头、正文、
TCP 连接标识），作为“走私流量确实没有到达上游”的证据。

## 本地无 Docker 开发运行

```bash
# 上游
pip install -r upstream/requirements.txt
( cd upstream && uvicorn app.main:app --host 127.0.0.1 --port 8000 )

# 代理（另开终端）
pip install -r proxy/requirements.txt
( cd proxy && UPSTREAM_HOST=127.0.0.1 UPSTREAM_PORT=8000 python -m app.main )
```

## 设计取舍

- 入站使用低层 `asyncio.Protocol` 而非 `StreamReader`，以便通过
  `connection_lost` 事件在**上游交换进行中**即时发现客户端断连；
- h11 只做无状态解析，所有安全策略（TE+CL、尾余走私、响应成帧）显式写在
  本仓库代码里，不依赖解析器版本的默认行为；
- 代理本身不缓存完整请求历史，入站正文超过 64 KiB 立即拒绝，内存占用有界；
- 上游 FastAPI 仅用于演示与取证，生产中可替换为任意固定 HTTP/1.1 服务，
  但代理只复用返回单一 `Content-Length` 响应的连接。
