# RuoYi Chaos Lab — 对抗 / 干扰型传输层靶场

> **用途**：验证 `Ruoyi-Scan` 在真实 HTTP 层异常（延迟、限流、WAF 挑战、软 404、
> 连接中断、超大响应）下的判定质量。本靶场**不实现任何漏洞**，只改变传输层行为，
> 与 `lab/server.py`（签名应答靶场）互补。
>
> ⚠️ 仅用于本机 / 授权测试环境。默认绑定 `127.0.0.1`，严禁暴露到公网。

---

## 1. 快速启动

```bash
# bash / git-bash
CHAOS_PROFILE=flaky CHAOS_PORT=8099 python lab/chaos/server.py

# PowerShell
$env:CHAOS_PROFILE="flaky"; $env:CHAOS_PORT="8099"; .venv\Scripts\python.exe lab\chaos\server.py
```

| 环境变量 | 默认值 | 说明 |
|---|---|---|
| `CHAOS_PROFILE` | `normal` | 行为 profile，见下表 |
| `CHAOS_PORT` | `8099` | 监听端口 |
| `CHAOS_HOST` | `127.0.0.1` | 监听地址；Docker 场景可覆盖为 `0.0.0.0` |

`GET /__lab/health` **永远返回 200**，且不消耗限流计数、不参与 flaky 抽样、不延迟。
所有请求都会打印到 stderr。

---

## 2. Profile 矩阵与期望三态

| profile | 真实 HTTP 行为 | 期望扫描器判定 |
|---|---|---|
| `normal` | 基线：`/` 返回登录页，其它 404 | 不产生 `CONFIRMED` 误报（额外基线，便于人工对照） |
| `slow` | 每个响应随机延迟 2–5s | 能完成时正常；超时策略应判 `UNKNOWN`，**不得把超时当 `SAFE`** |
| `tarpit` | `/` 正常，其它路径挂起 30s 后返回 200 | `UNKNOWN`（超时 / 挂起）；不得无限等待或误判 |
| `flaky` | 30% 请求返回 502/503（线程安全随机） | `UNKNOWN` / 重试；不得凭单次 5xx 判 `CONFIRMED` |
| `ratelimit` | 前 5 个请求正常，之后全部 429 + `Retry-After: 30` | 识别限流并退避；不得把 429 当 `SAFE` 或 `CONFIRMED` |
| `js_challenge` | 503 + Cloudflare 风格 JS 挑战页 + `cf-mitigated: challenge` | `UNKNOWN` / WAF 挑战；不得误报漏洞 |
| `soft404` | 未知路径 **HTTP 200** + 约 300 字节普通 404 页面 | `SAFE`；不得把软 404 当有效端点（防误报） |
| `block_all` | 所有路径 403 + 空 body + WAF 拦截头 | `UNKNOWN` / blocked；不得判 `CONFIRMED` |
| `redirect_loop` | `/` → `/a` → `/b` → `/a` 循环 302 | `UNKNOWN`；检测循环，不得无限跟随 |
| `gzip_chunked` | `/` 返回 `Transfer-Encoding: chunked` + `Content-Encoding: gzip` 的若依首页 | 指纹 / 首页类插件应可识别（`CONFIRMED` 指纹）；必须正确解压 |
| `bigbody` | `/` 返回 8–10 MB HTML | 指纹应可识别；不得 OOM / 因大响应误判 |
| `reset` | 读到请求后关闭底层 socket（失败时 `abort(413)`） | `UNKNOWN`；连接中断不得当 `SAFE` |

> 说明：`gzip_chunked` / `bigbody` 的 `CONFIRMED` 指**指纹识别**命中，不代表漏洞成立；
> 本靶场不提供任何漏洞端点。

---

## 3. 与签名靶场（`lab/server.py`）的差别

| 维度 | 签名靶场 | Chaos Lab |
|---|---|---|
| 目标 | 精确复现插件判定所需的响应签名 | 扰动真实 HTTP 传输层，检验超时 / 重试 / 限流 / 软 404 处理 |
| 响应 | 固定的正常 / 报错签名 | 真实延迟、状态码、分块编码、连接关闭、超大响应 |
| 误报检验 | safe 模式返回「已修复」签名 | 不返回漏洞签名，但用软 404 / 403 / 5xx 诱导误报 |
| 适用 | 插件匹配逻辑对拍 | 传输层健壮性、三态判定质量 |

---

## 4. 已知限制

- `flaky` 是概率行为：30 次请求全部未命中 5xx 的理论概率约 `0.7^30 ≈ 2e-5`，
  自测脚本因此可能极低概率失败一次，重跑即可。
- `tarpit` 的挂起发生在服务端线程中；自测脚本用 1.5s 客户端超时验证后直接杀掉进程。
- `reset` 的客户端症状取决于 HTTP 栈（连接重置 / 413 / 空响应），自测脚本接受多种表现。
- `bigbody` 每次请求分配 8–10 MB 内存，高并发时请降低并发数。
- 分块编码由 Werkzeug 开发服务器自动完成（已验证 Python 3.12 / Werkzeug 3.1）；
  若换成其他 WSGI 服务器，`Transfer-Encoding` 行为可能不同。
- 本靶场不含真实漏洞利用代码；`block_all` / `js_challenge` 仅用于判定质量检验。
