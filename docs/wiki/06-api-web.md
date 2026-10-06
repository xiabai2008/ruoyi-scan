# 06 · Web API 与控制台

> 这一章回答：`--serve` 起来的服务里有什么？鉴权怎么分级？实时进度是怎么推到浏览器的？
>
> 相关源码：[api/](https://github.com/xiabai2008/Ruoyi-Scan/tree/main/api) · [web/](https://github.com/xiabai2008/Ruoyi-Scan/tree/main/web) · [cli/serve_runner.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/cli/serve_runner.py)

---

## 1. 启动链路

```
main.py → dispatcher.dispatch() → args.serve 为真
    ↓
cli/serve_runner.run_serve_mode(args)
    ├─ API Key 成链回退：--api-key 优先 → RUOYI_SCAN_API_KEY 兜底 → 都空则仅本机
    ├─ 打印监听地址 / 文档地址 / 控制台地址 / 持久化路径 / 定时扫描配置
    ├─ 校验 --schedule 与 --schedule-target 必须成对
    ├─ create_app(api_key, cors_origins, db_path, schedule_expr, schedule_target)
    └─ uvicorn.run(app, host, port)
```

**只捕获 `ImportError`**——依赖缺失时给出明确的安装命令（`pip install fastapi uvicorn[standard]`）；其他启动异常照常抛出，不吞。

`--schedule` 与 `--schedule-target` 的成对校验在 CLI 层完成（缺一个就报错），避免把半截配置传进 `create_app`。

---

## 2. 应用工厂 `create_app()`

[api/app.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/api/app.py) 用工厂函数而非模块级 `app = FastAPI(...)`，理由是**可测试**：每个测试用例可以建一个独立 app，传入不同的 api_key / db_path。

### 2.1 创建顺序

```
1. set_quiet(True)                    # 服务模式静默：插件进度输出改走 logging
2. FastAPI(title=..., docs_url="/docs", redoc_url="/redoc", lifespan=lifespan)
3. CORS 中间件（默认仅 localhost）
4. ApiKeyMiddleware（api_key 为空则降级为"仅本地可访问"）
5. Storage(db_path or DEFAULT_DB_PATH)
6. TaskRegistry(storage=storage)
7. ScanOrchestrator(registry=registry)
8. ScanScheduler(orchestrator, storage)  # 加载失败 → None（降级为无调度）
9. app.state 挂载：registry / orchestrator / storage / api_key / scheduler
10. 挂载 6 个路由（全部 prefix="/api"）+ WebSocket /ws/scan/{task_id}
11. StaticFiles(web_dir, html=True) 挂载 "/" —— 仅当 web/ 存在
```

**第 1 步是必要的**：服务的实时进度已经通过 WebSocket 推给前端，插件再往 stdout 打一份就是纯噪音。`set_quiet(True)` 让 `lib/reporter.emit()` 改走 logging。

### 2.2 CORS 默认策略

```python
if cors_origins is None:
    cors_origins = ["http://localhost:3000", "http://127.0.0.1:3000",
                    "http://localhost:8000", "http://127.0.0.1:8000"]
allow_methods = ["GET", "POST", "DELETE"]        # 无 PUT/PATCH
allow_headers = ["X-API-Key", "Content-Type", "Authorization"]
```

**白名单而非 `*`**，且**方法列表只开放实际用到的**（没有 PUT/PATCH）。这是"收紧攻击面"的直接体现——即使有人把服务暴露到公网，CORS 层也不会放行任意来源的写操作。

### 2.3 生命周期 `lifespan`

| 阶段 | 动作 |
| --- | --- |
| startup | `registry.bind_loop(asyncio.get_running_loop())` → `restore_from_storage()` → `scheduler.start()` |
| shutdown | `scheduler.shutdown()` → `registry.unbind_loop()` → `orchestrator.shutdown()` |

**`bind_loop` 是跨线程推送的前提**：扫描跑在普通线程（`_DaemonThreadPoolExecutor`），WS 推送必须在 asyncio loop 上执行，因此需要在 startup 时把 loop 交给 registry。

**`restore_from_storage()` 让服务重启不丢历史**：任务与事件都在 SQLite 里，重启后内存 registry 从库中恢复。

**shutdown 顺序是反向的**，且 `orchestrator.shutdown()` 最后执行——先停调度器（不再产生新任务），再摘 loop，最后回收线程池。

---

## 3. 鉴权：API Key 分级（D11 / E9）

[api/auth.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/api/auth.py) 是一个 `BaseHTTPMiddleware`。整个模块的头部注释就写明了三条安全纪律，值得逐条理解。

### 3.1 权限矩阵

| scope | 数值 | 能做 |
| --- | --- | --- |
| `read` | 1 | 查询任务、下载报告 |
| `scan` | 2 | read + 发起/取消扫描 |
| `admin` | 3 | scan + 插件管理 + 定时任务管理 |

### 3.2 多 Key 配置格式

```bash
--api-key "key1:read,key2:scan,key3:admin"
```

`parse_api_keys()` 解析为 `{key: scope}`：

- `"single-key"` 无冒号 → `admin`（**向后兼容**单 Key 用法）；
- `"key:read"` → `read`；
- scope 不在 `_SCOPE_LEVEL` 里 → **回落 `admin`**（fail-closed 的反面：这里是 fail-open，但只在"用户写了非法 scope"这种配置错误场景，且会在启动时可见）。

### 3.3 路径 → 所需权限

```python
_ADMIN_PATHS = ("/api/plugin", "/api/schedule")     # 插件管理 + 定时任务
# 其余：POST/PUT/PATCH/DELETE → "scan"；GET → "read"
```

注意 `_required_scope` 里 admin 路径**先匹配**——否则 `/api/schedule` 的 POST 会被 `method in (...)` 规则捕获成 `scan` 而非 `admin`。

### 3.4 三道安全实现细节

**(a) 常量时间比较**

```python
hmac.compare_digest(provided_key, stored_key)
```

防时序侧信道攻击：普通 `==` 在第一个不同字符处提前返回，攻击者可以通过测量响应时间逐字节猜出密钥。

**(b) 多 Key 查找不提前返回**

```python
matched = None
for stored_key, scope in self.key_scopes.items():
    if hmac.compare_digest(provided_key, stored_key):
        matched = scope
        # 不 break：即使已匹配也继续遍历，保持恒定时间
```

如果命中就 `break`，则"命中第一个 key"比"命中最后一个 key"快——泄漏了 key 在配置中的位置信息。**遍历全部**才能保证响应时间与命中位置无关。

**(c) 禁止 URL 查询参数传输密钥**

```python
provided_key = request.headers.get("X-API-Key", "")
```

只接受 `X-API-Key` 头。`?api_key=xxx` 会泄漏到访问日志、浏览器历史、`Referer` 头——这是真实存在的密钥泄露渠道。**主动放弃便利性以换取安全性**。

### 3.5 无 Key 模式：仅本机

```python
if not self.api_key:
    if client_host in ("127.0.0.1", "::1", "localhost", "testclient"):
        return await call_next(request)
    return JSONResponse(401, {"detail": "API Key 未配置，仅允许本地访问。..."})
```

**默认安全**：不配 Key 不等于"无鉴权"，而是"退化为本机专用"。错误信息里直接给出解法（设置 `--api-key`）。`testclient` 在名单里是为了让 FastAPI 的 `TestClient` 能工作。

### 3.6 免鉴权路径

```python
PUBLIC_PATHS = ("/docs", "/openapi.json", "/redoc",
                "/api/system/health", "/api/system/metrics", "/favicon.ico")
```

`/api/system/metrics` 对外开放是为 Prometheus 抓取——注释里明确提示：

> 注：`/api/system/metrics` 对外开放供 Prometheus 抓取，**建议通过网络层（防火墙/Docker 网络）限制访问**。

即：这是应用层鉴权与应用层可观测性的取舍，把防护责任交给网络层，并把这一点写进代码注释。

---

## 4. WebSocket：实时事件流

### 4.1 为什么 WebSocket 要单独做鉴权

[api/ws/handler.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/api/ws/handler.py) 的注释点出了关键：

> `BaseHTTPMiddleware` **不拦截 WebSocket 请求**，此处单独做与 REST 一致的鉴权。

中间件只覆盖 HTTP 请求。如果不单独处理，WS 会成为一个**完全绕过鉴权的后门**——能读到所有扫描结果的实时流。

### 4.2 密钥怎么传

浏览器的 `WebSocket` 构造函数**无法设置自定义 Header**。因此用子协议头：

```javascript
new WebSocket(`ws://localhost:8000/ws/scan/${taskId}`,
              ['ruoyi-scan-api-key', apiKey])
```

```python
WS_SUBPROTOCOL = "ruoyi-scan-api-key"
# Sec-WebSocket-Protocol: ruoyi-scan-api-key, <api_key>
```

`_ws_auth_error()` 遍历子协议列表、跳过协议标识自身、取剩下的作为密钥，并同样用 `hmac.compare_digest` 常量时间比较（不提前返回）。

**同样禁止 `?api_key=`**：URL 会进日志与 `Referer`。

### 4.3 连接生命周期（`scan_ws`）

```
1. _ws_auth_error() 鉴权 → 失败 close(1008, reason)
2. accept(subprotocol=...) —— 仅当客户端请求了该子协议才回选
3. registry.get(task_id) → 不存在则发 error 事件 + close(1008)
4. registry.get_history(task_id) 逐条补播历史事件        ← 关键
5. 若任务已终态：发 connection_closed + close(1000)
6. registry.subscribe(task_id) 拿到队列
7. 循环 queue.get()（30s 超时 → 发 ping 保活）：
     ├─ type in ("complete", "error")          → sleep 0.5 → close(1000)
     ├─ type == "status" 且 status 为终态      → sleep 0.5 → close(1000)
     └─ 其他                                   → send_json
8. finally: registry.unsubscribe(task_id, queue)
```

三个值得注意的设计：

**(a) 历史补播（第 4 步）**：客户端可能在扫描开始后才连上 WS。如果只推新事件，前面的 `fingerprint`、`waf`、已产出的 `result` 全会丢。补播让"晚连接"与"早连接"看到相同的事件序列。

**(b) 两条独立的关闭路径**：`complete`/`error` 事件关闭是一路；`status` 事件里出现终态是另一路。注释解释了原因——**兼容事件顺序差异**（不同代码路径下终态可能先以 `status` 形式到达）。

**(c) `sleep(0.5)` 后再 close**：给客户端一点时间接收最后一条事件。直接 close 可能导致消息未送达。

**(d) 心跳 30s**：`asyncio.wait_for(queue.get(), timeout=HEARTBEAT_INTERVAL)` 超时即发 `ping`。长扫描中长时间无事件（例如一个慢插件）会触发中间代理断开空闲连接，心跳防这个。

### 4.4 事件协议

结构统一为：

```json
{"type": "<事件类型>", "data": { ... }, "task_id": "<id>"}
```

事件类型常量在 [api/ws/events.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/api/ws/events.py)：

| 事件 | 触发 |
| --- | --- |
| `status` | 任务状态变更（pending/running/done/failed/cancelled） |
| `complete` | 任务完成（含 duration / result_count / confirmed_count…） |
| `fingerprint` | 指纹识别完成 |
| `waf` | WAF 识别完成 |
| `portscan` | 端口扫描完成 |
| `category_start` | 插件分组开始 |
| `result` | 单个插件产生结果 |
| `progress` | 进度更新（done/total/percent） |
| `report` | 报告生成完成 |
| `error` | 任务异常 |

`ALL_EVENTS` 集合用于校验与文档——新增事件需同步登记。

> 注：orchestrator 的 `_emit` 还发了一些未列入 `ALL_EVENTS` 的事件（`recon` / `component` / `auth` / `template` / `plugins_loaded` / `waf_bypass` 等）。`ALL_EVENTS` 是**核心事件集合**，不是穷举。这是 [README 文档漂移清单](README.md#五文档与实现的一致性说明) 之外的又一处口径差异。

---

## 5. REST 端点全表

所有路由挂载在 `prefix="/api"` 下。

### 5.1 扫描任务（[api/routes/scan.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/api/routes/scan.py)）

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| `POST` | `/api/scan` | scan | 提交扫描，返回 `task_id`（非阻塞） |
| `GET` | `/api/scan` | read | 列出所有任务 |
| `GET` | `/api/scan/{task_id}` | read | 查询单个任务状态 |
| `DELETE` | `/api/scan/{task_id}` | scan | 取消任务（**软取消**） |
| `GET` | `/api/scan/{task_id}/results` | read | 获取结果列表 |

**`POST` 固定 `report_dir="reports/api"`**：API 提交的任务统一输出到固定目录，不暴露路径参数（避免路径穿越与磁盘写满）。

**软取消**：`DELETE` 只是把内存状态置为 `cancelled` 并广播事件。

> 软取消：只置内存状态标志并广播事件，执行中的插件线程在**下一轮检查状态时自行退出**。

即：**正在执行的插件不会被强杀**。这是刻意的——强杀线程在 Python 里不安全（`Thread.kill` 不存在，只能靠异常注入，会留下未释放的连接与半写文件）。

**结果从事件流重建**：`GET /results` 遍历 `record.events` 过滤 `type == "result"`，而非读单独的 results 表。**事件流是唯一事实来源**，避免了"事件流与结果表不同步"的经典问题。

### 5.2 定时扫描（`schedule_router`）

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| `GET` | `/api/schedule` | admin | 列出定时任务 |
| `POST` | `/api/schedule` | admin | 创建（body: `cron` / `target` / `mode` / `payload`） |
| `DELETE` | `/api/schedule/{job_id}` | admin | 删除 |

创建时**先校验 cron 表达式**（`parse_schedule_expr` 抛 `ValueError` → 400），避免存进调度器后才失败。调度器未初始化时返回 503 而非 500——明确区分"服务没这个能力"与"服务内部错误"。

### 5.3 报告（[api/routes/report.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/api/routes/report.py)）

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/api/report/{task_id}` | 报告（默认/HTML） |
| `GET` | `/api/report/{task_id}/html` | HTML |
| `GET` | `/api/report/{task_id}/json` | JSON |
| `GET` | `/api/report/{task_id}/csv` | CSV |
| `GET` | `/api/report/{task_id}/pdf` | PDF |
| `GET` | `/api/report/{task_id}/docx` | Word |
| `GET` | `/api/report/{task_id}/xlsx` | Excel |

### 5.4 插件与系统（[api/routes/plugin.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/api/routes/plugin.py) / [system.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/api/routes/system.py)）

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| `GET` | `/api/plugins` | admin | 列出插件（`PluginBase.meta()`） |
| `GET` | `/api/plugins/{name}` | admin | 单个插件详情 |
| `GET` | `/api/system/health` | 公开 | 健康检查 |
| `GET` | `/api/system/version` | read | 版本 |
| `GET` | `/api/system/fingerprint` | read | 在线指纹探测 |
| `GET` | `/api/system/metrics` | 公开 | Prometheus 指标 |

### 5.5 依赖注入（[api/deps.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/api/deps.py)）

```python
def get_registry(request) -> TaskRegistry:      # 从 request.app.state 取
def get_orchestrator(request) -> ScanOrchestrator:
```

两个函数都是 **`app.state` 取用 + 未初始化报 503**。注释解释了为何从 `request.app.state` 而不是模块级单例：

> 组件在 create_app 时挂载到 app.state，经 `Request` 取用便于**测试时替换实现**。

---

## 6. Prometheus 指标（D16）

[api/metrics.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/api/metrics.py) 手写 PlainText 格式（不引 `prometheus_client`）：

| 指标 | 类型 | 说明 |
| --- | --- | --- |
| `ruoyi_scan_uptime_seconds` | gauge | 服务运行时间 |
| `ruoyi_scan_tasks_total{status=...}` | gauge | 任务总数（按状态分） |
| `ruoyi_scan_tasks_active` | gauge | 活跃任务数（running + pending） |
| `ruoyi_scan_storage_tasks` | gauge | 持久化任务数 |
| `ruoyi_scan_results_total{status=...}` | gauge | 结果总数 |

两处实现细节：

**(a) 读 `registry._tasks` 加锁**

```python
with registry._lock:
    for record in registry._tasks.values():
```

源码注释坦承：

> 直接读 registry 内部任务表（**无公开统计接口**），加锁避免与写入线程竞争

即：这是一个"穿透封装"的实现，用锁保证安全。理想情况下 `TaskRegistry` 应提供公开的统计方法；现状是注释里承认了这一点。**注释诚实记录了技术债**，比默默穿透要好。

**(b) `unknown` 是近似值**

```python
# unknown 取 total - confirmed 的近似，max(0, ...) 防御数据不一致导致的负数
stats["unknown"] += max(0, total - confirmed)
```

`unknown = total - confirmed` 把 `safe` 也算进了 `unknown`。这不是精确统计，`metrics.py` 的注释明确说了是"近似"。`max(0, ...)` 是对数据不一致的防御性处理。

---

## 7. Web 控制台

[web/index.html](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/web/index.html) 是一个 **27 KB 的单文件控制台**，由 `StaticFiles(html=True)` 挂载到 `/`。

**单文件、零构建、零 npm** 的选择理由：

| 约束 | 收益 |
| --- | --- |
| 无构建步骤 | `git clone` 后 `--serve` 即可用，不需要 `npm install` |
| 无外部 CDN | 内网环境可用（安服现场常无外网） |
| 单文件 | 便于审计（一次读完），也便于通过邮件/微信分发 |

它通过 REST 提交任务 + WebSocket 订阅事件流，与服务端保持"零 API 版本耦合"——因为 WS 事件结构就是协议。

Prometheus 抓取配置在 [monitoring/prometheus.yml](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/monitoring/prometheus.yml)，配合 Docker 的 `--profile monitor` 使用（见 [07 章](07-desktop-deploy.md#4-容器部署)）。

---

## 8. 数据持久化

| 存储 | 路径 | 内容 |
| --- | --- | --- |
| 任务/事件/定时任务 | `data/tasks.db`（`--db-path` 可改） | [core/storage.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/storage.py) 的 `Storage` |
| API 报告 | `reports/api/` | 固定目录 |

`TaskRegistry` 是**内存为主**（速度快），`Storage` 负责**落盘与恢复**。启动时 `restore_from_storage()` 把历史任务读回内存，于是：

- 服务重启后 `GET /api/scan` 仍能看到历史任务；
- WS 的 `get_history()` 对重启前的任务也能补播（只要 registry 里恢复了事件）。

---

## 9. 安全收口清单

这个模块有明确的"第 2 周安全收口"标记，集中体现了以下决策：

| # | 决策 | 防的是 |
| --- | --- | --- |
| 1 | `hmac.compare_digest` 常量时间比较 | 时序侧信道攻击 |
| 2 | 多 Key 查找不 `break` | 通过响应时间泄漏 key 位置 |
| 3 | 禁止 `?api_key=` URL 传参 | 密钥泄漏到日志/历史/Referer |
| 4 | WS 单独鉴权（中间件不覆盖 WS） | WS 成为绕过鉴权的后门 |
| 5 | 无 Key 时仅允许本机 | "不配 Key = 无鉴权"的常见误用 |
| 6 | CORS 白名单 + 最小方法集 | 跨站写操作 |
| 7 | `_required_scope` 缺失时 fail-closed | 新增路径忘记配置权限时被误放行 |
| 8 | 路径穿越防护（插件安装侧，见 [05 章 §7](05-lib.md#7-关键机制五插件仓库与签名e5)） | 恶意插件包覆盖系统文件 |

第 7 条值得单独看：

```python
# 未知 scope 按数值 0 处理、未知路径所需权限按 read 兜底：整体 fail-closed
if _SCOPE_LEVEL.get(scope, 0) < _SCOPE_LEVEL.get(required, 1):
```

未知 scope → 0（低于任何权限，必被拒）；未知路径 → `read`（最低门槛，但只有 `read` 权限的 key 才能过）。**两个 `.get()` 的默认值方向相反，但结论都是"宁拒不放"**。

---

## 10. 本章小结

- `create_app()` 工厂 + `app.state` 挂载 + `deps.py` 取用，构成了**可测试的依赖注入结构**。
- 鉴权是三层：路径分类（admin/scan/read）→ 多 Key 解析 → 常量时间比较。三道安全细节（不提前返回、禁止 URL 传参、WS 单独鉴权）都是针对具体攻击面写的。
- WebSocket 的关键设计是**历史补播**与**心跳保活**；关闭路径有两条（`complete`/`error` 与终态 `status`），为兼容事件顺序差异。
- 事件流是**唯一事实来源**：`GET /results` 从事件重建，而非维护第二份结果表。
- `web/index.html` 单文件控制台的选择，服务于"内网可用、无需构建、便于审计"三个约束。

→ 下一章：[07 · 桌面端、靶场与部署](07-desktop-deploy.md)