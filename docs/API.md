# API 使用指南

RuoYi-Scan 提供 RESTful API 和 WebSocket 实时事件推送，支持远程发起扫描、查询结果、下载报告。

## 快速开始

### 启动 API 服务

```bash
# 方式一：直接运行
python -m api.app --host 0.0.0.0 --port 8000

# 方式二：通过 CLI
python main.py serve --port 8000
```

### 交互式文档

启动后访问 FastAPI 自动生成的交互式文档：

- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`
- **OpenAPI JSON**: `http://localhost:8000/openapi.json`

### 导出 OpenAPI 规范

```bash
python scripts/export_openapi.py --output docs/openapi.json
```

导出的 `docs/openapi.json` 可导入 Postman、Insomnia、Apifox 等工具。

## 端点总览

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/scan` | 提交扫描任务 |
| GET | `/api/scan` | 列出所有任务 |
| GET | `/api/scan/{task_id}` | 查询任务状态 |
| GET | `/api/scan/{task_id}/results` | 获取扫描结果 |
| DELETE | `/api/scan/{task_id}` | 取消/删除任务 |
| GET | `/api/scan/{task_id}/report` | 下载报告 |
| GET | `/api/scan/{task_id}/report/metadata` | 报告元数据 |
| GET | `/api/plugins` | 列出所有插件 |
| GET | `/api/plugins/{name}` | 查询插件详情 |
| GET | `/api/system/info` | 系统信息 |
| GET | `/api/system/health` | 健康检查 |
| GET | `/api/metrics` | Prometheus 指标 |
| WS | `/ws/scan/{task_id}` | 实时事件订阅 |

## 核心接口详解

### 1. 提交扫描任务

```
POST /api/scan
```

**请求体**（`ScanRequestDTO`）：

```json
{
  "target": "http://example.com/",
  "mode": "u",
  "cms": "",
  "threads": 1,
  "rate": 0,
  "proxy": "",
  "timeout": 10,
  "debug": false,
  "report_format": "html",
  "no_dedup": false,
  "pass_level": "full",
  "portscan": false,
  "ports": "",
  "bypass_waf": "auto",
  "crawl": false,
  "crawl_depth": 2,
  "crawl_max_pages": 50,
  "subdomain": false,
  "js_extract": false,
  "template": "",
  "auth": null
}
```

| 字段 | 类型 | 默认 | 说明 |
|------|------|------|------|
| target | string | (必填) | 目标 URL |
| mode | string | "u" | 扫描模式：u=综合 / m=目录 / p=漏洞 / l=爆破 |
| cms | string | "" | 手动指定 CMS（空=自动指纹识别） |
| threads | int | 1 | 并发线程数 |
| rate | int | 0 | 限速（请求/秒，0=不限） |
| proxy | string | "" | HTTP 代理地址 |
| timeout | int | 10 | 请求超时秒数 |
| report_format | string | "html" | 报告格式：html/json/csv/pdf/docx/xlsx/sarif/all |
| portscan | bool | false | 是否启用端口扫描 |
| ports | string | "" | 自定义端口（逗号分隔） |
| bypass_waf | string | "auto" | WAF 绕过：auto/on/off |
| crawl | bool | false | 主动爬虫 |
| subdomain | bool | false | 子域名枚举 |
| js_extract | bool | false | JS 端点提取 |
| template | string | "" | 扫描模板：quick/deep/compliance/dengbao |
| auth | object | null | 认证配置 |

**auth 对象结构**：

```json
{
  "cookies": {"session": "abc123"},
  "headers": {"Authorization": "Bearer token"},
  "type": "session"
}
```

**响应**（`ScanResponseDTO`）：

```json
{
  "task_id": "a1b2c3d4e5f6",
  "status": "pending",
  "target": "http://example.com/",
  "created_at": 1721480000.0
}
```

**示例**：

```bash
# 基础扫描
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "http://192.168.1.100:8080/", "mode": "u"}'

# 带认证的深度扫描
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target": "http://192.168.1.100:8080/",
    "mode": "p",
    "auth": {"cookies": {"session": "admin_token"}},
    "template": "deep"
  }'
```

### 2. 查询任务状态

```
GET /api/scan/{task_id}
```

**响应**：

```json
{
  "task_id": "a1b2c3d4e5f6",
  "status": "done",
  "target": "http://example.com/",
  "mode": "u",
  "started_at": 1721480000.0,
  "finished_at": 1721480030.0,
  "duration": 30.5,
  "request_count": 152,
  "result_count": 18,
  "confirmed_count": 5,
  "error": "",
  "fingerprint": {
    "cms": "ruoyi",
    "confidence": 0.95,
    "matched": ["login_page"]
  },
  "waf": null,
  "report_paths": ["/data/reports/a1b2c3d4e5f6/report.html"]
}
```

任务状态流转：`pending` → `running` → `done` / `failed`

### 3. 获取扫描结果

```
GET /api/scan/{task_id}/results
```

**响应**（`ScanResultDTO` 列表）：

```json
[
  {
    "kind": "vuln",
    "name": "SQL注入-角色列表",
    "severity": "high",
    "status": "CONFIRMED",
    "url": "http://example.com/system/role/list",
    "evidence": "Boolean-based blind SQL injection detected",
    "cve": "CVE-2023-XXXX",
    "timestamp": 1721480010.0
  }
]
```

三种状态：
- `CONFIRMED` — 确认存在漏洞
- `SAFE` — 确认不存在漏洞
- `UNKNOWN` — 无法判定

### 4. 下载报告

```
GET /api/scan/{task_id}/report?format=html
```

| 参数 | 说明 |
|------|------|
| format | 报告格式：html/json/csv/pdf/docx/xlsx/sarif |

返回对应格式的文件流。先通过 `GET /api/scan/{task_id}/report/metadata` 查询可用格式。

### 5. WebSocket 实时事件

```
WS /ws/scan/{task_id}
```

连接后自动补播历史事件，然后实时推送新事件。

**事件类型**：

| 事件 | 说明 |
|------|------|
| `status` | 任务状态变更（pending/running/done/failed） |
| `portscan` | 端口扫描结果 |
| `fingerprint` | 指纹识别结果 |
| `waf` | WAF 探测结果 |
| `waf_bypass` | WAF 绕过模式 |
| `auth` | 认证注入 |
| `template` | 模板过滤 |
| `recon` | 信息收集（子域名/爬虫/JS 提取） |
| `plugins_loaded` | 插件加载完成 |
| `category_start` | 插件分类开始执行 |
| `result` | 单条扫描结果 |
| `complete` | 扫描完成（含统计摘要） |
| `error` | 扫描异常 |

**JavaScript 示例**：

```javascript
const ws = new WebSocket('ws://localhost:8000/ws/scan/a1b2c3d4e5f6');
ws.onmessage = (e) => {
    const event = JSON.parse(e.data);
    console.log(`[${event.type}]`, event.data);

    if (event.type === 'result') {
        console.log(`${event.data.name}: ${event.data.status}`);
    }
    if (event.type === 'complete') {
        console.log(`扫描完成，耗时 ${event.data.duration}s`);
        ws.close();
    }
};
```

**Python 示例**：

```python
import websockets
import asyncio
import json

async def listen(task_id):
    uri = f"ws://localhost:8000/ws/scan/{task_id}"
    async with websockets.connect(uri) as ws:
        async for message in ws:
            event = json.loads(message)
            print(f"[{event['type']}] {event.get('data', {})}")
            if event['type'] == 'complete':
                break

asyncio.run(listen("a1b2c3d4e5f6"))
```

### 6. 插件查询

```
GET /api/plugins
GET /api/plugins/{name}
```

返回所有已加载插件的元数据（名称、分类、严重度、CVE、影响版本等）。

## 错误处理

所有错误响应遵循统一格式：

```json
{
  "detail": "任务不存在: invalid_task_id"
}
```

常见 HTTP 状态码：

| 状态码 | 说明 |
|--------|------|
| 200 | 成功 |
| 400 | 请求参数错误 |
| 404 | 任务/插件不存在 |
| 500 | 服务器内部错误 |

## 完整示例：扫描流程

```bash
# 1. 提交扫描任务
TASK_ID=$(curl -s -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "http://192.168.1.100:8080/", "mode": "u"}' \
  | python -c "import sys,json; print(json.load(sys.stdin)['task_id'])")

echo "任务 ID: $TASK_ID"

# 2. 轮询任务状态（也可用 WebSocket 实时订阅）
while true; do
  STATUS=$(curl -s http://localhost:8000/api/scan/$TASK_ID | python -c "import sys,json; print(json.load(sys.stdin)['status'])")
  echo "状态: $STATUS"
  if [ "$STATUS" = "done" ] || [ "$STATUS" = "failed" ]; then
    break
  fi
  sleep 2
done

# 3. 获取扫描结果
curl -s http://localhost:8000/api/scan/$TASK_ID/results | python -m json.tool

# 4. 下载 HTML 报告
curl -o report.html http://localhost:8000/api/scan/$TASK_ID/report?format=html
echo "报告已下载: report.html"
```

## OpenAPI 规范

完整的 OpenAPI 3.0 规范已导出至 `docs/openapi.json`，可通过以下方式使用：

```bash
# 生成静态 HTML 文档（需安装 redoc-cli）
npx redoc-cli bundle docs/openapi.json -o docs/api-docs.html

# 导入 Postman
# Postman → Import → 选择 docs/openapi.json

# 导入 Apifox
# Apifox → 导入数据 → 选择 OpenAPI/Swagger → docs/openapi.json
```
