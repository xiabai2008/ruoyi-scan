# Ruoyi-Scan 安全收口报告（最终版）

> 版本：v1.0.1（2026-08-24）
> 范围：第 1 周插件供应链安全 + 第 2 周 API 鉴权与靶场暴露面安全
> 结论：两轮安全收口共 14 项整改全部完成并通过回归验证（1185 测试全绿）

---

## 1. 安全收口总览

| 编号 | 风险项 | 严重度 | 状态 |
|------|--------|--------|------|
| W1-1 | 插件远程安装无签名校验（可被供应链投毒） | 高 | ✅ 已修复 |
| W1-2 | 插件 manifest 路径穿越 / zip-slip | 高 | ✅ 已修复 |
| W1-3 | 无 cryptography 时降级为纯摘要校验（弱验签） | 高 | ✅ 已修复 |
| W1-4 | 插件签名发布流程私钥泄露风险 | 高 | ✅ 已修复 |
| W2-1 | API Key 明文 `==` 比较（时序侧信道） | 高 | ✅ 已修复 |
| W2-2 | API Key 经 `?api_key=` URL 传输（泄露到日志/历史/Referer） | 高 | ✅ 已修复 |
| W2-3 | 带洞靶场默认绑定 `0.0.0.0`（局域网暴露） | 高 | ✅ 已修复 |
| W2-4 | WebSocket 端点绕过 API Key 鉴权 | 高 | ✅ 已修复 |
| W2-5 | Grafana / Prometheus 宿主端口全接口暴露 | 中 | ✅ 已修复 |
| W2-6 | 权限未分级（任意 Key 均可管理插件） | 中 | ✅ 已修复 |
| W2-7 | 靶场启动无安全横幅（易误部署到公网） | 低 | ✅ 已修复 |

---

## 2. 第 1 周：插件供应链安全

### W1-1 Ed25519 强制验签（fail-closed）

[lib/plugin_repo.py](file:///c:/Users/HZR/Desktop/HZR_PROJECTS/ruoyi-scan/lib/plugin_repo.py) 中
`download_and_install` / `verify_manifest` 实现：

- 远程安装强制要求 manifest 携带 **Ed25519 签名**，公钥来自本地可信存储
  `~/.ruoyi-scan/signing.pub`（消费者自行放置，不随发布物分发）
- **无签名 / 无公钥 / 验签失败一律拒绝安装**（fail-closed，默认 `require_signature=True`）
- 验签失败原因逐项收集到 `errors` 返回，便于定位（缺签名、缺 cryptography、公钥不匹配等）

### W1-2 路径穿越 / zip-slip 防护

`_is_safe_rel` + `_safe_join` 双层校验 manifest 相对路径与 zip 成员名：

- 拒绝绝对路径（`/`、`\` 开头或 `os.path.isabs`）
- 拒绝含反斜杠的路径（防 Windows 盘符穿越）
- 拒绝任一路径段为 `..` / `.`
- `normpath`/`abspath` 二次确认拼接后不越出仓库目录

### W1-3 cryptography 硬性依赖

- 远程安装 **要求安装 cryptography 库**；缺失时直接拒绝（`pip install cryptography` 指引），
  **不降级为纯 SHA256 摘要校验**，防止攻击者以"无法验签"为借口降低安全等级
- 本地生成/加载 Ed25519 密钥、签名、验签均基于 `cryptography.hazmat.primitives.asymmetric.ed25519`

### W1-4 CI 签名发布流程

- manifest 生成与签名由 **CI 自动完成**（使用 GitHub Secrets），禁止手工提交 manifest，
  避免本地/CI 文件排序差异导致的无谓变更
- 签名私钥仅存放于 `$RUNNER_TEMP`（工作区外），使用后即时删除
- 发布物中排除私钥文件（`signing.key*`），仅分发 `manifest.json + plugins/ + signing.pub`

---

## 3. 第 2 周：API 鉴权与靶场暴露面安全

### W2-1 API Key 常量时间比较

[api/auth.py](file:///c:/Users/HZR/Desktop/HZR_PROJECTS/ruoyi-scan/api/auth.py)：

- 所有密钥比较使用 `hmac.compare_digest`，比较耗时与密钥内容无关，消除时序侧信道
- 多 Key 模式下 `_lookup_scope` **遍历全部密钥且不提前返回**，即使命中仍继续遍历，
  保证查找耗时恒定，不泄露"密钥是否存在"

### W2-2 禁止 URL 传输密钥

- 移除 `?api_key=` 查询参数支持，密钥**仅接受 `X-API-Key` 请求头**
- 防泄露面：访问日志、浏览器历史、Referer、代理/网关默认参数采集
- WebSocket 同口径：密钥经 `Sec-WebSocket-Protocol` 子协议头传递，URL 查询参数一律拒绝

### W2-3 靶场服务绑定 127.0.0.1

三个带洞靶场服务统一引入 `HOST` 环境变量，默认 `127.0.0.1`：

- [lab/server.py](file:///c:/Users/HZR/Desktop/HZR_PROJECTS/ruoyi-scan/lab/server.py)（若依签名靶场）
- [lab/spring_server.py](file:///c:/Users/HZR/Desktop/HZR_PROJECTS/ruoyi-scan/lab/spring_server.py)（Spring 签名靶场）
- [lab/real-spring/server.py](file:///c:/Users/HZR/Desktop/HZR_PROJECTS/ruoyi-scan/lab/real-spring/server.py)（真实漏洞复现靶场）

容器环境通过 `LAB_HOST=0.0.0.0` 覆盖，保证 scanner/api 容器间互通；宿主端口在
[docker-compose.yml](file:///c:/Users/HZR/Desktop/HZR_PROJECTS/ruoyi-scan/docker-compose.yml)
中再收口为 `127.0.0.1:<port>:<port>`，形成"容器内互通 + 宿主仅本机"双层边界。

### W2-4 WebSocket 鉴权修复

[api/ws/handler.py](file:///c:/Users/HZR/Desktop/HZR_PROJECTS/ruoyi-scan/api/ws/handler.py)：

- 根因：`BaseHTTPMiddleware` 不拦截 WebSocket，`/ws/scan/{task_id}` 原为无鉴权面
- 修复：`_ws_auth_error` 在 `accept()` 前校验——
  - 无 Key 模式：仅允许本地回环（`127.0.0.1`/`::1`/`localhost`/`testclient`）
  - 有 Key 模式：从子协议头取密钥，`hmac.compare_digest` 常量时间校验
  - 失败以 `1008 Policy Violation` 拒绝连接
- 客户端握手示例：`new WebSocket(url, ['ruoyi-scan-api-key', apiKey])`

### W2-5 监控栈端口收口

docker-compose.yml 中 Grafana（3000）、Prometheus（9090）宿主端口均改为 `127.0.0.1:`，
监控面板与指标端点不暴露到局域网。

### W2-6 权限分级

- 三级权限矩阵 `read < scan < admin`，按路径映射所需最小权限
- 多 Key 格式 `--api-key "k1:read,k2:scan,k3:admin"`；单 Key 无 scope 兼容为 admin
- 权限不足返回 `403`（如 read 不能发起扫描、scan 不能管理插件）

### W2-7 靶场启动安全横幅 + 变更日志收尾

- 三个带洞靶场启动时打印安全横幅：`[!] 安全提示：本靶场含漏洞响应签名，仅限本机/授权测试环境使用，严禁部署到公网或未授权网络`
- [CHANGELOG.md](file:///c:/Users/HZR/Desktop/HZR_PROJECTS/ruoyi-scan/CHANGELOG.md) `[Unreleased]` 区登记两周安全收口记录

---

## 4. 回归验证

| 项目 | 结果 |
|------|------|
| 完整测试套件 | **1185 passed / 0 failed**（退出码 0） |
| 新增安全测试 | WS 鉴权 4 例 + URL 传密钥拒绝 1 例（test_e9_team / test_api_ws） |
| 改动文件编译 | 6 个 Python 文件 py_compile 全通过 |
| 依赖修复 | requirements-dev.txt 补声明 `requests_mock`（4 个既有测试文件在用但缺失） |

---

## 5. 残余风险与后续建议

| 风险 | 等级 | 说明与建议 |
|------|------|-----------|
| Web 控制台（web/index.html）未接入密钥输入 | 中 | REST/WS 均不携带 Key，仅在无 Key 模式下可用；建议增加登录/密钥输入 UI |
| `lib/web_ui.py` 独立 HTML 模板连接 `/ws/scan`（无 task_id） | 低 | 与现有路由 `/ws/scan/{task_id}` 不符，属历史失效代码；建议清理或对齐 |
| `/api/system/metrics` 对 Prometheus 开放 | 低 | 已靠 Docker 网络层隔离；如脱离 Docker 部署需在防火墙侧限制 |
| 多 Key 密钥含 `:` 会与 scope 解析冲突 | 低 | 现有格式约束；如需要可在解析层转义 |
| API Key 存于环境变量/命令行 | 低 | 生产建议接入密钥管理系统（如 KMS / Secrets Manager）轮换与审计 |

### 后续可选收口方向

1. Web 控制台增加 API Key 登录界面，打通有 Key 模式全链路
2. API Key 支持 HMAC 签名请求（防重放）或短期 Token 替代静态密钥
3. 为 API 增加速率限制与审计日志，配合监控栈形成可观测闭环
