# 1.x → 2.0 迁移说明

> 适用版本：从 v1.8.0 及更早版本升级到 **v2.0.0**。  
> 2.0 是主版本升级：默认行为、报告字段和部分旧参数有**破坏性变化**，升级前请阅读本文。

## 一、升级方式

### Python / CLI

```bash
pip install -U ruoyi-scan
ruoyi-scan -V
```

### 桌面端

- Windows：下载并覆盖安装 v2.0.0 安装包；
- 旧版配置/历史报告保留在用户数据目录，2.0 可继续读取 1.8 的 JSON 报告，但新增字段只在新报告中出现。

### 回滚

```bash
pip install "ruoyi-scan==1.8.0"
```

桌面端可回退安装 1.8.0 安装包；1.8 不识别 2.0 新增的报告字段，但不会因未知字段崩溃。

---

## 二、破坏性变更

### 1. 爆破字典默认级别从 full 改为 top100

- 2.0 默认 `--pass-level top100`，完整字典必须显式 `--pass-level full`。
- 原因：旧默认在真实登录站点会跑 6×1,053 组 Druid 字典（R1 约 6,318 请求），
  可能触发账号锁定/告警。
- Druid 爆破新增锁定/429/验证码检测，命中后返回 `UNKNOWN(brute_blocked)` 并主动停止。
- 如需保持 1.x 的完整字典行为：

```bash
ruoyi-scan -u http://target --pass-level full
```

### 2. 报告 request_count 口径变化

- 旧版只统计主会话；1.8 实测 R11 少计 88 个请求。
- 2.0 统计主会话、recon、anonymous、isolated auth 全部请求。
- **升级后同一个目标的 request_count 会比 1.x 大**，这是修正，不是流量增加。
- 批量报告的每目标 request_count / duration / fingerprint 也改为真实值，不再是 `len(results)` / 0 / 空指纹。

### 3. 报告 JSON 新增字段

- `plugin_metrics`: 每个插件的 `{plugin, duration_ms, requests}`；
- `waf`: WAF 识别结果（包括 `generic-http-filter` 行为识别）；
- 结果对象可能新增 `unknown_reason=brute_blocked`、`no_login_page` 等。

按固定字段集合校验报告的下游脚本需要允许新增字段。

### 4. 已删除的旧参数/入口

以下 1.x 参数/入口已删除，2.0 会直接报参数错误：

- 缓存：`--cache`、`--cache-ttl`、`--cache-db`、`--cache-stats`、`--cache-clear`、`--cache-clear-all`；
- Web UI：`--web-ui`、`--web-ui-output`、`--web-ui-api`；
- 语言：`--lang`；
- `--no-components`；
- `--plugin-new`（保留 `--plugin-init`）；
- `--serve` 不再提供内置 Web 控制台页面，根路径 `/` 改为 404/API 入口；
  人机界面请使用桌面端，服务侧使用 REST/WS 与 `/docs`。

`--category` 已更名为 `--framework`，旧名仍保留为兼容别名。

### 5. OAST 默认行为

- 2.0 新增 `--oast` 扫描侧接线（1.x 只有 `--oast-server`）。
- 启用后本机会启动 HTTP 回调监听和按需 TCP 监听；默认绑定需符合你的网络/防火墙策略，
  远程回调请显式使用 `--oast-bind` / `--oast-host`。
- 不启用 `--oast` 时，`requires_oast` 插件会在加载期被过滤，不产生伪 UNKNOWN。

### 6. 新增在线更新

- 桌面端：启动自动检查，设置页可手动检查/下载安装；更新包 Ed25519 验签。
- CLI：`--check-update` / `--self-update`；pip 版调用 pip，Windows 单文件 exe 自动替换并重启。
- 更新清单默认指向 GitHub Release 的 `version.json` / `latest.json`；镜像可用 `--update-url` 覆盖。
- 详见[在线更新](updates.md)。

### 7. 插件与检测声明

- 插件数从 1.8 的 62 增至 **63**（新增前端 SourceMap 源码泄露）；
- 新增 Cloud 能力包、WAF 行为识别、Ruoyi-Plus/Cloud 指纹增强；
- 旧版自定义插件若依赖已删除模块名（如 `lib/reporter`、`core/cache`、`core/auth_chain`），
  需按 1.8 的模块重命名迁移；2.0 不再提供旧 import 路径。

---

## 三、建议的升级验证

```bash
# 1. 版本
ruoyi-scan -V

# 2. 插件清单应为 63
ruoyi-scan --plugin-list | measure

# 3. 负样本目标应 0 CONFIRMED
ruoyi-scan -u http://your-safe-target/ --no-pause --no-cta

# 4. 批量报告 request_count 不再为 len(results)
ruoyi-scan -u -f targets.txt --report reports/upgrade-smoke --report-format json
```

## 四、兼容性

- Python：`>=3.8`（与 1.8 相同）；
- 报告格式：HTML/DOCX/XLSX/PDF/CSV/SARIF 保持，JSON 只新增字段；
- API：`/api/scan` 请求/响应兼容，任务响应新增 `plugin_metrics` / `waf` 字段；
- 历史报告：2.0 可读取 1.8 JSON 报告；1.8 读取 2.0 报告时忽略新增字段。
