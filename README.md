# Ruoyi-Scan — 若依专项漏洞扫描工具

> **2026-07-18 路线调整**：项目从"多 CMS 扫描器"转向**专注若依做深**。
> thinkphp / weaver / shiro / struts2 / nuclei 插件包已抽离至 [`../cms-scan-extras/`](../cms-scan-extras/)。
> 当前专注：登录链打通、多版本适配、验证码处理、real-ruoyi 自动化验收、误报率实测。

---

## 项目定位

一款合法授权的**若依（RuoYi）专项漏洞扫描器**，插件化架构，三态判定（CONFIRMED / SAFE / UNKNOWN），支持批量扫描与多格式报告。

- **作者**：雪山乘客
- **版本**：1.0.0
- **技术栈**：Python 3 + `requests`，命令行工具，控制台彩色输出

---

## 当前能力

| 模块 | 说明 |
|------|------|
| `plugins/ruoyi/` | 若依 16 个 POC（核心，做深方向） |
| `plugins/spring/` | Spring Boot 14 个 POC（协同，与若依生态强相关） |
| `plugins/common/` | 通用漏洞包（.git/.env/备份/CORS 等，不依赖 CMS 指纹） |
| 指纹识别 | favicon hash + 特征路径 + 登录页关键字，数据驱动 |
| 批量扫描 | `-f targets.txt`，批量汇总报告 |
| 报告 | HTML（SVG 图表）/ JSON / CSV / PDF / Word / Excel（D8，可选依赖降级） |
| 并发限速 | ThreadPoolExecutor + 令牌桶（锁外 sleep，无并发退化） |
| 三态判定 | 网络异常绝不判 SAFE |
| WAF 绕过 | 11 种绕过策略（L1 变形/L2 编码/L3 协议/L4 源站直连）+ 三态判定保护矩阵 + 策略成功率追踪（D7） |
| Web API | FastAPI REST + WebSocket 实时推送 + Alpine.js 控制台（D9，`--serve` 模式） |

---

## 快速开始

```bash
# 安装依赖
pip install -r requirements.txt

# 单目标漏洞扫描
python main.py -p http://target:8080/

# 批量扫描
python main.py -f targets.txt -p --report ./reports

# 手动指定 CMS（跳过指纹识别）
python main.py -p http://target:8080/ --cms ruoyi

# 综合扫描（目录扫描 + 漏洞检测 + 登录爆破）
python main.py -u http://target:8080/

# 生成全格式报告（HTML/JSON/CSV/PDF/Word/Excel）
python main.py -p http://target:8080/ --report ./reports --report-format all

# 关闭结果去重聚合
python main.py -p http://target:8080/ --report ./reports --no-dedup

# 执行漏洞利用链（D6）
python main.py --chain ruoyi_sql_to_rce -u http://target:8080/
python main.py --chain list  # 列出可用链

# WAF 绕过（D7，检测到 WAF 自动启用）
python main.py -p http://target:8080/ --bypass-waf auto   # 自动模式（默认）
python main.py -p http://target:8080/ --bypass-waf on     # 强制启用
python main.py -p http://target:8080/ --bypass-waf off    # 禁用绕过

# Web API 服务（D9，启动 HTTP API + WebSocket + Web 控制台）
python main.py --serve                              # 默认 0.0.0.0:8000
python main.py --serve --host 127.0.0.1 --port 9000 # 自定义地址端口
# 启动后访问：
#   http://host:port/         Web 控制台
#   http://host:port/docs     OpenAPI 交互文档
#   ws://host:port/ws/scan/{task_id}  WebSocket 实时事件
```

**CLI 参数**：`-h` 帮助 / `-u` 综合扫描 / `-m` 目录扫描 / `-p` 漏洞检测 / `-l` 登录爆破 / `-f` 批量 / `--cms` 指定 CMS（ruoyi/spring）/ `--threads` 并发数 / `--rate` 限速 / `--proxy` 代理 / `--report` 报告目录 / `--report-format` 报告格式（html/json/csv/pdf/docx/xlsx，逗号分隔，all=全部）/ `--no-dedup` 关闭去重 / `--chain` 执行漏洞利用链 / `--chain-list` 列出可用链 / `--bypass-waf` WAF 绕过策略（auto/on/off，默认 auto）/ `--portscan` 端口扫描 / `--ports` 自定义端口 / `--passive` 被动代理模式 / `--passive-host` 代理监听地址 / `--passive-port` 代理监听端口 / `--serve` 启动 Web API 服务 / `--host` 监听地址 / `--port` 监听端口 / `--timeout` 超时 / `--debug` 调试模式 / `--pass-level` 口令字典级别（top100/top1000/full）

---

## 目录结构

```
Ruoyi-Scan/
├── main.py                  # CLI 入口
├── config/settings.py       # 全局配置
├── core/                    # 引擎/路由/指纹/会话/报告/缓存
├── plugins/                 # 插件包（ruoyi + spring + common）
├── lib/                     # 工具库（指纹特征/HTTP/匹配器/颜色）
├── data/                    # 字典（ruoyi.txt / password.txt）
├── lab/                     # 靶场
│   ├── server.py            # RuoYi 签名靶场
│   ├── spring_server.py     # Spring 签名靶场
│   ├── real-spring/         # Spring 真实响应靶场（CI 自动）
│   ├── real-ruoyi/          # 真实 RuoYi 4.7.8 Java 应用
│   ├── REAL-RUOYI.md        # 真实 RuoYi 验证报告
│   ├── REAL-SPRING.md       # 真实 Spring 验证报告
│   └── VULN-REINTRODUCE.md  # RuoYi 漏洞重引入指南
├── tests/                   # 单元测试 + 回归测试
├── scripts/run_e2e.py       # 端到端验证脚本
├── agents.md                # AI 编码约束（最高优先级）
├── P0P1P2升级计划.md        # 做深若依 D1-D5 计划（当前有效）
├── trae_prompt.md           # Trae 长程任务提示词（当前有效）
├── 开发方案.md              # 初期插件化重构方案（历史参考）
└── 后续开发方案.md          # 早期多 CMS 扩充规划（已废弃）
```

---

## 做深若依路线（2026-07-18 起）

| 阶段 | 内容 | 优先级 |
|------|------|--------|
| D4 | real-ruoyi 自动化验收 + 删签名 marker 循环验证 | 高（建基线） |
| D1 | 登录链打通（v4 Session + v5 JWT 双链路） | 高 |
| D2 | 多版本 POC 适配（4.2 / 4.7 / v5） | 高 |
| D5 | 误报率实测（10 个非若依站，假阳率 < 5%） | 高 |
| D3 | 验证码处理（OCR / 绕过 / 跳过 三模式） | 中 |
| D8 | 报告增强（PDF/Word/Excel + 结果去重聚合） | 高（已完成） |
| D6 | 漏洞利用链编排（DAG 拓扑 + 条件分支 + 失败策略） | 高（已完成） |
| D7 | WAF 自动绕过执行（11 策略 + 三态判定保护矩阵 + 成功率追踪） | 高（已完成） |
| D9 | Web API REST 接口（FastAPI + WebSocket + Alpine.js 控制台） | 高（已完成） |

详见 [`P0P1P2升级计划.md`](P0P1P2升级计划.md)。

---

## 测试

```bash
# 单元测试
python -m pytest tests/ -q

# 若依插件回归
python tests/regression_ruoyi.py

# Spring 插件回归
python tests/regression_spring.py

# 签名靶场对拍
LAB_MODE=vuln LAB_PORT=8090 python lab/server.py &
python main.py -p http://127.0.0.1:8090/   # 期望全 CONFIRMED
```

---

## 已抽离内容

以下 CMS 插件包已于 2026-07-18 抽离至 [`../cms-scan-extras/`](../cms-scan-extras/)，不再维护：

- `thinkphp`（12 POC）+ 签名靶场 + 真实 PHP 靶场 + 验证报告
- `weaver`（11 POC）+ 签名靶场 + 回归测试
- `shiro`（7 POC）
- `struts2`（8 POC）
- `nuclei` 桥接 + `core/nuclei_adapter.py` + pyyaml 依赖

抽离原因：POC 广而浅，真实命中率低，稀释项目可信度。详见 [`../cms-scan-extras/README.md`](../cms-scan-extras/README.md)。

---

## 安全与合规

本工具仅用于**授权范围内**的安全测试与学习研究。不得用于未授权目标。涉及利用的插件默认仅做存在性验证，不做实际破坏。

---

## 文档导航

- [`agents.md`](agents.md) — AI 编码约束（最高优先级，Trae 必读）
- [`P0P1P2升级计划.md`](P0P1P2升级计划.md) — 做深若依 D1-D5 计划（当前有效）
- [`trae_prompt.md`](trae_prompt.md) — Trae 长程任务提示词（当前有效）
- [`lab/REAL-RUOYI.md`](lab/REAL-RUOYI.md) — 真实 RuoYi 4.7.8 验证报告
- [`lab/REAL-SPRING.md`](lab/REAL-SPRING.md) — 真实 Spring 验证报告
- [`lab/VULN-REINTRODUCE.md`](lab/VULN-REINTRODUCE.md) — RuoYi 漏洞重引入指南
- [`开发方案.md`](开发方案.md) — 初期插件化重构方案（历史参考）
- [`后续开发方案.md`](后续开发方案.md) — 早期多 CMS 扩充规划（已废弃）
