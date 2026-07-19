# Ruoyi-Scan — 若依专项漏洞扫描工具

> 一款合法授权的**若依（RuoYi）专项漏洞扫描器**，插件化架构，三态判定（CONFIRMED / SAFE / UNKNOWN）。
> 支持批量扫描、多格式报告、WAF 绕过、漏洞利用链、Web API 等企业级特性。

---

## 项目定位

- **作者**：XIABAI
- **版本**：1.1.0
- **仓库**：https://github.com/xiabai2004/Ruoyi-Scan
- **技术栈**：Python 3.8+ / requests / FastAPI / Docker
- **许可**：MIT License

---

## 核心能力

| 模块 | 说明 |
|------|------|
| `plugins/ruoyi/` | 若依 16 个 POC（文件读取、SQL 注入、RCE、SSTI、未授权等） |
| `plugins/spring/` | Spring Boot 14 个 POC（Actuator、Gateway、Jolokia、Spring4Shell 等） |
| `plugins/common/` | 通用漏洞包（.git/.env 泄露、备份文件、CORS、Swagger 等） |
| 指纹识别 | favicon hash + 特征路径 + 关键字，多 CMS 数据驱动 |
| 三态判定 | CONFIRMED（确认存在）/ SAFE（确认不存在）/ UNKNOWN（无法判定） |
| WAF 绕过 | 11 种绕过策略 + 三态判定保护矩阵 + 成功率追踪 |
| 漏洞利用链 | DAG 拓扑编排 + 条件分支 + 3 条内置链 |
| 批量扫描 | `-f targets.txt` 多目标 + 批量汇总报告 |
| 报告输出 | HTML（SVG 图表）/ JSON / CSV / PDF / Word / Excel / SARIF |
| Web API | FastAPI REST + WebSocket 实时推送 + Web 控制台 |
| 并发限速 | ThreadPoolExecutor + 令牌桶（锁外 sleep，无并发退化） |
| 验证码处理 | 自动探测 / OCR 识别 / 跳过 三模式 |
| 多版本适配 | RuoYi 4.2 / 4.7 / v5 版本感知 POC 过滤 |
| 端口扫描 | TCP 端口扫描 + 服务识别 + Banner 抓取 |
| 被动代理 | HTTP/HTTPS 代理，捕获流量自动扫描 |

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

# WAF 绕过（检测到 WAF 自动启用）
python main.py -p http://target:8080/ --bypass-waf auto

# 执行漏洞利用链
python main.py --chain ruoyi_sql_to_rce -u http://target:8080/
python main.py --chain list  # 列出可用链

# Web API 服务
python main.py --serve
# 访问 http://localhost:8000/ (Web 控制台)
# 访问 http://localhost:8000/docs (OpenAPI 文档)

# 端口扫描 + 漏洞检测
python main.py -p http://target:8080/ --portscan

# 被动代理模式
python main.py --passive --passive-port 8080

# Docker 部署
docker-compose up -d
```

### CLI 参数速查

| 参数 | 说明 |
|------|------|
| `-h` | 帮助信息 |
| `-u <url>` | 综合扫描（目录+漏洞+爆破） |
| `-m <url>` | 目录扫描 |
| `-p <url>` | 漏洞检测 |
| `-l <url>` | 登录爆破 |
| `-f <file>` | 批量扫描（从文件读取目标列表） |
| `--cms <ruoyi\|spring>` | 手动指定 CMS |
| `--proxy <url>` | 代理地址 |
| `--threads <n>` | 并发线程数 |
| `--rate <n>` | 每秒请求数（0=不限速） |
| `--report <dir>` | 报告输出目录 |
| `--report-format <f>` | 报告格式（html/json/csv/pdf/docx/xlsx/sarif） |
| `--timeout <n>` | 请求超时秒数 |
| `--debug` | 调试模式 |
| `--chain <name>` | 执行漏洞利用链 |
| `--bypass-waf <auto\|on\|off>` | WAF 绕过策略 |
| `--portscan` | 端口扫描 |
| `--passive` | 被动代理模式 |
| `--serve` | 启动 Web API 服务 |
| `--template <name>` | 扫描模板（quick/deep/compliance/dengbao） |
| `--config <path>` | YAML 配置文件 |

---

## 目录结构

```
Ruoyi-Scan/
├── main.py                  # CLI 入口（~390 行，纯参数解析+分发）
├── config/settings.py       # 全局配置
├── core/                    # 核心引擎层
│   ├── runner.py            # 扫描编排器（P0 拆分）
│   ├── engine.py            # 并发编排+令牌桶限速
│   ├── models.py            # 数据模型（三态判定）
│   ├── loader.py            # 插件动态发现
│   ├── fingerprint.py       # 指纹识别
│   ├── router.py            # 指纹→插件路由
│   ├── session.py           # 会话封装
│   ├── chain.py             # 漏洞利用链引擎
│   ├── report.py            # 报告渲染（HTML/JSON/CSV）
│   └── ...                  # 更多核心模块
├── plugins/                 # 插件系统
│   ├── base.py              # PluginBase 抽象基类
│   ├── ruoyi/               # 若依 16 个 POC
│   ├── spring/              # Spring 14 个 POC
│   ├── common/              # 通用 8 个 POC
│   └── chain/               # 3 条利用链
├── lib/                     # 工具库（26 个模块）
├── api/                     # Web API（FastAPI + WebSocket）
├── data/                    # 字典文件
├── tests/                   # 39 个测试文件 / 871 条用例
├── lab/                     # 靶场环境
├── web/                     # Web 控制台前端
├── monitoring/              # Grafana + Prometheus
├── .github/workflows/       # CI 配置
├── Dockerfile               # Docker 镜像
├── docker-compose.yml       # Docker 编排
├── LICENSE                  # MIT License
└── requirements.txt         # 依赖管理
```

---

## 测试

```bash
# 全量测试
python -m pytest tests/ -q

# 若依插件回归
python tests/regression_ruoyi.py

# Spring 插件回归
python tests/regression_spring.py
```

---

## 安全与合规

本工具仅用于**授权范围内**的安全测试与学习研究。不得用于未授权目标。涉及利用的插件默认仅做存在性验证，不做实际破坏。

---

## License

MIT License © 2026 XIABAI
