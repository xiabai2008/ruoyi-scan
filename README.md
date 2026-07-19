# Ruoyi-Scan — 若依专项漏洞扫描工具

> 一款合法授权的**若依（RuoYi）专项漏洞扫描器**，插件化架构，三态判定，支持批量扫描与多格式报告。

---

## 项目定位

针对若依（RuoYi）系统框架的综合漏洞检测工具，专注做深而非做宽。

- **作者**：XIABAI
- **版本**：1.1.0
- **技术栈**：Python 3 + `requests`，命令行工具，控制台彩色输出
- **许可证**：MIT

---

## 当前能力

| 模块 | 说明 |
|------|------|
| `plugins/ruoyi/` | 若依 16 个 POC（核心，做深方向） |
| `plugins/spring/` | Spring Boot 14 个 POC（协同，与若依生态强相关） |
| `plugins/common/` | 通用漏洞包（.git/.env/备份/CORS 等，不依赖 CMS 指纹） |
| 指纹识别 | favicon hash + 特征路径 + 登录页关键字，数据驱动 |
| 批量扫描 | `-f targets.txt`，批量汇总报告 |
| 报告 | HTML（SVG 图表）/ JSON / CSV / PDF / Word / Excel / SARIF（可选依赖降级） |
| 并发限速 | ThreadPoolExecutor + 令牌桶（锁外 sleep，无并发退化） |
| 三态判定 | CONFIRMED / SAFE / UNKNOWN，网络异常绝不判 SAFE |
| WAF 绕过 | 11 种绕过策略 + 三态判定保护矩阵 + 策略成功率追踪 |
| Web API | FastAPI REST + WebSocket 实时推送 + Alpine.js 控制台 |
| 漏洞利用链 | DAG 拓扑编排 + 条件分支 + 失败策略 |

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

# 生成全格式报告
python main.py -p http://target:8080/ --report ./reports --report-format all

# 执行漏洞利用链
python main.py --chain ruoyi_sql_to_rce -u http://target:8080/
python main.py --chain list  # 列出可用链

# WAF 绕过
python main.py -p http://target:8080/ --bypass-waf auto

# Web API 服务
python main.py --serve
# 访问 http://localhost:8000/         Web 控制台
# 访问 http://localhost:8000/docs     OpenAPI 文档
```

**主要 CLI 参数**：`-h` 帮助 / `-u` 综合扫描 / `-m` 目录扫描 / `-p` 漏洞检测 / `-l` 登录爆破 / `-f` 批量 / `--cms` 指定 CMS / `--threads` 并发 / `--rate` 限速 / `--proxy` 代理 / `--report` 报告 / `--chain` 利用链 / `--serve` Web API / `--passive` 被动代理 / `--portscan` 端口扫描

---

## 目录结构

```
Ruoyi-Scan/
├── main.py                  # CLI 入口
├── config/settings.py       # 全局配置
├── core/                    # 引擎/路由/指纹/会话/报告/缓存/编排器
├── plugins/                 # 插件包（ruoyi + spring + common）
├── lib/                     # 工具库（WAF绕过/爬虫/子域名/分布式等）
├── data/                    # 字典文件
├── api/                     # Web API（FastAPI + WebSocket）
├── chains/                  # 漏洞利用链定义
├── lab/                     # 靶场环境
├── tests/                   # 单元测试 + 回归测试
├── LICENSE                  # MIT License
├── requirements.txt         # 依赖管理
└── README.md
```

---

## 测试

```bash
# 全部单元测试
python -m pytest tests/ -q

# 若依插件回归
python tests/regression_ruoyi.py

# Spring 插件回归
python tests/regression_spring.py

# 签名靶场对拍
LAB_MODE=vuln LAB_PORT=8090 python lab/server.py &
python main.py -p http://127.0.0.1:8090/
```

---

## Docker 部署

```bash
docker-compose up -d
```

---

## 安全与合规

本工具仅用于**授权范围内**的安全测试与学习研究。不得用于未授权目标。涉及利用的插件默认仅做存在性验证，不做实际破坏。

---

## 相关链接

- 作者：XIABAI
- GitHub：https://github.com/xiabai2004/Ruoyi-Scan
