# Ruoyi-Scan — RuoYi Dedicated Vulnerability Scanner

[English](README_EN.md) | [中文](README.md)

[![CI](https://github.com/xiabai2004/Ruoyi-Scan/actions/workflows/ci.yml/badge.svg)](https://github.com/xiabai2004/Ruoyi-Scan/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![Coverage](https://codecov.io/gh/xiabai2004/Ruoyi-Scan/branch/main/graph/badge.svg)](https://codecov.io/gh/xiabai2004/Ruoyi-Scan)

> A legally authorized **RuoYi-dedicated vulnerability scanner** with a plugin-based architecture and three-state verdict (CONFIRMED / SAFE / UNKNOWN).
> Supports enterprise-grade features such as batch scanning, multi-format reporting, WAF bypass, exploit chains, and a Web API.

---

## Project Overview

- **Author**: XIABAI
- **Version**: 1.1.0
- **Repository**: https://github.com/xiabai2004/Ruoyi-Scan
- **Tech Stack**: Python 3.8+ / requests / FastAPI / Docker
- **License**: MIT License

---

## Core Capabilities

| Module | Description |
|--------|-------------|
| `plugins/ruoyi/` | 16 RuoYi POCs (file read, SQL injection, RCE, SSTI, unauthorized access, etc.) |
| `plugins/spring/` | 14 Spring Boot POCs (Actuator, Gateway, Jolokia, Spring4Shell, etc.) |
| `plugins/common/` | Common vulnerability package (.git/.env leakage, backup files, CORS, Swagger, etc.) |
| Fingerprinting | favicon hash + signature paths + keywords, multi-CMS data-driven |
| Three-state verdict | CONFIRMED (confirmed present) / SAFE (confirmed absent) / UNKNOWN (cannot be determined) |
| WAF bypass | 11 bypass strategies + three-state verdict protection matrix + success-rate tracking |
| Exploit chains | DAG topological orchestration + conditional branches + 3 built-in chains |
| Batch scanning | `-f targets.txt` multi-target + aggregated summary report |
| Report output | HTML (SVG charts) / JSON / CSV / PDF / Word / Excel / SARIF |
| Web API | FastAPI REST + WebSocket real-time push + Web console |
| Concurrency & rate limiting | ThreadPoolExecutor + token bucket (sleep outside lock, no concurrency degradation) |
| CAPTCHA handling | Auto-detect / OCR recognition / skip — three modes |
| Multi-version adaptation | RuoYi 4.2 / 4.7 / v5 version-aware POC filtering |
| Port scanning | TCP port scan + service identification + banner grabbing |
| Passive proxy | HTTP/HTTPS proxy, captures traffic for automatic scanning |
| OAST out-of-band detection | Self-hosted callback server + 6 payload templates (SSRF/XXE/blind SQLi/blind RCE/LDAP/command injection) |
| Business logic detection | IDOR / privilege escalation / parameter tampering / race condition — 4 detector types |
| CVE sync | NVD REST API + 24h TTL cache + CWE→OWASP/MLPS compliance mapping |
| SIEM integration | ECS / CEF / LEEF / JSON — 4 export formats + Syslog forwarding |
| Async engine | ThreadPoolExecutor concurrent scanning + aiohttp optional async HTTP |
| Distributed scanning | Redis Master-Worker queue + Standalone fallback mode |
| Result caching | SQLite persistence + SHA256 key + TTL + hit-rate statistics |
| Scan templates | quick / deep / compliance / dengbao — 4 preset strategies |
| Authenticated scanning | Cookie / Token / Bearer / auto-login — 4 auth injection types |
| Internationalization | Chinese/English report switching (`--lang zh|en`) |
| Plugin SDK | Template generation + validation + enumeration (`--plugin-init` / `--plugin-check`) |
| CI/CD integration | Severity-threshold exit + GitHub/GitLab/Jenkins template generation |
| Vulnerability knowledge base | Offline HTML Wiki + JSON API |

---

## Quick Start

```bash
# Install dependencies (core + reporting + Web API)
pip install -r requirements.txt

# Optional feature dependencies (install on demand)
pip install pyyaml          # --config YAML configuration file
pip install redis           # --distributed Redis distributed scanning
pip install aiohttp         # --async async HTTP client

# Single-target vulnerability scan
python main.py -p http://target:8080/

# Batch scanning
python main.py -f targets.txt -p --report ./reports

# Manually specify CMS (skip fingerprinting)
python main.py -p http://target:8080/ --cms ruoyi

# Comprehensive scan (directory scan + vulnerability detection + login brute force)
python main.py -u http://target:8080/

# Generate all-format reports (HTML/JSON/CSV/PDF/Word/Excel)
python main.py -p http://target:8080/ --report ./reports --report-format all

# WAF bypass (auto-enabled when a WAF is detected)
python main.py -p http://target:8080/ --bypass-waf auto

# Execute exploit chain
python main.py --chain ruoyi_sql_to_rce -u http://target:8080/
python main.py --chain list  # List available chains

# Web API service
python main.py --serve
# Visit http://localhost:8000/ (Web console)
# Visit http://localhost:8000/docs (OpenAPI docs)

# Port scan + vulnerability detection
python main.py -p http://target:8080/ --portscan

# Passive proxy mode
python main.py --passive --passive-port 8080

# Docker deployment (see the "Docker Deployment" section below)
# docker-compose up -d
```

### Docker Deployment

Ruoyi-Scan provides a production-ready Docker image (multi-stage build, non-root user).

**Build the image**

```bash
docker build -t ruoyi-scan .
```

**Scan a target**

```bash
# Basic scan
docker run --rm ruoyi-scan -p http://target/

# Scan and save the report to the host
docker run --rm -v $(pwd)/reports:/app/reports ruoyi-scan \
  -p http://target/ --report /app/reports
```

**Web API service**

```bash
# Start the FastAPI Web API (port 8000)
docker run --rm -p 8000:8000 ruoyi-scan --serve --host 0.0.0.0 --port 8000

# API with authentication
docker run --rm -p 8000:8000 -e RUOYI_SCAN_API_KEY=your-secret ruoyi-scan \
  --serve --host 0.0.0.0 --port 8000 --api-key your-secret
```

**Docker Compose one-click deployment**

```bash
# Start all services (scanner + API + 2 signed labs)
docker compose up -d

# Scan the built-in lab
docker compose run --rm scanner -p http://lab-ruoyi:8080/ --report /app/reports

# Start the monitoring stack (Prometheus + Grafana)
docker compose --profile monitor up -d
# Grafana: http://localhost:3000 (admin/admin)
# Prometheus: http://localhost:9090

# Clean up
docker compose down
```

| Service | Port | Description |
|---------|------|-------------|
| scanner | - | Scanner CLI (invoked via `docker compose run`) |
| api | 8000 | FastAPI Web API + WebSocket + Web console |
| lab-ruoyi | 8080 | RuoYi signed lab (vuln mode) |
| lab-spring | 8091 | Spring Boot signed lab (vuln mode) |
| prometheus | 9090 | Metrics collection (`--profile monitor`) |
| grafana | 3000 | Monitoring dashboard (`--profile monitor`) |

### CLI Parameter Reference

> For full parameter details, run `python main.py -h`. All parameters are grouped by function below.

#### Core Scan Modes

| Parameter | Description |
|-----------|-------------|
| `-h` | Help information |
| `-u <url>` | Comprehensive scan (directory + vulnerability + brute force) |
| `-m <url>` | Directory scan |
| `-p <url>` | Vulnerability detection |
| `-l <url>` | Login brute force |
| `-f <file>` | Batch scan (read target list from file) |
| `--cms <ruoyi\|spring>` | Manually specify CMS (skip fingerprinting) |
| `--pass-level <lvl>` | Password dictionary level top100/top1000/full |
| `--template <name>` | Scan template (quick/deep/compliance/dengbao) |
| `--template-list` | List all available templates |
| `--config <path>` | YAML configuration file (CLI parameters take precedence over config) |

#### Network & Concurrency

| Parameter | Description |
|-----------|-------------|
| `--proxy <url>` | Proxy address (e.g. http://127.0.0.1:8080) |
| `--proxy-file <f>` | Proxy pool file (one proxy URL per line) |
| `--proxy-rotate <s>` | Proxy rotation strategy round-robin/random/least-fail |
| `--threads <n>` | Number of concurrent threads |
| `--rate <n>` | Requests per second (0 = no rate limit) |
| `--timeout <n>` | Request timeout in seconds |
| `--debug` | Debug mode (request logs output to stderr) |

#### Information Gathering (D14)

| Parameter | Description |
|-----------|-------------|
| `--crawl` | Enable active crawler |
| `--crawl-depth <n>` | Maximum crawler depth (default 2) |
| `--crawl-max-pages <n>` | Maximum crawler pages (default 50) |
| `--subdomain` | Enable subdomain enumeration |
| `--js-extract` | Enable JS endpoint extraction |
| `--portscan` | Port scan + service identification |
| `--ports <p1,p2>` | Custom port list (comma-separated) |
| `--passive` | Start passive proxy mode |
| `--passive-host <addr>` | Proxy listen address (default 127.0.0.1) |
| `--passive-port <n>` | Proxy listen port (default 8080) |

#### Reporting & Output

| Parameter | Description |
|-----------|-------------|
| `--report <dir>` | Report output directory |
| `--report-format <f>` | Report format html/json/csv/pdf/docx/xlsx/sarif |
| `--no-dedup` | Disable result deduplication/aggregation |
| `--lang <zh\|en>` | Report language (default zh) |
| `--diff <old.json>` | Compare against a historical scan report |
| `--diff-only <old> <new>` | Only compare two JSON reports |
| `--save-baseline` | Save this scan result as a baseline |

#### WAF Bypass & Exploit Chains

| Parameter | Description |
|-----------|-------------|
| `--bypass-waf <auto\|on\|off>` | WAF bypass strategy (default auto) |
| `--chain <name>` | Execute an exploit chain |
| `--chain-list` | List all available exploit chains |

#### Authenticated Scanning (D26)

| Parameter | Description |
|-----------|-------------|
| `--auth <type=value>` | Authentication injection (can be specified multiple times) |
| `--auth-file <path>` | Load authentication info from file |
| `--auth-login <user:pass>` | Auto-login to obtain authentication |

#### Web API Service (D9/D11)

| Parameter | Description |
|-----------|-------------|
| `--serve` | Start Web API service (FastAPI + WebSocket + Web console) |
| `--host <addr>` | API service listen address (default 0.0.0.0) |
| `--port <n>` | API service listen port (default 8000) |
| `--api-key <key>` | API Key authentication |
| `--cors-origins <o>` | Allowed CORS origins (comma-separated) |
| `--db-path <path>` | SQLite task persistence database path |

> For detailed API endpoint descriptions, request/response examples, and WebSocket event formats, see the [API Usage Guide](docs/API.md).
> The OpenAPI 3.0 specification can be exported to `docs/openapi.json` via `python scripts/export_openapi.py`.

#### OAST Out-of-Band Detection (D30)

| Parameter | Description |
|-----------|-------------|
| `--oast` | Enable OAST out-of-band detection |
| `--oast-server` | Start the OAST callback server |
| `--oast-host <addr>` | OAST server listen address |
| `--oast-port <n>` | OAST server listen port |

#### Business Logic Detection (D31)

| Parameter | Description |
|-----------|-------------|
| `--logic-scan` | Business logic vulnerability detection (IDOR/privilege escalation/parameter tampering/race condition) |
| `--logic-endpoints <file>` | Business scan endpoint list file |
| `--logic-concurrency <n>` | Concurrency for race condition detection |

#### CVE Sync (D32)

| Parameter | Description |
|-----------|-------------|
| `--cve-sync` | Sync NVD CVE information |
| `--cve-id <CVE-ID>` | Query a single CVE |
| `--nvd-api-key <key>` | NVD API Key (improves rate limit) |

#### SIEM Integration (D33)

| Parameter | Description |
|-----------|-------------|
| `--siem-export <fmt>` | Export SIEM format (ecs/cef/leef/json) |
| `--siem-output <path>` | SIEM export path |
| `--siem-syslog <host:port>` | Send to a Syslog server |
| `--siem-protocol <p>` | Syslog protocol udp/tcp |

#### Async Engine (D34)

| Parameter | Description |
|-----------|-------------|
| `--async` | Enable async scan engine (ThreadPoolExecutor) |
| `--async-workers <n>` | Number of async concurrent threads (default 10) |

#### Web UI Console (D35)

| Parameter | Description |
|-----------|-------------|
| `--web-ui` | Generate a Web UI console (single-page HTML) |
| `--web-ui-output <path>` | Web UI output path |
| `--web-ui-api <url>` | API address the Web UI connects to |

#### Distributed Scanning (D36)

| Parameter | Description |
|-----------|-------------|
| `--distributed <mode>` | Distributed mode (master/worker/standalone) |
| `--redis-url <url>` | Redis connection URL |
| `--distributed-rate <n>` | Global distributed rate limit (requests per second, 0 = unlimited) |
| `--worker-max-tasks <n>` | Worker max tasks (0 = unlimited) |
| `--distributed-timeout <n>` | Distributed timeout in seconds (default 600) |

#### Result Caching (D37)

| Parameter | Description |
|-----------|-------------|
| `--cache` | Enable scan result caching (SQLite) |
| `--cache-ttl <n>` | Cache TTL in seconds (default 3600) |
| `--cache-db <path>` | Cache database path |
| `--cache-stats` | View cache statistics |
| `--cache-clear` | Clear expired cache |
| `--cache-clear-all` | Clear all cache |

#### Notifications (D21)

| Parameter | Description |
|-----------|-------------|
| `--notify <type=target>` | Scan completion notification (can be specified multiple times) |

#### Plugin SDK (D25)

| Parameter | Description |
|-----------|-------------|
| `--plugin-init <name>` | Generate a plugin template |
| `--plugin-check <path>` | Validate plugin file integrity |
| `--plugin-list` | List all loaded plugins |
| `--category <cat>` | Plugin category ruoyi/spring/common |

#### CI/CD Integration (D28)

| Parameter | Description |
|-----------|-------------|
| `--ci` | CI mode (non-zero exit code when severity exceeds threshold) |
| `--severity-threshold <lvl>` | CI failure threshold low/medium/high (default high) |
| `--ci-init <platform>` | Generate CI config (github/gitlab/jenkins) |

#### Vulnerability Knowledge Base (D29)

| Parameter | Description |
|-----------|-------------|
| `--wiki` | Generate vulnerability knowledge base (HTML Wiki + JSON API) |
| `--wiki-output <path>` | Knowledge base output path |

---

## Directory Structure

```
Ruoyi-Scan/
├── main.py                  # CLI entry point (~390 lines, pure arg parsing + dispatch)
├── config/settings.py       # Global configuration
├── core/                    # Core engine layer
│   ├── runner.py            # Scan orchestrator (P0 split)
│   ├── engine.py            # Concurrency orchestration + token-bucket rate limiting
│   ├── models.py            # Data models (three-state verdict)
│   ├── loader.py            # Dynamic plugin discovery
│   ├── fingerprint.py       # Fingerprinting
│   ├── router.py            # Fingerprint → plugin routing
│   ├── session.py           # Session wrapper
│   ├── chain.py             # Exploit chain engine
│   ├── report.py            # Report rendering (HTML/JSON/CSV)
│   └── ...                  # More core modules
├── plugins/                 # Plugin system
│   ├── base.py              # PluginBase abstract base class
│   ├── ruoyi/               # 16 RuoYi POCs
│   ├── spring/              # 14 Spring POCs
│   ├── common/              # 8 common POCs
│   └── chain/               # 3 exploit chains
├── lib/                     # Utility library (31 modules)
├── api/                     # Web API (FastAPI + WebSocket)
├── data/                    # Dictionary files
├── tests/                   # 38 test files / 887 test cases
├── lab/                     # Lab environments
├── web/                     # Web console frontend
├── monitoring/              # Grafana + Prometheus
├── .github/workflows/       # CI configuration
├── Dockerfile               # Docker image
├── docker-compose.yml       # Docker Compose
├── LICENSE                  # MIT License
└── requirements.txt         # Dependency management
```

---

## Testing

```bash
# Full test suite
python -m pytest tests/ -q

# RuoYi plugin regression
python tests/regression_ruoyi.py

# Spring plugin regression
python tests/regression_spring.py
```

---

## Security & Compliance

This tool is intended solely for **authorized** security testing and research. It must not be used against unauthorized targets. Exploitation-related plugins perform existence verification only and do not cause actual damage by default.

---

## License

MIT License © 2026 XIABAI
