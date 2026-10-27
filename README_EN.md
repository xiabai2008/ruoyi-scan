# Ruoyi-Scan · RuoYi-focused Vulnerability Scanner

[![CI](https://github.com/xiabai2008/ruoyi-scan/actions/workflows/ci.yml/badge.svg)](https://github.com/xiabai2008/ruoyi-scan/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/ruoyi-scan)](https://pypi.org/project/ruoyi-scan/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> A **RuoYi-specific** vulnerability scanner for authorized security testing. 54 POC plugins,
> 5 RuoYi variant fingerprints, 20 Java component CVE checks — and only three verdicts:
> **CONFIRMED / SAFE / UNKNOWN**.
>
> `pip install -U ruoyi-scan` — or grab the [single-file desktop build](https://github.com/xiabai2008/ruoyi-scan/releases/latest) (Windows, no Python needed).

[中文文档](README.md) · [Docs site](https://xiabai2008.github.io/ruoyi-scan/)

<p align="center">
  <img src="https://raw.githubusercontent.com/xiabai2008/ruoyi-scan/main/docs/images/report-overview.png" alt="Scan report: risk distribution + MLPS 2.0 / OWASP mapping" width="900" />
</p>

> Real HTML report from a single `-p` run (v1.5.2 against the bundled signature lab): risk distribution,
> MLPS 2.0 / OWASP clause hits, 20 confirmed findings — the report itself is the deliverable, in 7 formats
> (HTML/JSON/CSV/PDF/Word/Excel/SARIF).

---

## Why not just use nuclei / xray?

Generic scanners tell you "something might be here". Ruoyi-Scan gives a verdict you can put in a report:

| | Generic scanners | Ruoyi-Scan |
|---|---|---|
| Not vulnerable | Absent from the report; you can't tell if it was tested | `SAFE` — tested and ruled out |
| Network error / WAF block / captcha | error or skipped | `UNKNOWN` — **never silently reported as SAFE** |
| Evidence | signature match | structured validation + proof (file content read back, injection marker) |

This discipline is testable: the bundled signature lab runs in `vuln` and `safe` modes, and CI /
nightly acceptance assert "20 confirmed findings in vuln mode" and "zero false positives in safe mode".
Per-plugin verification level (L1 lab / L2 real response / L3 real software, both directions) is public
in [docs/verification-matrix.md](docs/verification-matrix.md).

## Quick start

```bash
pip install -U ruoyi-scan

ruoyi-scan -p http://target:8080/                       # POC verification only (fast)
ruoyi-scan -u http://target:8080/                       # full scan: fingerprint → dir → POC → weak creds
ruoyi-scan -u http://target:8080/ --report ./reports --report-format all
```

Real output (v1.5.2, against the bundled signature lab):

<p align="center">
  <img src="https://raw.githubusercontent.com/xiabai2008/ruoyi-scan/main/docs/images/cli-demo.png" alt="CLI output: green = confirmed, red = not vulnerable, yellow = undetermined" width="780" />
</p>

Every line is one verdict, colored by state; the tail prints the summary, dedup stats and report path.

## Reports

<p align="center">
  <img src="https://raw.githubusercontent.com/xiabai2008/ruoyi-scan/main/docs/images/report-findings.png" alt="Report detail: evidence, remediation advice, fix details, repro command, compliance mapping" width="900" />
</p>

Each finding carries evidence (status code + matched keyword / reflected content), remediation advice,
fix details (nginx / Apache / IIS snippets and code changes), a repro command, CVE / CVSS and compliance
mapping (MLPS clause + OWASP category).

## Modes

| Mode | Command | Description |
|---|---|---|
| POC check | `-p <url>` | Vulnerability verification only; fast, low request count |
| Full scan | `-u <url>` | Fingerprint → directory scan → POC → weak-password brute force |
| Directory scan | `-m <url>` | Sensitive paths, admin panels, actuator endpoints |
| Login brute force | `-l <url>` | Druid / default admin credentials (`--pass-level top100` to narrow) |

Batch: `ruoyi-scan -f targets.txt -p --report ./reports`. All flags: [docs/usage.md](docs/usage.md).

## Capabilities

- **Detection** — 54 POCs: RuoYi 20 (incl. 2 Plus-variant only) / Spring Boot 14 / generic 12 / JeecgBoot 8;
  5 variant fingerprints (Vue3 / App / Plus / Cloud-Plus / Magic); 20 Java component→CVE checks;
  11 WAF bypass strategies + optional stealth transport; nuclei YAML compatible (`--nuclei`)
- **Delivery** — 7 report formats (HTML/JSON/CSV/PDF/Word/Excel/SARIF), MLPS 2.0 / OWASP mapping sections,
  docx template engine, remediation re-test, SARIF for GitHub Code Scanning
- **Engineering** — FastAPI + WebSocket API with RBAC and scheduled scans, single-exe desktop app, Docker,
  plugin SDK + community template repo with enforced Ed25519 signatures
- **Runnable labs** — signature lab / behaviour-level simulation (captcha + CSRF + diff-based verdicts) /
  adversarial network (WAF, rate limit, soft-404) / real Docker stack (RuoYi 4.7.8 + MySQL + nginx + ModSecurity).
  8 real-world usage scenarios are scripted in `scripts/scenario_audit.py`; see [lab/SCENARIO-AUDIT.md](lab/SCENARIO-AUDIT.md)

## Install options

| Form | How | Notes |
|---|---|---|
| pip | `pip install -U ruoyi-scan` | Recommended; optional extras: `ruoyi-scan[report,serve]` |
| Desktop | `ruoyi-scan-desktop.exe` from [Releases](https://github.com/xiabai2008/ruoyi-scan/releases/latest) | ~49 MB, engine + 54 POCs embedded, no install |
| Docker | `docker build -t ruoyi-scan .` or `docker compose up -d` | Multi-stage, non-root; compose ships two signature labs |

## Desktop app

<p align="center">
  <img src="https://raw.githubusercontent.com/xiabai2008/ruoyi-scan/main/docs/images/desktop-app.png" alt="Desktop app: task list, scan config, live results and reports" width="900" />
</p>

> Single-file Windows exe (Tauri + WebView2): engine and 54 POCs embedded; new scan, live results and report
> archiving in one window. The engine subprocess is bound to a JobObject, so killing the app leaves no orphans.

## Documentation

[Quick start](docs/quickstart.md) · [User manual](docs/usage.md) · [Plugin development](docs/plugin_dev.md) ·
[Verification matrix](docs/verification-matrix.md) · [Desktop](docs/desktop.md) · [API](docs/api.md) ·
[DevSecOps](docs/devsecops.md) · [Online docs](https://xiabai2008.github.io/ruoyi-scan/)

## Compliance

For **authorized** security testing and vulnerability verification only — existence checks, no destructive
exploitation. You are responsible for complying with applicable laws; testing systems without permission is illegal.

## License

[MIT](LICENSE) © XIABAI
