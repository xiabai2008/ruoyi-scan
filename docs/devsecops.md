# DevSecOps 集成指南（E6）

Ruoyi-Scan 提供三层 CI/CD 集成能力：
1. **CI 模式**（`--ci`）：按严重度阈值决定退出码（0=通过 / 1=发现漏洞 / 2=错误）
2. **SARIF 2.1.0 输出**（`--report-format sarif`）：对接 GitHub Code Scanning
3. **模板生成**（`--ci-init github|gitlab|jenkins`）：一键生成流水线配置

## GitHub Code Scanning（推荐）

仓库已内置 `.github/workflows/security-scan.yml`：
- **PR 触发**：每次 PR 自动扫描，高危漏洞直接在 PR 安全标签页展示
- **定时触发**：每周一凌晨 2 点全量扫描
- **SARIF 上传**：`github/codeql-action/upload-sarif@v3` 上传 `reports/report.sarif`
- **阈值**：`--severity-threshold high`（可调 low/medium/high）

使用前在仓库 Settings → Secrets 配置 `SCAN_TARGET`（授权扫描目标）。

```bash
# 手动生成/更新 workflow
python main.py --ci-init github
```

## GitLab CI

```bash
python main.py --ci-init gitlab
```

- 扫描结果作为 CI artifact 归档
- 高危漏洞导致流水线失败（退出码 1）
- 配置 `SCAN_TARGET` CI/CD 变量

## Jenkins

```bash
python main.py --ci-init jenkins
```

- 生成 `Jenkinsfile`（Pipeline 语法）
- 与 GitLab CI 相同语义

## 与 GitHub CodeQL 共存

本 workflow 与 CodeQL（静态分析）互不冲突：
- CodeQL：分析仓库**源代码**漏洞（SAST）
- Ruoyi-Scan：检测**运行中的目标**漏洞（DAST，外部授权目标）
- 两者结果在 GitHub Security 标签页并列展示

## 最佳实践

1. **授权目标**：只扫描你拥有或获书面授权的主机（`SCAN_TARGET` secret 管理）
2. **阈值策略**：上线期用 high，稳定后用 medium 逐步收紧
3. **组件检测**：`--components` 自动比对 fastjson/SpringBoot/Shiro/Nacos/Log4j 版本 CVE，CI 建议开启
4. **报告留存**：artifacts 保留 7 天，配合 `--diff` 基线对比跟踪修复进度
