# Release 发布 SOP（F8）

## 版本节奏

- **语义化版本**：`vMAJOR.MINOR.PATCH`
  - PATCH：bug 修复（`v1.1.1`）
  - MINOR：新功能（`v1.2.0`）
  - MAJOR：破坏性变更（`v2.0.0`）
- 每次变更同步 `CHANGELOG.md` + 全部版本位：`config/settings.py`、`pyproject.toml`、`desktop/package.json(+lock)`、`desktop/src-tauri/Cargo.toml(+lock)`、`desktop/src-tauri/tauri.conf.json`，以及 README / docs 中的版本引用

## 定期维护节奏

> 维护是常态化的：签名数据会过期、靶场基线会漂移、依赖会有新 CVE。
> 下表固定「什么时候做什么」，避免问题积压到发布前才暴露。

| 周期 | 事项 | 具体动作 |
|------|------|---------|
| 每次合并 | 代码门禁（自动） | ruff + mypy 硬门禁、双平台测试矩阵、`verification_matrix.py --check`、覆盖率棘轮——均由 `ci.yml` 自动执行，无需人工 |
| 每周 | 流水线巡检 | ① 巡检 Nightly Acceptance（失败自动开 issue，当天分诊，不留过夜红灯）；② 处理 dependabot PR（pip / Actions；web 的 npm 与 desktop 的 Cargo 依赖人工月度检查）；③ issue / PR 分诊，收集误报线索 |
| 每月 | 数据与安全 | ① CVE 同步：`--cve-sync` 后核对 `data/cve_offline.json`、`data/component_cve_map.json` 提 PR；② 口令字典补充（`data/password.txt` / `pass_top100.txt`，随新泄漏字典发布同步）；③ 依赖漏洞扫描（`pip-audit` / OSV）；④ 完整安全审计（复盘 CodeQL / Scorecard / 扫描钩子结论）；⑤ 有变更则发 PATCH 版本 |
| 每季度 | 版本与回归 | ① MINOR 版本发布（按需）；② WAF 特征与指纹/版本表复核（`core/waf_features.py`、`core/fingerprint_features.py`、`core/ruoyi_versions.py`），覆盖 RuoYi 新变体与新年份；③ 误报回归库扩充：把线上 issue 暴露的误报目标沉淀为 `lab/fp_lab/` 新用例；④ 刷新 README 截图 / 演示 GIF / `docs/wiki/`（UI、CLI 输出或架构有变化时必做）；⑤ 复核支持策略（旧 minor 停更公告） |
| 每个大版本 | 路线校准 | ① 按实际发布节奏校准 `ROADMAP.md` 阶段状态与指标；② 复核三条底线与检测范围，防止范围蔓延；③ 评估依赖下限与废弃参数清理 |

### 两条硬规则

1. **新增 CONFIRMED 判定必须同步验收基线**
   插件新增或收紧判定后，`data/acceptance_baseline.json` 的 `expected_confirmed` / `allowed_confirmed`
   必须同步更新并递增基线 `version`——否则 Nightly Acceptance 会把正常判定报成「误报」，门禁失去意义
   （曾出现：`定时任务任意文件读取` 未收录导致 nightly 持续报误报）。
2. **版本号全部位对齐后才可打 tag**
   以脚本或测试校验 `config/settings.py` / `pyproject.toml` / `desktop/*` / `CHANGELOG.md` 顶部一致
   （见「版本节奏」列出的全部版本位），避免手工多提交同步漂移。

### 维护留痕

定期维护在对应 issue 或 `CHANGELOG.md` 的 `Unreleased` 段留痕（数据刷新批次、审计结论、误报处理），
便于下一位维护者接续；季度级的回归库扩充与媒体刷新建议在 release-notes 中提及。

## 发布步骤

### 1. 本地构建验证

```bash
./scripts/build_release.sh 1.2.0
```

- 产出 `dist/*.whl`、`dist/*.tar.gz`、`dist/checksums.txt`
- 验证 whl 可安装、可运行

### 2. 编写发布说明（推荐）

在 `release-notes/<tag>.md`（如 `release-notes/v1.5.0.md`）写**面向用户**的版本说明：
亮点速览、行为变更提醒、安装/升级方式。`release.yml` 会将其作为 GitHub Release 正文；
未提供该文件时自动回退 GitHub 生成的变更说明。

### 3. 提交 + 打 tag

```bash
git add -A && git commit -m "release: v1.2.0 — 变更摘要"
git tag v1.2.0
git push && git push --tags
```

### 4. CI 自动发布

push tag 后 GitHub Actions（`release.yml`）自动：
- 构建 wheel + sdist
- 生成 `checksums.txt`（SHA256）
- 创建 Release + 附件上传（正文优先采用 `release-notes/<tag>.md`，缺省回退自动生成）

### 5. 发布后检查

- [ ] Release 页面附件完整（whl/tar.gz/checksums.txt）
- [ ] README badge 正常
- [ ] `pip install ruoyi_scan-<version>-py3-none-any.whl` 安装成功
- [ ] `--plugin-update` 模板仓库仍可用（若插件有变更需同步重新签名 manifest）
- [ ] 发布后首个 Nightly Acceptance 运行为绿
- [ ] 本次含插件 / UI / CLI 输出变更时，验收基线（`data/acceptance_baseline.json`）与 README 演示媒体已同步

## 消费者校验

```bash
# 下载后校验完整性
sha256sum -c checksums.txt
pip install ruoyi_scan-<version>-py3-none-any.whl
```
