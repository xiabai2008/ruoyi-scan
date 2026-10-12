# Release 发布 SOP（F8）

## 版本节奏

- **语义化版本**：`vMAJOR.MINOR.PATCH`
  - PATCH：bug 修复（`v1.1.1`）
  - MINOR：新功能（`v1.2.0`）
  - MAJOR：破坏性变更（`v2.0.0`）
- 每次变更同步 `CHANGELOG.md` + 全部版本位：`config/settings.py`、`pyproject.toml`、`desktop/package.json(+lock)`、`desktop/src-tauri/Cargo.toml(+lock)`、`desktop/src-tauri/tauri.conf.json`，以及 README / docs 中的版本引用

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

## 消费者校验

```bash
# 下载后校验完整性
sha256sum -c checksums.txt
pip install ruoyi_scan-<version>-py3-none-any.whl
```
