# Release 发布 SOP（F8）

## 版本节奏

- **语义化版本**：`vMAJOR.MINOR.PATCH`
  - PATCH：bug 修复（`v1.1.1`）
  - MINOR：新功能（`v1.2.0`）
  - MAJOR：破坏性变更（`v2.0.0`）
- 每次变更同步 `CHANGELOG.md` + `config/settings.py` 的 `VERSION`

## 发布步骤

### 1. 本地构建验证

```bash
./scripts/build_release.sh 1.2.0
```

- 产出 `dist/*.whl`、`dist/*.tar.gz`、`dist/checksums.txt`
- 验证 whl 可安装、可运行

### 2. 提交 + 打 tag

```bash
git add -A && git commit -m "release: v1.2.0 — 变更摘要"
git tag v1.2.0
git push && git push --tags
```

### 3. CI 自动发布

push tag 后 GitHub Actions（`release.yml`）自动：
- 构建 wheel + sdist
- 生成 `checksums.txt`（SHA256）
- 创建 Release + 附件上传（`generate_release_notes: true` 自动生成变更说明）

### 4. 发布后检查

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
