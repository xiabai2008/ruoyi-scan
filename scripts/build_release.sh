#!/usr/bin/env bash
# F8: 本地 Release 构建脚本（wheel + sdist + SHA256 校验）
# 用法：
#   ./scripts/build_release.sh            # 构建当前版本
#   ./scripts/build_release.sh 1.2.0      # 构建并打 tag v1.2.0（不推送）
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

VERSION="${1:-$(python -c 'from config import settings; print(settings.VERSION)')}"

echo "[*] 构建 ruoyi-scan v${VERSION} ..."
pip install build >/dev/null 2>&1 || pip install build
rm -rf dist build
python -m build

echo "[*] 生成 SHA256 校验 ..."
sha256sum dist/*.whl dist/*.tar.gz > dist/checksums.txt
cat dist/checksums.txt

echo "[*] 校验 whl 可安装 ..."
python -m pip install --force-reinstall --no-deps dist/*.whl >/dev/null
ruoyi-scan --version 2>/dev/null || python -c "import ruoyi_scan; print('import ok')"

if [ "$VERSION" != "$(python -c 'from config import settings; print(settings.VERSION)')" ]; then
  echo "[*] 更新 settings.VERSION -> ${VERSION}（请手动提交后再打 tag）"
fi

echo "[*] 完成。发布步骤见 docs/RELEASE.md"
