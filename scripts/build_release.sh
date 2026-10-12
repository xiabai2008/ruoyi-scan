#!/usr/bin/env bash
# F8: 本地 Release 构建脚本（wheel + sdist + SHA256 校验）
# 用法：
#   ./scripts/build_release.sh            # 构建当前版本
#   ./scripts/build_release.sh 1.2.0      # 校验版本一致后构建 v1.2.0
#
# 版本号事实来源是 pyproject.toml（python -m build 的真实版本来源）：
# 传入版本不一致时直接失败，避免产出与预期版本不符的产物。
# 打 tag / 推送不在本脚本内执行，请按 docs/RELEASE.md 手动操作。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

VERSION="${1:-$(python -c 'from config import settings; print(settings.VERSION)')}"

# 版本对齐校验：python -m build 从 pyproject.toml 读取版本，入参只影响日志文本
PYPROJECT_VERSION="$(python - <<'PY'
import pathlib
import re

text = pathlib.Path("pyproject.toml").read_text(encoding="utf-8")
match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.M)
print(match.group(1) if match else "")
PY
)"
if [ -z "$PYPROJECT_VERSION" ]; then
  echo "[!] 无法从 pyproject.toml 解析版本号" >&2
  exit 2
fi
if [ "$VERSION" != "$PYPROJECT_VERSION" ]; then
  echo "[!] 请求版本 v${VERSION} 与 pyproject.toml v${PYPROJECT_VERSION} 不一致：请先同步版本后再构建" >&2
  exit 2
fi

echo "[*] 构建 ruoyi-scan v${VERSION} ..."
# 构建后端固定版本：避免 build 工具演进导致产物差异（复现性）
pip install "build==1.6.1" >/dev/null 2>&1 || pip install "build==1.6.1"

# 先构建到临时目录，成功后才替换 dist/：构建失败时上一版发布产物保持完好
TMP_ROOT="$(mktemp -d)"
trap 'rm -rf "$TMP_ROOT"' EXIT
python -m build --outdir "$TMP_ROOT/dist"

rm -rf dist build
mkdir -p dist
mv "$TMP_ROOT"/dist/* dist/

echo "[*] 生成 SHA256 校验 ..."
# 在 dist/ 内计算：checksums.txt 记录裸文件名（cd dist && sha256sum -c checksums.txt 可用）；
# nullglob 处理「只构建出 whl / tar.gz 其一」的场景，避免未匹配的 glob 按字面传给 sha256sum
(
  cd dist
  shopt -s nullglob
  files=(./*.whl ./*.tar.gz)
  if [ ${#files[@]} -eq 0 ]; then
    echo "[!] dist/ 下未找到 whl/tar.gz 产物" >&2
    exit 1
  fi
  sha256sum "${files[@]}" > checksums.txt
)
cat dist/checksums.txt

echo "[*] 校验 whl 可安装 ..."
# 装进临时 venv：不污染当前解释器，且去掉 --no-deps 以顺带验证运行时依赖可解析
python -m venv "$TMP_ROOT/venv"
"$TMP_ROOT/venv/bin/python" -m pip install --force-reinstall dist/*.whl >/dev/null
# 入口点必须真实可执行：main:main 未实现 --version，-h 打印帮助并以 0 退出；
# 失败即中止发布（不再以「能 import」这种弱校验掩盖入口点损坏）
"$TMP_ROOT/venv/bin/ruoyi-scan" -h >/dev/null

echo "[*] 完成。发布步骤见 docs/RELEASE.md"
