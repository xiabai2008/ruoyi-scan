#!/usr/bin/env bash
# F4: CI 环境靶场验收入口（GitHub Actions ubuntu 使用）
#
# 流程：docker build 靶场镜像 → 启动 vuln + safe 双实例 → 等待就绪 → python 对拍 → 退出码透传
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CONTAINERS="lab-vuln lab-safe"

cleanup() {
  docker rm -f $CONTAINERS >/dev/null 2>&1 || true
}
# 任意退出路径（正常/失败/中断）都清理容器，避免残留占用 8080/8081 污染后续 CI
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo "[*] 构建 lab 靶场镜像 ..."
# 刻意不走 docker compose：lab-ruoyi 服务同样映射 8080，会与下方手动实例端口冲突；
# lab 镜像为单容器双模式，直接以不同端口启动两个实例即可
if ! docker build -q -t ruoyi-scan-lab ./lab; then
  echo "[!] lab 镜像构建失败" >&2
  exit 2
fi

cleanup
echo "[*] 启动 lab 靶场（vuln:8080 + safe:8081）..."
if ! docker run -d --name lab-vuln --rm -e LAB_MODE=vuln -e LAB_PORT=8080 -p 8080:8080 ruoyi-scan-lab >/dev/null; then
  echo "[!] lab-vuln 启动失败（8080 端口被占用或镜像异常）" >&2
  exit 2
fi
if ! docker run -d --name lab-safe --rm -e LAB_MODE=safe -e LAB_PORT=8081 -p 8081:8081 ruoyi-scan-lab >/dev/null; then
  echo "[!] lab-safe 启动失败（8081 端口被占用或镜像异常）" >&2
  exit 2
fi

# docker run 成功不代表容器在运行：立即校验状态，失败则输出日志并快速退出
for c in $CONTAINERS; do
  if [ "$(docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null || true)" != "true" ]; then
    echo "[!] 容器 $c 未能保持运行" >&2
    docker logs "$c" 2>&1 | tail -20 || true
    exit 2
  fi
done

echo "[*] 等待靶场就绪..."
ready=false
for i in $(seq 1 30); do
  if curl -sf http://127.0.0.1:8080/ >/dev/null 2>&1 && curl -sf http://127.0.0.1:8081/ >/dev/null 2>&1; then
    ready=true
    break
  fi
  sleep 2
done
if [ "$ready" != "true" ]; then
  echo "[!] 靶场 60s 内未就绪" >&2
  docker logs lab-vuln 2>&1 | tail -20 || true
  docker logs lab-safe 2>&1 | tail -20 || true
  exit 2
fi

echo "[*] 执行对拍..."
set +e
python lab/run_acceptance.py \
  --baseline data/acceptance_baseline.json \
  --output acceptance.json
EXIT_CODE=$?
set -e

# 容器清理由 EXIT trap 统一负责

if [ "$EXIT_CODE" -ne 0 ]; then
  echo "[!] 验收失败（exit=$EXIT_CODE），详见 acceptance.json"
  cat acceptance.json 2>/dev/null || true
fi
exit "$EXIT_CODE"
