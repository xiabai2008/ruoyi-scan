#!/usr/bin/env bash
# F4: CI 环境靶场验收入口（GitHub Actions ubuntu 使用）
#
# 流程：docker compose 启动 vuln + safe 双靶场 → 等待就绪 → python 对拍 → 退出码透传
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "[*] 启动 lab 靶场（vuln:8080 + safe:8081）..."
docker compose up -d --build lab-ruoyi 2>/dev/null || true

# lab 单容器镜像同时支持双模式：直接以不同端口启动两个实例
docker build -q -t ruoyi-scan-lab ./lab

docker rm -f lab-vuln lab-safe >/dev/null 2>&1 || true
docker run -d --name lab-vuln --rm -e LAB_MODE=vuln -e LAB_PORT=8080 -p 8080:8080 ruoyi-scan-lab >/dev/null
docker run -d --name lab-safe --rm -e LAB_MODE=safe -e LAB_PORT=8081 -p 8081:8081 ruoyi-scan-lab >/dev/null

echo "[*] 等待靶场就绪..."
for i in $(seq 1 30); do
  if curl -sf http://127.0.0.1:8080/ >/dev/null 2>&1 && curl -sf http://127.0.0.1:8081/ >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

echo "[*] 执行对拍..."
set +e
python lab/run_acceptance.py \
  --baseline data/acceptance_baseline.json \
  --output acceptance.json
EXIT_CODE=$?
set -e

docker rm -f lab-vuln lab-safe >/dev/null 2>&1 || true

if [ "$EXIT_CODE" -ne 0 ]; then
  echo "[!] 验收失败（exit=$EXIT_CODE），详见 acceptance.json"
  cat acceptance.json 2>/dev/null || true
fi
exit "$EXIT_CODE"
