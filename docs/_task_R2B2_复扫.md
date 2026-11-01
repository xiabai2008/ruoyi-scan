# 工单 R2B2：修复后的复扫对照（v2）

> 执行者：opencode。验收者：lead。
> 工作区 `D:\HZR_PROJECTS\ruoyi-scan-p1`。**只跑扫描，不改代码。**

---

## 一、前置

1. `git log --oneline -1`，确认包含 F6、F7 的提交/改动（未 commit 也可以，记录 `git status`）。
2. 记录 `git rev-parse HEAD` 与 `git status --short` 到 manifest。
3. 复用 `artifacts/round2/run_baseline.py`，改输出目录与 tag：

```
python artifacts/round2/run_baseline.py --tag v2 --out artifacts/round2_v2
```

如果脚本不支持参数，复制一份改输出路径，不要重写逻辑。

## 二、目标矩阵

与 R2B 完全一致（13 次扫描）：

- C1-1..C1-4（19301–19304）
- C2-1a SBA server（19311）、C2-1b client（19312）
- C2-2 Spring4Shell（19313）、C2-3 Cloud Function（19314）
- C3（19331）
- D1 匿名 + 带凭据（19321）
- A2 匿名 + 带凭据（19341）
- R2 对照（19102）
- R8 可选，内存 <3.2GB 记 SKIP

逐座 start → 探活 → 扫描 → stop，不许全量启动。

## 三、对照报告（`docs/round2_v2_20261101.md`）

1. 总表：每站 v1 与 v2 的 `C/S/U/requests/cms/version` 并排。
2. 变化明细：哪些 CONFIRMED 消失、哪些新增、哪些 UNKNOWN 变 SAFE。
3. 逐条对照 R2B 的问题清单：

| 问题 | v1 | v2 | 是否修好 |
|---|---|---|---|
| P0-1 `/login` 404 判默认口令 | C2-2/D1 CONFIRMED | ? | ? |
| P1 Spring 插件不加载 | C2-2 无 Spring 结果 | ? | ? |
| P1 SBA 漏报 | SAFE | ? | ? |
| P1 ruoyi-cloud 空 200 | 1.0 | ? | ? |
| P2 Swagger 空 paths | CONFIRMED | ? | ? |
| P1 Spring4Shell 只探 `/` | SAFE | ? | ? |

4. 未修好或新出现的问题，写清现象与证据。
5. 复现命令。

## 四、停点

1. 贴 v2 manifest 总表。
2. 贴对照报告的“变化明细”和“问题清单对照”。
3. 贴 `git status --short` 与 `git rev-parse HEAD`。
4. 扫描结束后所有靶场端口释放。
5. 不改代码、不 commit。
