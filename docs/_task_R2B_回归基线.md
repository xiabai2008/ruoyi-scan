# 工单 R2B：21 座靶场的回归基线（固定 p1 分支）

> 执行者：opencode。验收者：lead。
> 工作区 `D:\HZR_PROJECTS\ruoyi-scan-p1`（feat/p1-blindtest）。
> **只跑扫描，不改扫描器一行代码；不 commit。**
> 靶场在 `C:\Users\HZR\Desktop\若依系统`，按需启停，扫完即停。

---

## 零、目的

这不是盲测，是**回归基线**：靶场答案已知，目的是把"现在到底差在哪"量化成一张表，
给下一轮修复排优先级。所有结论必须能复现。

---

## 一、前置（不满足就停）

1. `cd D:\HZR_PROJECTS\ruoyi-scan-p1`
2. `git status --short` 只允许出现 `docs/_task_R2B_回归基线.md` 这一条未跟踪文件；
   出现其它条目就停，先报告。
3. 记录 `git rev-parse HEAD`（预期 `20bd530` 或更新），写进 manifest。
4. `git log --oneline -1` 写进 manifest。
5. 确认 54 个插件：`python main.py --plugin-list | tail -3`。

---

## 二、目标矩阵（13 次扫描）

每座靶场：**启动 → 等就绪 → 扫描 → 停止**，一次只起一座。
C1/C2/C3/D1/A2 的启停命令见 `若依系统/docs/靶场总览.md`。

| # | 靶场 | URL | 启动命令 | 认证 |
|---|---|---|---|---|
| 1 | C1-1 Jolokia | 19301 | `components_start.py jolokia` | 无 |
| 2 | C1-2 H2 | 19302 | `components_start.py h2-console` | 无 |
| 3 | C1-3 Data REST | 19303 | `components_start.py data-service` | 无 |
| 4 | C1-4 Config | 19304 | `components_start.py config-server` | 无 |
| 5 | C2-1a SBA server | 19311 | `c2_sba.py start` | 无 |
| 6 | C2-1b SBA client | 19312 | 同上（server 起着时 client 也在） | 无 |
| 7 | C2-2 Spring4Shell | 19313 | `c2_s4s.py start` | 无 |
| 8 | C2-3 Cloud Function | 19314 | `c2_scf.py start` | 无 |
| 9 | C3 蜜罐 | 19331 | `c3_honeypot.py start` | 无 |
| 10 | D1 二开（匿名） | 19321 | `d1_start.py start` | 无 |
| 11 | D1 二开（带凭据） | 19321 | 同上 | `--auth-login admin:admin123` |
| 12 | A2 双因子（匿名） | 19341 | `a2_start.py start` | 无 |
| 13 | A2 双因子（带凭据） | 19341 | 同上 | `--auth-login admin:admin123` |

另外两条可选（内存够就跑）：

| # | 靶场 | URL | 说明 |
|---|---|---|---|
| 14 | R8 Cloud | 19108 | `start_r8_cloud.py start`，需 ≥3.2GB 可用内存；不够就记为 SKIP，不许杀别的站点 |
| 15 | R2 对照 | 19102 | 若依 4.6.2 基线，用于发现回归 |

扫描命令统一：

```
"D:\tools\Python 3.12.9\python.exe" main.py -u <URL> --report artifacts/round2/<id> --no-pause --no-cta
```

带凭据的加 `--auth-login admin:admin123`。

---

## 三、执行脚本（`artifacts/round2/run_baseline.py`）

不要手动一条条敲，写个脚本，要求：

1. 按矩阵顺序执行；每座靶场 start → 探活 → 扫描 → stop。
2. 扫描前记录 `start_at`，扫描后记录 `end_at / duration / exit_code`。
3. 从 `report.json` 读：`target / request_count / fingerprint.cms / version / confidence /
   risk_distribution / results[].status`，统计 CONFIRMED/SAFE/UNKNOWN。
4. 如果 `report.json` 里有 `auth_status`（或 `surface_auth_status`），一并记录；没有就写 `MISSING`。
5. 靶场启停失败时，不要跳过扫描去扫空气；记录 `LAB_FAILED` 并继续下一座。
6. R8 启动前检查可用内存；<3200MB 记 `SKIP_LOW_MEM`，**不许自动停其他站点**。
7. 每座扫完必须 stop；脚本退出时保证 19301–19314、19321、19331、19341 都已释放。
8. 输出 `artifacts/round2/manifest.md`，列：

```
| # | id | target | branch | commit | start | duration | requests | cms | version | C | S | U | exit | auth_status | notes |
```

外加每个靶场的原始报告目录路径。

---

## 四、缺口报告（`docs/round2_baseline_20261031.md`）

结构固定：

1. **总表**：13（+2）次扫描的计数与指纹。
2. **预期 vs 实测**，逐靶场写：

| 靶场 | 预期 | 实测 | 归类 |
|---|---|---|---|
| C1-1 | jolokia×2 + actuator + mappings + heapdump | ? | 漏报/误报/正常 |
| C3 | 0 条 B 类；A 类可接受 | ? | ? |
| D1 | cms 空、登录链失败 | ? | ? |
| A2 | 默认口令 UNKNOWN；auth_status=failed | ? | ? |

3. **问题清单**，每条写：现象、证据（report.json 片段或 URL）、根因（文件/函数）、
   影响面、建议修法。按影响面排序。
4. **不确定项**：扫描器没给结论、靶场也没法证明的，单独列，不许猜。
5. **复现命令**：一行一条。

归类口径：

- **漏报**：靶场有真实暴露，扫描器没报；
- **误报**：靶场没有该问题，扫描器报了（C3 的 B 类优先看）；
- **静默降级**：登录/探测失败但报告看不出来（A2 的 `auth_status` 缺失属这类）；
- **正常**：预期与实测一致，含"正确判 UNKNOWN"。

---

## 五、不许做的事

1. 不许改扫描器代码、不许 `git add/commit/push`。
2. 不许改靶场、不许为了结果好看调靶场参数。
3. 不许把 A2 的 TOTP 密钥写进报告或日志。
4. 不许跳过失败的靶场不记录。
5. 不许自动停 R1–R12 给 R8 腾内存。

---

## 六、交付与停点

1. 贴 `manifest.md` 全文。
2. 贴缺口报告的核心表与问题清单（不用整篇贴）。
3. 贴 `git status --short`：只允许新增 `artifacts/round2/`、`docs/round2_baseline_20261031.md`
   与本工单文件，**不得有任何已跟踪文件被修改**；再贴 `git rev-parse HEAD`。
4. 贴执行结束后的端口检查：19301–19314、19321、19331、19341 全部释放。
5. **停在这里，不修任何代码。**
