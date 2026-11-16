# v1.7 WP-2 · 三态 vs 二态对照实验

## 实验假设

**H1**：在自建靶场 GT 上，三态判定（CONFIRMED / SAFE / UNKNOWN）相对二态判定，
在**不显著抬高漏报**的前提下显著降低误报，综合判别能力（Youden J）更高。

## 数据集

- 报告目录：`artifacts/blind_v4`（仅匿名报告：True）
- GT 站点：30，可评估：27
- 评估条目：243
- GT 标签构成：{'safe': 193, 'unknown': 39, 'vulnerable': 11}
- 扫描器状态构成：{'CONFIRMED': 21, 'MISSING': 16, 'SAFE': 149, 'UNKNOWN': 57}
- UNKNOWN 率：23.46%
- 假阴性藏匿率（GT 真漏洞中被标 UNKNOWN 的比例）：0.00%

## UNKNOWN 归因交叉（WP-1）

| 原因码 | 条数 |
|---|---:|
| `auth_wall` | 56 |
| `denied` | 1 |

### GT 标签 × 扫描器状态

| GT 标签 | CONFIRMED | SAFE | UNKNOWN | MISSING |
|---|---:|---:|---:|---:|
| vulnerable | 9 | 2 | 0 | 0 |
| safe | 3 | 120 | 56 | 14 |
| unknown | 9 | 27 | 1 | 2 |

### UNKNOWN 原因 × GT 标签（回答「多少 UNKNOWN 其实是真漏洞」）

| 原因码 | GT vulnerable | GT safe | GT unknown |
|---|---:|---:|---:|
| `auth_wall` | 0 | 56 | 0 |
| `denied` | 0 | 0 | 1 |

> 若 `GT vulnerable` 列在某原因码下为 0，说明该原因下的 UNKNOWN 没有 GT 真漏洞被藏起来；
> 若不为 0，则该数字就是「被降级掉的正确答案」的实测条数。
> 注意：本表只统计 GT 覆盖到的 UNKNOWN（当前 57 条）；全量 567 条 UNKNOWN 的归因见
> `python scripts/unknown_audit.py`。

## 三组判定口径

| 组 | 判定口径 | Precision | Recall | F1 | Specificity | Youden J | TP/FP/FN/TN |
|---|---|---:|---:|---:|---:|---:|---|
| G0 | 三态（原始） | 75.00% | 81.82% | 0.7826 | 97.81% | 0.7963 | 9/3/2/134 |
| G1 | 二态·保守（UNKNOWN→SAFE） | 75.00% | 81.82% | 0.7826 | 98.45% | 0.8026 | 9/3/2/190 |
| G2 | 二态·激进（UNKNOWN→CONFIRMED） | 13.24% | 81.82% | 0.2278 | 69.43% | 0.5125 | 9/59/2/134 |

## 结论（按实际数据，不美化）

G0 的 Youden J 与 G1 相差 **-0.0063**，**本数据集不支持 H1 的强形式**：保守二态折叠（UNKNOWN→SAFE）的 P/R 与三态相同，J 甚至略高。三态的价值应表述为「可解释性与风险分层」——它把 UNKNOWN 与 SAFE 分开，避免把 57 条未判定（占 23.5%）伪装成“确认不存在”，而不是在本 GT 上提高 J。
G2（UNKNOWN→CONFIRMED）的 Precision 为 13.24%、J 为 0.5125，显著差于 G0/G1——激进折叠会把“测不了”批量变成误报，直接验证项目坚持三态的动机。

## 逐站结果（三组 Youden J）

| 站点 | 条目 | G0 | G1 | G2 | 报告 |
|---|---:|---:|---:|---:|---|
| A2 | 9 | 0.000 | 0.000 | -0.889 | `artifacts/blind_v4/A2-anon/report.json` |
| C1-1 | 9 | 1.000 | 1.000 | 1.000 | `artifacts/blind_v4/C1-1-anon/report.json` |
| C1-2 | 9 | 0.000 | 0.000 | 0.000 | `artifacts/blind_v4/C1-2-anon/report.json` |
| C1-3 | 9 | 0.000 | 0.000 | 0.000 | `artifacts/blind_v4/C1-3-anon/report.json` |
| C1-4 | 9 | -0.222 | -0.222 | -0.222 | `artifacts/blind_v4/C1-4-anon/report.json` |
| C2-1a | 9 | 0.875 | 0.875 | 0.875 | `artifacts/blind_v4/C2-1a-anon/report.json` |
| C2-1b | 9 | 1.000 | 1.000 | 1.000 | `artifacts/blind_v4/C2-1b-anon/report.json` |
| C2-2 | 9 | 0.000 | 0.000 | 0.000 | `artifacts/blind_v4/C2-2-anon/report.json` |
| C2-3 | 9 | 0.000 | 0.000 | 0.000 | `artifacts/blind_v4/C2-3-anon/report.json` |
| C3 | 9 | -0.400 | -0.400 | -0.400 | `artifacts/blind_v4/C3-anon/report.json` |
| C4-2 | 9 | 0.000 | 0.000 | 0.000 | `artifacts/blind_v4/C4-2-anon/report.json` |
| C4-3 | 9 | 0.000 | 0.000 | 0.000 | `artifacts/blind_v4/C4-3-anon/report.json` |
| C4-4 | 9 | 0.000 | 0.000 | 0.000 | `artifacts/blind_v4/C4-4-anon/report.json` |
| C4-5 | 9 | 0.000 | 0.000 | 0.000 | `artifacts/blind_v4/C4-5-anon/report.json` |
| C4-6 | 9 | 0.000 | 0.000 | 0.000 | `artifacts/blind_v4/C4-6-anon/report.json` |
| D1 | 9 | 0.000 | 0.000 | 0.000 | `artifacts/blind_v4/D1-anon/report.json` |
| R1 | 9 | 0.000 | 0.000 | -0.889 | `artifacts/blind_v4/R1-anon/report.json` |
| R10 | 9 | -1.000 | -1.000 | -1.000 | `artifacts/blind_v4/R10-anon/report.json` |
| R11 | 9 | 0.000 | 0.000 | 0.000 | `artifacts/blind_v4/R11-anon/report.json` |
| R12 | 9 | 0.000 | 0.000 | -0.889 | `artifacts/blind_v4/R12-anon/report.json` |
| R2 | 9 | 0.000 | 0.000 | -0.889 | `artifacts/blind_v4/R2-anon/report.json` |
| R3 | 9 | 0.000 | 0.000 | -0.889 | `artifacts/blind_v4/R3-anon/report.json` |
| R4 | 9 | 0.000 | 0.000 | -0.889 | `artifacts/blind_v4/R4-anon/report.json` |
| R5 | 9 | 0.000 | 0.000 | -0.889 | `artifacts/blind_v4/R5-anon/report.json` |
| R6 | 9 | 0.000 | 0.000 | 0.000 | `artifacts/blind_v4/R6-anon/report.json` |
| R7 | 9 | 0.000 | 0.000 | 0.000 | `artifacts/blind_v4/R7-anon/report.json` |
| R9 | 9 | -1.000 | -1.000 | -1.000 | `artifacts/blind_v4/R9-anon/report.json` |
| lab-ruoyi-safe | 0 | — | — | — | 无报告，跳过 |
| lab-ruoyi-vuln | 0 | — | — | — | 无报告，跳过 |
| lab-spring-vuln | 0 | — | — | — | 无报告，跳过 |

## 适用边界

- 数据来自自建靶场与匿名视角，不能外推到生产环境；
- GT 只覆盖手工探过的项，GT 未覆盖的结果不计入混淆矩阵；当前 GT 表 30 个站点中 27 个有报告，3 个签名靶场报告不在工作区；
- 二态 G1/G2 是分析层折叠，不改变扫描器运行时的三态语义；
- 若 G0 的 Youden J 不高于 G1/G2，应如实写入报告并分析三态的成本，不得美化。
