# v2.0 真实靶场全量验证（2026-11-19）

> 基线：`8e21d45` + 爆破安全策略（未提交前的验证工作区）。  
> 靶场：32 个扫描目标（31 个 lab 目标 + Y1；R8 独占内存启动，R13 为 hold-out WAF）。  
> 方法：每个目标用 `lab.py verify` 确认 UP 后跑一次 `-u`；R1–R5/R12/R13 按设计带 `--auth-login`（可用时）和 `--surface-account`；R13 使用带认证扫描验证 hold-out。报告 JSON 落盘到 `reports/validation-v2/`（本目录被 .gitignore 忽略，原文可按编号重跑）。

## 一、总表

| 目标 | 请求 | 耗时 s | CONFIRMED | 指纹 | 结论 |
|---|---:|---:|---:|---|---|
| R1 | 1,441 | 16.0 | 6 | ruoyi / 4.5.1 | 数量符合 6，但组成不符：缺 Druid、备份、.svn、文件读取 |
| R2 | 938 | 12.4 | 5 | ruoyi / 4.6.2 | 数量符合 5，缺 Swagger、.git；Druid 为额外命中 |
| R3 | 1,434 | 16.2 | 5 | ruoyi / 4.7.8 | CVE 对 + 上传/默认口令/目录遍历，符合主要预期 |
| R4 | 925 | 13.0 | 4 | ruoyi / 4.8.0 | CVE 对 + 上传/默认口令；部门树越权 UNKNOWN（FN） |
| R5 | 1,390 | 20.8 | 1 | ruoyi / 4.8.3 | **靶场造错**：DB 实际 admin/admin123，设计写 Admin@2026；扫描器正确发现真实弱口令，不是 FP |
| R6 | 886 | 17.1 | 4 | ruoyi / 3.9.2 / 变体空 | 变体识别失败（期望 ruoyi-vue/ruoyi-vue3）；上传 UNKNOWN、匿名注册未覆盖 |
| R7 | 889 | 22.8 | 7 | ruoyi / 3.8.9 / 变体空 | Actuator/备份/SCM 命中；**sourcemap 缺失**；变体空 |
| R8 | 1,418 | 18.7 | 8 | 指纹空（Cloud 能力命中） | Gateway 路由泄露/Nacos 默认口令/Actuator 均 TP；Cloud 指纹为空 |
| R9 | 1,419 | 29.6 | 2 | 指纹空（Plus 能力命中） | 变体识别失败（期望 ruoyi-plus）；CORS/Plus 认证命中 |
| R10 | 1,450 | 8.9 | 0 | jeecgboot / 3.6.3 | 负样本正确，无若依误报 |
| R11 | 927 | 11.1 | 0 | spring | 负样本正确，无若依误报；请求数达标 |
| R12 | 935 | 12.7 | 5 | ruoyi / 4.6.2 | WAF 未识别；业务面仍报出 R2 真实问题（非攻击 payload）；`-p` 0 命中、16 UNKNOWN |
| R13 | 941 | 8.5 | 5 | ruoyi / 4.6.2 | hold-out 与 R12 一致，无过拟合；WAF 未识别 |
| C1-1 | 173 | 5.8 | 5 | spring | Jolokia/Actuator/Heapdump TP |
| C1-2 | 926 | 8.9 | 1 | spring | H2 Console TP |
| C1-3 | 926 | 9.7 | 1 | spring | Spring Data REST TP |
| C1-4 | 926 | 16.7 | 1 | spring | Config Server 配置泄露 TP |
| C2-1a | 1,455 | 13.9 | 4 | spring | SBA/Actuator/Heapdump TP |
| C2-1b | 174 | 5.4 | 5 | spring | Gateway RCE/Actuator TP（路由 best-effort 清理） |
| C2-2 | 922 | 7.1 | 0 | 空 | 无 `--exploit` 时按设计 UNKNOWN；`--exploit` 复测 Spring4Shell CONFIRMED |
| C2-3 | 925 | 6.6 | 1 | spring | Spring Cloud Function RCE TP |
| C3 | 1,446 | 10.1 | 2 | 空 | 蜜罐仅假 .env/.git 命中，未把假 Druid/Swagger 判真 |
| C4-1 | 926 | 1.4 | 1 | spring | Redis 未授权 TP（需 HTTP 基准 + `--redis-port`） |
| C4-2 | 919 | 7.4 | 1 | 空 | MinIO 未授权 TP |
| C4-3 | 920 | 6.8 | 1 | 空 | RocketMQ Dashboard 未授权 TP |
| C4-4 | 926 | 6.8 | 1 | spring | jmreport SSTI TP |
| C4-5 | 926 | 6.7 | 0 | spring | 代码生成 SSTI 未命中，待复核是否为鉴权前置 |
| C4-6 | 890 | 6.1 | 1 | ruoyi-cloud | Thymeleaf/SpEL TP |
| C5 | 920 | 5.6 | 0 | 空 | 401 全拦，0 CONFIRMED，正确 |
| D1 | 932 | 10.0 | 2 | 指纹空 | 默认口令/Druid TP；context-path 指纹未识别 |
| A2 | 1,386 | 11.8 | 0 | ruoyi / 4.6.2 | MFA 正确降级 UNKNOWN，0 误报 |
| Y1 | 1,444 | 11.6 | 6 | yudao | 租户未授权/Druid/CORS/Swagger TP |

## 二、P0 结论

### 1. 爆破安全策略通过验证

- 默认 `top100` 后 R1 请求 **1,441**、R2 **938**；完整字典时 R1 约 7,201。
- R1 仍为 **6 CONFIRMED**，R2 仍为 **5 CONFIRMED**，没有因默认字典收敛丢结果。
- R2 Druid 仍在 top100 内命中（ruoyi/123456），说明“安全默认”没有牺牲真实基线。
- 新逻辑收到锁定/429 时返回 `UNKNOWN(brute_blocked)`，不会把未跑完伪装成 SAFE。

### 2. 全量验证暴露的 P0/P1 缺口

| 优先级 | 缺口 | 证据 | 定性 |
|---|---|---|---|
| P0 | R4 部门树越权 CONFIRMED 缺失 | R4 为 4.8.0，设计预期受影响；结果 UNKNOWN(insufficient_evidence) | 扫描器 FN（需复核低权差分） |
| P0 | R6/R7/R8/R9/D1 指纹/变体识别失败 | R6/R7 variant 空；R8/R9/D1 cms 空 | 扫描器 FN（识别链） |
| P0 | R7 sourcemap 缺失 | 设计明确 R7 应有 .map，当前无插件命中 | 扫描器 FN（能力空白） |
| P0 | R12/R13 WAF 未识别 | `waf=None`、`blocked=False`；`-p` 下攻击项正确 UNKNOWN，无假 SAFE | P1 能力缺口，2.0 必须修 |
| P1 | R1/R2 设计预期项未命中 | R1 缺 Druid/备份/.svn/文件读取；R2 缺 Swagger/.git | 需区分靶场未造 vs 插件 FN |
| P1 | R6 上传 UNKNOWN、匿名注册未覆盖 | R6 上传证据已成功但状态 UNKNOWN(unclassified) | 判定 bug/能力缺口 |
| P1 | C4-5 代码生成 SSTI 0 | 可能需登录态；当前 0 命中 | 待复核 |
| 环境 | R5 DB 口令不符 | R5 DB hash = md5(admin+admin123+111111)，不是 Admin@2026 | **靶场造错，非扫描器 FP** |

### 3. 不能发布的判断

当前**未达到 2.0 发布条件**：基础爆破安全已达标，但真实靶场验证发现 4 类 P0 缺口（R4 越权、变体/指纹、sourcemap、WAF），且 R1/R2 的预期组成仍有差异。下一步应优先修这些，不是继续加插件。
