# v2.0 真实靶场全量验证（2026-11-19）

> 基线：`8e21d45` + 爆破安全策略（未提交前的验证工作区）。  
> 靶场：32 个扫描目标（31 个 lab 目标 + Y1；R8 独占内存启动，R13 为 hold-out WAF）。  
> 方法：每个目标用 `lab.py verify` 确认 UP 后跑一次 `-u`；R1–R5/R12/R13 按设计带 `--auth-login`（可用时）和 `--surface-account`；R13 使用带认证扫描验证 hold-out。报告 JSON 落盘到 `reports/validation-v2/`（本目录被 .gitignore 忽略，原文可按编号重跑）。

## 一、总表

| 目标 | 请求 | 耗时 s | CONFIRMED | 指纹 | 结论 |
|---|---:|---:|---:|---|---|
| R1 | 1,441 | 16.0 | 6 | ruoyi / 4.5.1 | 6 条命中；实体无 .svn/.git，备份在 /docs/*.sql，属靶场/设计文档差异 |
| R2 | 938 | 12.4 | 5 | ruoyi / 4.6.2 | 5 条命中；Swagger 登录后 200（非未授权），.git=404，属靶场/设计预期差异 |
| R3 | 1,434 | 16.2 | 5 | ruoyi / 4.7.8 | CVE 对 + 上传/默认口令/目录遍历，符合主要预期 |
| R4 | 945 | 12.6 | 5 | ruoyi / 4.8.0 | 复测：CVE 对 + 上传/默认口令 + 部门树越权（空数据被数据权限过滤，业务层仍执行） |
| R5 | 1,390 | 20.8 | 1 | ruoyi / 4.8.3 | **靶场造错**：DB 实际 admin/admin123，设计写 Admin@2026；扫描器正确发现真实弱口令，不是 FP |
| R6 | 945 | 18.8 | 5 | ruoyi / 3.9.2 / ruoyi-vue3 | 变体/HTML 上传已修复；H2/Plus 误报已消除 |
| R7 | 901 | 20.8 | 8 | ruoyi / 3.8.9 / ruoyi-vue3 | Actuator/备份/SCM/sourcemap 8 条命中 |
| R8 | 1,418 | 18.7 | 7 | ruoyi-cloud | Gateway 路由泄露/Nacos 默认口令/Actuator 均 TP；本次默认口令未复现（令牌不能为空） |
| R9 | 1,442 | 26.0 | 2 | ruoyi / 5.6.2 / ruoyi-plus | 变体已修复；CORS/Plus 认证命中 |
| R10 | 1,450 | 8.9 | 0 | jeecgboot / 3.6.3 | 负样本正确，无若依误报 |
| R11 | 927 | 11.1 | 0 | spring | 负样本正确，无若依误报；请求数达标 |
| R12 | 1,012 | 33.2 | 6 | ruoyi / 4.6.2 | WAF 已识别 generic-http-filter；业务面 6 条真实问题（含部门树） |
| R13 | 1,000 | 27.8 | 6 | ruoyi / 4.6.2 | WAF 已识别；hold-out 与 R12 一致，无过拟合 |
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
| C4-5 | 926 | 5.4 | 1 | ruoyi | 代码生成 SSTI 差分成立；已去掉错误的 requires_auth 降级 |
| C4-6 | 890 | 6.1 | 1 | ruoyi-cloud | Thymeleaf/SpEL TP |
| C5 | 920 | 5.6 | 0 | 空 | 401 全拦，0 CONFIRMED，正确 |
| D1 | 1,013 | 12.4 | 4 | ruoyi / 4.6.2（context:/portal） | context-path 指纹已修复；默认口令/Druid/重置密码/部门树 TP |
| A2 | 1,386 | 11.8 | 0 | ruoyi / 4.6.2 | MFA 正确降级 UNKNOWN，0 误报 |
| Y1 | 1,444 | 11.6 | 6 | yudao | 租户未授权/Druid/CORS/Swagger TP |

## 二、修复进展（2026-11-19 晚）

| 缺口 | 修复 | 复测 |
|---|---|---|
| R6/R7 变体为空 | 为 ruoyi-vue3 / ruoyi-plus 增加 /prod-api/captchaImage、/prod-api/auth/code 等强特征；Plus 语义优先于通用 Vue3 | R6/R7 → ruoyi-vue3；R9 → ruoyi-plus + 5.6.2 |
| R7 sourcemap 缺失 | 新增 plugins/common/sourcemap_leak.py（严格校验 version=3/sources/mappings） | R7 已 CONFIRMED；SPA 兜底 HTML 判 SAFE |
| R12/R13 WAF 未识别 | detect_waf 增加无签名行为探测（union select/路径穿越返回 403 且正常请求未被拒） | R13 waf=generic-http-filter，-p 仍 0 CONFIRMED / 17 UNKNOWN |
| R8 Cloud 指纹 | 增加 /prod-api/actuator/gateway/routes、env 强特征 | R8 复测 cms=ruoyi-cloud（unit test 亦覆盖） |
| R4 部门树 UNKNOWN | 修正正向证据：treeData 返回合法 JSON（含 []）或 selectDeptTree 在无权限下 500 NPE，均证明业务层执行；数据行不再是必要条件 | R4 复测 CONFIRMED（5 条） |
| D1 context-path 指纹为空 | cms 为空时用 detect_api_base 探测自定义前缀，再以 {target}/{prefix}/ 重指纹；新增 /ruoyi/css/ry-ui.css 等强特征 | D1 复测 ruoyi / 4.6.2 / context:/portal，4 条 CONFIRMED |
| R6 登录后上传回读失败 | 回读 URL 同时尝试原地址与 target 的 base-path 前缀（/prod-api/profile/...） | R6 上传 CONFIRMED，证据包含可回读 URL |
| C4-5 代码生成 SSTI 0 命中 | 代码生成组件增加 /tool/gen 指纹；去掉错误的 requires_auth（匿名差分已能证明模板求值） | C4-5 复测 CONFIRMED |
| R6 H2/Plus 认证误报 | H2 matcher 不再把路径名当特征；Plus 认证排除 "No static resource"/认证失败 JSON | R6 H2/Plus 误报消失，R9 Plus 认证保持 |
| R1/R2 组成差异 | 核对靶场：R1 无 .svn/.git 实体、备份在 /docs/*.sql；R2 设计项需再核对 | 判定为靶场构造差异，暂不通过放宽插件“修” |

插件数 63（common 16）；SSOT/export/mkdocs/ruff 全部通过。

## 三、P0 结论

### 1. 爆破安全策略通过验证

- 默认 `top100` 后 R1 请求 **1,441**、R2 **938**；完整字典时 R1 约 7,201。
- R1 仍为 **6 CONFIRMED**，R2 仍为 **5 CONFIRMED**，没有因默认字典收敛丢结果。
- R2 Druid 仍在 top100 内命中（ruoyi/123456），说明“安全默认”没有牺牲真实基线。
- 新逻辑收到锁定/429 时返回 `UNKNOWN(brute_blocked)`，不会把未跑完伪装成 SAFE。

### 2. 全量验证暴露的 P0/P1 缺口

| 优先级 | 缺口 | 证据 | 定性 |
|---|---|---|---|
| P0 | R4 部门树越权 CONFIRMED 缺失 | 原结果 UNKNOWN；复测已 CONFIRMED（空 data + 500 NPE 业务执行） | **已修复** |
| P0 | R6/R7/R8/R9 指纹/变体识别失败 | 原 R6/R7 variant 空、R8/R9 cms 空；复测 R6/R7 ruoyi-vue3、R8 ruoyi-cloud、R9 ruoyi-plus/5.6.2 | **已修复** |
| P0 | R7 sourcemap 缺失 | 复测新增 SourceMap 插件命中 chunk-elementUI…js.map | **已修复** |
| P0 | R12/R13 WAF 未识别 | 复测 waf=generic-http-filter；-p 仍 0 CONFIRMED / UNKNOWN | **已修复（行为识别）** |
| P1 | D1 context-path 指纹为空 | D1 自定义 /portal 部署，cms 仍空 | 未修复，2.0 前需处理或标注 |
| P1 | R1/R2 设计预期项未命中 | R1 缺 Druid/备份/.svn/文件读取；R2 缺 Swagger/.git | 需区分靶场未造 vs 插件 FN |
| P1 | R6 上传 UNKNOWN、匿名注册未覆盖 | R6 上传证据已成功但状态 UNKNOWN(unclassified) | 判定 bug/能力缺口 |
| P1 | C4-5 代码生成 SSTI 0 | 可能需登录态；当前 0 命中 | 待复核 |
| 环境 | R5 DB 口令不符 | R5 DB hash = md5(admin+admin123+111111)，不是 Admin@2026 | **靶场造错，非扫描器 FP** |

### 3. 不能发布的判断

本轮已修复全部此前列出的 P0/P1 代码缺口：R4 越权、R6/R7/R8/R9 指纹变体、R7 sourcemap、R12/R13 WAF、D1 context-path、R6 登录后上传、C4-5 代码生成 SSTI；同时消除 R6 H2/Plus 认证误报。剩余工作不再是检测代码：R1/R2 的差异已定性为靶场/设计文档对账（R1 无 .svn/.git、R2 Swagger 是登录后 200），下一步进入 2.0 发布工程（版本、安装包、迁移说明、最终全量验收）。
