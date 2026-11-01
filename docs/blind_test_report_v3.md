# ruoyi-scan v1.5.5 盲测 v3 报告（能力建设验证）

- 盲测日期：2026-11-02
- 被测代码：main `cae0a46`（含本轮 F10 登录、F11 Jeecg 双前缀、F12 Spring 真实响应、F13 降级口径）
- 靶场版本：lab repo `de58a37`（R10 Jeecg 漏洞版）、`085884e`（C2 Spring 真实组件）、`9106053`（D1 二开漏洞版）、`4b15a05`（绝对 profile）
- 原始数据：`artifacts/blind_v3/`（63 次常规扫描 + D1 补扫 2 次 + 安全模式 8 次 + R8 独占 4 次 = 77 份报告）
- 驱动脚本：`artifacts/blind_v3/{run_blind_v3,run_safe_phases,run_r8_phase}.ps1`、`aggregate.py`

## 0. 本轮目标与判定口径

v1.5.4 已解决「乱报」问题（盲测 v2：TP 10 / FN 1 / FP 0，但 54 插件中 25 个一次 CONFIRMED 都没有）。
本轮（v1.5.5）目标是把「该报的能报」补上来：给零产出插件建真实靶场、修判定缺陷，再用同一套扫描矩阵复测。

覆盖判定：同一插件在任一盲测报告中有 CONFIRMED 即计为「有产出」；安全/负样本模式出现 CONFIRMED 计为误报（B 类硬误报）。

## 1. 结论摘要

| 指标 | 盲测 v2（v1.5.4） | 盲测 v3（v1.5.5） | 变化 |
|---|---|---|---|
| 有 CONFIRMED 产出的插件 | 29/54 | **46/54** | **+17** |
| 零产出插件 | 25 | **8** | **-17** |
| v2 已有产出在 v3 丢失 | — | **0** | 无回归 |
| 安全模式新增 CONFIRMED（B 类误报） | 0 | **0** | 保持 |

> 剩余 8 个零产出项中：2 个是 recon 类（目录扫描/HTTP 方法探测，设计上不是漏洞判定）、
> 1 个 Shiro 指纹（设计上只有 SAFE/UNKNOWN）、2 个任意文件读取（Windows 靶场无法提供 /etc/passwd 型证据）、
> 1 个 RuoYi-Plus 定时任务未授权（需 Plus 误配靶场）、1 个 Redis 未授权（需 6379 无认证实例）、
> 1 个备份文件泄露（本轮未补对应靶场）。**本轮新增目标全部达成，剩余项均为已识别边界或下一轮候选。**

## 2. 新增 CONFIRMED 明细（17 项）

### 2.1 JeecgBoot 8/8（真实 JeecgBoot 3.6.3，R10 漏洞版；报告 `R10-anon`）

| 插件 | 证据（报告摘要） |
|---|---|
| 默认口令 | admin/123456 登录成功，返回真实 JWT |
| 字典越权 | /sys/dict/list 未授权返回分页 records+total |
| 任意文件读取 | /common/download 返回 /etc/passwd 真实行（root:x:0:0:） |
| jmreport 文件上传 | 上传返回成功标记 + url/fileName |
| 报表 SSTI | ${7*7} 真实 FreeMarker 求值返回 49（无载荷回显） |
| 报表未授权 | /jmreport/list 未授权返回报表列表 |
| jmreport SQL 注入 | 真实 JDBC 执行，select user() 回显 root@localhost |
| queryUserByDepId SQL 注入 | 差分命中：注入后 XPATH syntax error，基线无 |

### 2.2 Spring 5/5（真实组件靶场；报告 `C2-1b-anon` / `C2-3-anon` / `C2-2-exploit`）

| 插件 | 站点 | 证据 |
|---|---|---|
| Actuator env 配置覆盖 RCE | C2-1b 真实 Gateway 3.1.0 | POST 写入 ruoyi.scan.env_probe 返回 200 回显，GET 回读生效 |
| CVE-2022-22947 Gateway RCE | C2-1b | POST 创建路由 201 + Location=/routes/ruoyi-scan-probe-*（探针路由已 DELETE 清理） |
| Actuator /trace 泄露 | C2-1b | /actuator/trace 返回真实 HttpTraceRepository 数据 |
| CVE-2022-22963 SCF RCE | C2-3（3.2.2 受影响版） | routing-expression sleep(4000) 延迟 4.02s vs 基线 0.00s |
| CVE-2022-22965 Spring4Shell | C2-2 真实 Tomcat 9 | --exploit 写入 JSP 并执行，返回标记 |

### 2.3 RuoYi 二开 2 项（真实 D1；报告 `D1-anon` / `D1-auth`）

| 插件 | 阶段 | 证据 |
|---|---|---|
| 定时任务 RCE（未授权访问） | anon | 未鉴权 POST /monitor/job/edit（jobId=99999）→ 业务层 code=500「任务不存在」 |
| RuoYi 代码生成模块 SSTI | auth | 差分成立：基线无 49，注入 ${7*7} 后出现独立 49；带 --auth-login 时 CONFIRMED |

### 2.4 RuoYi-Cloud / Nacos 2 项（R8 独占轮次；报告 `R8-nacos-anon`，直连 8848）

| 插件 | 证据 |
|---|---|
| Nacos 未授权访问 | v1 服务发现匿名可读：ruoyi-job/auth/file/system/gen 5 个服务 |
| RuoYi-Cloud Nacos 配置泄露 | 已知 dataId ruoyi-gateway-dev.yml 可匿名读取正文（含 spring/password 关键字） |

## 3. v2 基线复现

v2 的 29 个有产出插件在 v3 全部复现（0 丢失），其中 R1–R9、C1/C2/C3/C4 的既有正样本结论与 v2 一致；
R10 由「负样本站」切换为「漏洞版」（vuln/safe 双模式）后，原负样本行为由 `R10-safe-*` 扫描验证（0 CONFIRMED）。

## 4. 安全模式 / 负样本验证（误报检查）

| 目标 | 模式 | CONFIRMED | 结论 |
|---|---|---|---|
| R10 JeecgBoot | safe（默认） | 0（anon/auth 均 0） | 8 个 Jeecg 场景恢复修复版行为，无残留误报 |
| C2-1b 真实 Gateway | safe（Gateway 3.1.1 + exposure 收敛） | 0 | env/gateway/trace 全部 404 → SAFE |
| C2-3 真实 SCF | safe（3.2.5 修复版） | 0 | 时序差分即时返回 → SAFE |
| C2-2 真实 Tomcat | safe（-Ds4s.hardened=true） | 0（含 --exploit） | 绑定被忽略、无新 JSP → UNKNOWN |
| D1 二开 | safe + auth | 1（后台默认口令 admin/admin123） | **真阳性**（D1 本就保留默认口令基线）；job UNKNOWN / gen SAFE |
| C3 蜜罐站 | 匿名/认证 | 4（A 类诱饵真实存在） | 与 v2 定级一致（A 类可接受，B 类 0） |
| R11 内部接口 | 匿名 | 0 | 负样本无新增误报 |
| R13 WAF hold-out | 匿名 | 1（后台默认口令） | 与 v2 设计一致：WAF 拦截项 UNKNOWN、真漏洞保留 |

## 5. R8 独占轮次说明

R8（RuoYi-Cloud）为 7 JVM + Nacos（约 4.2GB）独占靶场，本轮单独执行：停全站 → 起 R8 → 扫描 → 停 → 恢复全站。

- `R8-anon`：7 CONFIRMED，全部为 **gateway 组件暴露** 真阳性（Gateway RCE、Actuator H2/env、Swagger、批量未授权、Plus 认证接口）。
  归因仍需注意：这些是 gateway 的 actuator/swagger，不是若依业务漏洞（v2 已记录同一现象）。
- `R8-nacos-anon`（直连 8848）：2 CONFIRMED（Nacos 未授权 + Cloud 配置泄露）。
  站点扫描（19108）看不到 Nacos 是预期：nginx 的 /prod-api/ 只转 gateway，无 /nacos 路由。
- `R8-auth`：exit 4（gateway 统一认证入口无默认口令），不影响未授权结论。

## 6. 已知限制（如实记录）

1. **任意文件读取 ×2**：证据要求 /etc/passwd 特征（root:x:0:0:），Windows 靶场无法提供；需 Linux 靶场或插件扩展 win.ini 等 Windows 特征。
2. **RuoYi-Plus 定时任务未授权**：R9 是「生产配置规范」负样本（判 SAFE 正确）；需另建 Plus 误配站。
3. **备份文件泄露**：本轮未给 R1–R7 补「运维遗留备份」静态资产。
4. **R8 站点扫描的归因**：gateway 组件暴露被挂在若依插件名下，报告需按「gateway 组件」归类阅读。
5. **D1 gen SSTI**：官方 RuoYi 4.6.2 Velocity 链路对 ${7*7} 原样输出，D1 的命中来自二开新增开放接口的真实 SpEL 求值（真实端点/引擎，非打桩）；官方链路下该注入不可复现。
6. **扫描器不识别自定义 context-path（/portal）**：core/basepath 只探测固定前缀；D1 用 nginx 精确路径映射兜底，真实二开部署仍会漏。列为 v1.5.6 候选。
7. 扫描器 -p 模式只加载 vuln 类插件（brute 类默认口令不在其中），验收应按 -u 口径。

## 7. 交付物

- 靶场 commit：`de58a37`（R10）、`085884e`（C2）、`9106053`（D1）、`4b15a05`（launch profile）
- 扫描器 commit：`3c27e31`（F10 登录）、`95f27be`（F11 Jeecg）、`fee7580`（F12 Spring）、`cae0a46`（F13 降级口径）
- 原始数据：`artifacts/blind_v3/`（含 `coverage_summary.json`、`results.tsv`、各站点 report.json 与日志）
