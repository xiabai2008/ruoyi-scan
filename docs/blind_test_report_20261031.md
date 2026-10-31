# ruoyi-scan v1.5.3 盲测能力评估报告

- 盲测日期：2026-10-31
- 被测版本：Ruoyi-Scan v1.5.3（54 插件：ruoyi 20 / spring 14 / common 12 / jeecgboot 8）
- 靶场：R1–R7、R9、R10、R11（10 站）；R8 未建成跳过；R12 全程未触碰
- 原始结果：`artifacts/blind_20261031/`（`raw-backup/` 为不可变副本，含 SHA256SUMS）
- 独立事实基线：`artifacts/blind_20261031/ground_truth.md`
- 本报告为 Phase 4 产物；Phase 5/6（修复与回归）**尚未执行**，等确认后再动代码

---

## 0. 本次盲测没有覆盖到的能力

先把没测到的说清楚，避免把「没测」误读成「没问题」：

1. **R8（RuoYi-Cloud）**：靶场未建成（0 张业务表、部门 10/用户 2），跳过；Cloud 变体、Nacos、Gateway actuator 路由全部未测。
2. **R12（WAF 前置）**：按任务约定全程未触碰（不 curl、不看日志），WAF 识别与「403 应判 UNKNOWN 而非 SAFE」这条关键纪律**未验证**；这是 Phase 6 唯一的未污染验证站。
3. **Shiro rememberMe 反序列化**：只确认了 `rememberMe=deleteMe` 指纹，未构造可用 gadget、未验证默认密钥可利用性，因此无法判定 R1（4.5.1，<4.6.1）是否真的可利用。
4. **Thymeleaf SSTI**：4.8.3 changelog 明确写「修改 Thymeleaf 变量，防止 SSTI RCE 风险」，但未定位到可利用端点；R1–R4 的 SSTI 面记为「未独立确认」。
5. **R9 工作流越权**（CVE-2026-58176 / 77795）：R9 没有 `scanner_low` 低权账号，只能验证 admin，无法做低权差分。
6. **R6/R7 文件上传、R4 `/monitor/online/list` orderBy 注入**：只做到「端点可达 / 报错面存在」，未完成完整利用。
7. **端口层**：未做 `--portscan`，6379 Redis、192xx 后端直连、R7 Actuator 19207 直连均未系统测量（R7 的 `/prod-api/actuator/env` 经 nginx 实测可达，见 §2.1）。
8. **其他模式**：`--serve` / `--distributed` / `--nuclei` / `--chain` / `--async` / `--passive` / `--crawl` 均未测；本次只测综合扫描、三个子模式、带会话与 `--auth-surface`。
9. **Phase 6 回归**：未执行。因此本报告只能回答「现在差在哪」，不能回答「改完好了多少」。

---

## 1. 总体结论

**最严重的能力短板是「高权会话获取链」：`--auth-login` 在验证码站（R1–R5）和 context-path/Plus/Jeecg 站（R7/R9/R10）上全面失败，`--auth-surface` 又在登录失败时直接崩溃；由此，所有「必须登录才能验证」的漏洞面（dataScope SQL 注入、任意文件上传、默认口令、Druid 弱口令、Swagger/Actuator、源码泄露）被系统性压成 UNKNOWN 或错误 SAFE。**

一句话量化：需要登录的 9 个站里有 8 个高权登录失败（R6 是唯一碰巧成功的；R11 无登录），17 条预期命中被漏掉，其中过半直接卡在认证链上；`--auth-surface` 5/5 崩溃。

---

## 2. 量化总表

统计口径：以 `artifacts/blind_20261031/*-anon/report.json` 为扫描器结论；以 `ground_truth.md` + 07 预期矩阵为事实基线。漏报/误报只统计**扫描器错**，靶场造错（见 §2.2）不计入。

| 站点 | 指纹 | 版本判定 | CONFIRMED | SAFE | UNKNOWN | 漏报 | 误报 | 耗时 |
|---|---|---|---|---|---|---|---|---|
| R1 | ruoyi / 0.70 | 4.5.1 ✅ | 3 | 0 | 26 | 2 | 0 | 74.5s |
| R2 | ruoyi / 0.70 | 4.6.2 ✅ | 3 | 0 | 26 | 2 | 0 | 78.6s |
| R3 | ruoyi / 0.70 | 4.7.8 ✅ | 3 | 0 | 24 | 0 | 0 | 74.5s |
| R4 | ruoyi / 0.70 | 4.8.0 ✅ | 2 | 0 | 25 | 2 | 0 | 78.4s |
| R5 | ruoyi / 0.70 | 4.8.3 ✅ | 0 | 0 | 25 | 0 | 0 | 71.6s |
| R6 | ruoyi / 0.50 | 未识别 ❌ | 0 | 19 | 10 | 3 | 0 | 30.7s |
| R7 | ruoyi / 0.70 | 未识别 ❌ | 5 | 15 | 9 | 3 | 0（路径级 3） | 336.7s |
| R9 | 未识别 / 0.00 | 未识别 ❌ | 3 | 20 | 8 | 2 | 1 | 51.4s |
| R10 | jeecgboot / 0.50 | 未识别 ❌ | 0 | 12 | 8 | 3 | 0 | 7.4s |
| R11 | 未识别 / 0.00 | 未识别 ❌ | 0 | 25 | 6 | 0 | 0 | 39.4s |
| **合计** | | **5/10 命中** | **19** | **91** | **167** | **17** | **1（+3 路径）** | |

补充：

- UNKNOWN 占比 **167/277 = 60.3%**；其中 R1–R5 的 SAFE→UNKNOWN 是登录墙下的**正确三态纪律**，不是缺陷（见 §5）。
- 「漏报」明细：R1 dataScope 注入 + 默认口令；R2 Swagger（带会话可达）+ Druid 弱口令；R4 HTML 上传 + 默认口令；R6 变体 + 公开 Swagger 文档 + 默认口令；R7 变体 + 默认口令 + sourcemap；R9 变体 + 默认口令；R10 公开 API 文档 + CORS + 默认口令。
- 「误报」明细：R9 `/prod-api/auth/login` GET 405 被报成 low 级「认证接口探测」（不是漏洞）；R7 的 Swagger 结论为真，但 8 个路径里混入 3 个 `HTTP 200 + {"code":401}` 假端点。
- 「证据不足」单列 3 条：R1/R2/R4 的「部门树越权」按 07 预期应命中（扫描器也报了），但独立探测只拿到 `[]`，没有数据泄露；按任务书「拿到本不该拿到的数据」口径证据不足，按 07 口径算 TP。详见 §2.2「真实未知」。

### 2.1 三方对照明细（07 预期 vs 实测）

> 站点代号按端口/版本对齐，不按 07 里的旧单位名。

**R1（4.5.1）**

| 预期项 | 07 预期 | 实测 | 归类 |
|---|---|---|---|
| 版本识别 | 4.5.1 | 4.5.1（`ry-ui.js?v=4.5.1`） | TP |
| 定时任务调用目标 | 命中 | CONFIRMED（scanner_low 写入/回读/还原成功） | TP |
| dataScope SQL 注入 | 命中 | UNKNOWN；独立验证 `params[dataScope]` 布尔差分 + `SLEEP(6.04s)` + `updatexml` 报错 `~ry_r1~` 成立 | **FN（扫描器错）** |
| 默认口令 | 命中 | UNKNOWN；独立登录 admin/admin123 成功 | **FN（扫描器错）** |
| 文件读取/路径穿越 | 命中 | 未确认：`/common/download/resource` 返回 200 空体；`profile` 目录不存在 | 靶场造错 |
| 文件上传 | 命中 | 未确认：`/common/upload` 500 `FileNotFoundException ...\.\profile\upload\...` | 靶场造错 |
| Druid 弱口令 | 命中 | 未确认：admin 会话下 `/druid/index.html` 200，但 `/druid/submitLogin` 500 | 靶场造错 |
| 备份文件 | 命中 | 未确认：`/backup/*.sql` 404（有会话仍 404） | 靶场造错 |
| `.svn` 泄漏 | 命中 | 未确认：`/.svn/entries`、`/.svn/wc.db` 404 | 靶场造错 |
| Shiro rememberMe | 不应命中 | UNKNOWN（仅 deleteMe 指纹，未 CONFIRMED） | 可接受（非 FP） |
| 重置密码页 / 部门树 | §8.3 命中 | 均 CONFIRMED；重置密码页泄露 `loginName=admin`（真实），部门树返回 `[]`（证据不足） | TP / 证据不足 |

**R2（4.6.2）**

| 预期项 | 07 预期 | 实测 | 归类 |
|---|---|---|---|
| 版本识别 | 4.6.2 | 4.6.2 | TP |
| 变体识别 | 空 | 空 | TP |
| 定时任务调用目标 | 命中 | CONFIRMED（写入/回读/还原成功） | TP |
| dataScope SQL 注入 | 不应命中 | UNKNOWN；独立验证 R2 无差分（已修） | TN（UNKNOWN 粒度偏粗，非 FP） |
| 默认口令 | UNKNOWN | UNKNOWN | TP |
| Swagger（需会话） | 命中 | UNKNOWN；独立验证 admin 会话下 `/v2/api-docs` 200 | **FN（扫描器错：认证失败）** |
| Druid 弱口令 | 矩阵未列，实际存在 | UNKNOWN；独立验证 `ruoyi/123456` → `success` | **FN（扫描器错）** |
| 文件读取/上传 | 命中 | 未确认：upload 500 目录不存在；read 200 空体 | 靶场造错 |
| `.git` 泄漏 | 命中 | 未确认：`/.git/HEAD`、`/.git/config` 404 | 靶场造错 |
| 目录扫描 | 无会话 0 命中 | UNKNOWN（0 命中，基线 404 可信） | 粒度问题 |

**R3（4.7.8）**

| 预期项 | 07 预期 | 实测 | 归类 |
|---|---|---|---|
| 版本识别 | 4.7.8 | 4.7.8 | TP |
| CVE-2025-46174 重置密码页 | 命中 | CONFIRMED；独立验证泄露 `loginName=admin` | TP |
| CVE-2025-70986 部门树 | 命中 | CONFIRMED；独立验证泄露 `工程技术部` | TP |
| 定时任务调用目标 | 不应命中 | 未出现在结果（版本过滤） | TN |
| 文件读取 / Druid / Swagger / download 穿越 | 不应命中 | 均 UNKNOWN，无 CONFIRMED | TN |
| `/logs/` 目录可列 | 命中 | CONFIRMED low；独立验证 `Index of /logs/` 200 | TP |

**R4（4.8.0）**

| 预期项 | 07 预期 | 实测 | 归类 |
|---|---|---|---|
| 版本识别 | 4.8.0 | 4.8.0 | TP |
| CVE-2025-46174 | 命中 | CONFIRMED；独立验证泄露 admin | TP |
| CVE-2025-70986 | 命中 | CONFIRMED；独立验证 `treeData/0` 返回 `[]` | TP（07 口径）/ 证据不足 |
| Swagger `/v2/api-docs` | 不应命中 | UNKNOWN，无 CONFIRMED | TN |
| 文件上传 | 命中 | UNKNOWN；独立验证 `.html` 上传成功并可通过 URL 访问 | **FN（扫描器错：认证失败）** |
| 默认口令 | 命中 | UNKNOWN；独立登录 admin/admin123 成功 | **FN（扫描器错）** |

**R5（4.8.3，误报检验站）**

| 预期项 | 07 预期 | 实测 | 归类 |
|---|---|---|---|
| 版本识别 | 4.8.3 | 4.8.3 | TP |
| 任何高危 CONFIRMED | 0 | 0 | TP |
| 管理员口令 `Admin@2026` | 灰色项 | 扫描器字典不含该口令，未报 | 不计 |

**R6（3.9.2）**

| 预期项 | 07 预期 | 实测 | 归类 |
|---|---|---|---|
| 变体识别 | `ruoyi-vue`（大概率误标 `ruoyi-vue3`） | **空** | **FN（变体完全未识别）** |
| 版本识别 | 识别不到 | 空（3.x 正则不匹配） | TP（设计取舍） |
| 文件上传 | 矩阵写「应命中」，§9.5 修订为 SAFE | UNKNOWN | 粒度问题（不计 FN/FP） |
| 匿名注册 | 命中 | 未报；独立探测 `/prod-api/register` → `当前系统没有开启注册功能！` | 靶场造错 |
| `captchaImage` 识别 | 正确识别 | 登录成功（验证码关闭），但指纹无 captcha 命中记录 | 部分 |
| （新增）公开 Swagger | 07 未列，但实测 `/prod-api/v3/api-docs` 200/64KB + `/swagger-ui/index.html` 200 | SAFE | **FN（能力缺口）** |
| （新增）默认口令 | 07 未列，但 admin/admin123 可登录 | SAFE | **FN（错误 SAFE）** |

**R7（3.8.9）**

| 预期项 | 07 预期 | 实测 | 归类 |
|---|---|---|---|
| 变体识别 | `ruoyi-vue3` | **空** | **FN** |
| 版本识别 | 识别不到 | 空 | TP（设计取舍） |
| Actuator env/heapdump | 命中（19207 直连） | `/prod-api/actuator/env` 200/69KB → CONFIRMED；heapdump 未测（端口未扫） | TP（env）/ 未覆盖 |
| 前端 sourcemap | 命中 | 未报；独立验证 `/static/js/app.d647f972.js.map` 200/572KB | **FN（无插件）** |
| Druid 控制台/弱口令 | §9.2 命中 | CONFIRMED（`ruoyi/123456` → `success`） | TP |
| Swagger/Druid/CORS/Actuator | §9.2 命中 | 5 条 CONFIRMED，内容级验证均为真 | TP（路径级 3 假） |
| 默认口令 | 未列，但 admin/admin123 可登录 | SAFE | **FN（错误 SAFE）** |
| Redis | 取决于 6379 | 未扫端口；Redis 现有密码 `ruoyi123` | 未覆盖 |

**R9（Plus 5.6.2）**

| 预期项 | 07 预期 | 实测 | 归类 |
|---|---|---|---|
| 变体识别 | `ruoyi-plus` | **空** | **FN** |
| 版本识别 | 未列 | 空；公开 `/prod-api/v3/api-docs` 含 `版本号: 5.6.2` | 能力缺口 |
| CORS | 未列，实际存在 | CONFIRMED（ACAO 反射 + ACAC=true） | TP |
| Swagger 文档 | 未列，实际存在 | CONFIRMED（`/prod-api/v3/api-docs` 312KB） | TP |
| 默认口令 | 未列，实际存在 | UNKNOWN；独立 `/prod-api/auth/login` 可登录 | **FN** |
| `/prod-api/auth/login` GET 405 | 不是漏洞 | CONFIRMED low「RuoYi-Plus 认证接口探测」 | **FP** |

**R10（JeecgBoot 3.6.3，误报检验站）**

| 预期项 | 07 预期 | 实测 | 归类 |
|---|---|---|---|
| CMS 识别 | jeecgboot | jeecgboot / 0.50 | TP |
| 被识别成 ruoyi | 误报重点记录 | 未发生 | TP |
| （新增）公开 v2 API 文档 | 未列，实际 `/jeecg-boot/v2/api-docs` 200/114KB + `doc.html` | SAFE | **FN** |
| （新增）CORS | 未列，实际 ACAO+ACAC | SAFE | **FN** |
| （新增）默认口令 | 未列，实际 admin/123456（验证码 OCR） | UNKNOWN | **FN** |
| jmreport 未授权注入 | 扫描器 UNKNOWN | 独立验证全部要 token，不成立 | TN（UNKNOWN 合理） |

**R11（自建 Spring Boot，误报检验站）**

| 预期项 | 07 预期 | 实测 | 归类 |
|---|---|---|---|
| CMS 识别 | spring 或未识别 | 未识别 | TP |
| 任何 RuoYi CONFIRMED | 全是误报 | 0 CONFIRMED | TP |
| （新增）25 条 SAFE | — | 对非若依目标无意义（应为「不适用」） | 语义噪声 |
| （新增）日志「登录成功」 | 目标无登录 | R11 日志出现「登录成功但任务列表不可读」 | 证据生成缺陷 |

### 2.2 三方分类汇总

**A. 扫描器错（本次要修，17 条漏报 + 1 条误报）**

- 认证链：R1/R2/R3/R4/R5/R7/R9/R10 的高权登录失败 → dataScope、上传、默认口令、Druid、Swagger(post-auth) 全部降级。
- 上下文路径：R10 只扫 144 请求/7.4s，Jeecg 未授权面全漏；R6 base-path 被根路径便利映射误导。
- 变体：10/10 全空，R9 Plus、R6/R7 Vue 均未识别。
- 插件逻辑：R7 Swagger 401 回显路径被当文档；R9 auth 405 被当漏洞；R6/R7 默认口令错误 SAFE。
- CLI：`-m/-p/-l` 被 `-u` 覆盖；`--auth-surface` 登录失败时 2 元组崩溃。

**B. 靶场造错（只记录，不改靶场）**

| 站点 | 现象 | 与 07 预期的偏差 |
|---|---|---|
| R8 | 未建成（0 业务表） | 跳过 |
| R1/R2 | `ruoyi.profile` 目录不存在，`/common/upload` 500、`/common/download` 200 空体 | 07 预期「文件上传/读取命中」不成立 |
| R1 | `/backup/*.sql`、`/.svn/*` 均 404（有会话仍 404） | 07 预期命中不成立 |
| R1 | `/druid/submitLogin` 500，但 `/druid/index.html` 登录后 200 | 07 预期「Druid 弱口令」不成立（更像未授权可读） |
| R2 | `.git/HEAD`、`.git/config` 404 | 07 预期命中不成立 |
| R6 | `/prod-api/register` 返回「当前系统没有开启注册功能」 | 07 预期匿名注册命中不成立 |
| R6 | nginx 根路径便利映射（非官方形态） | 导致 base-path 误判为「根路径直连」 |
| R7 | `/prod-api/actuator/env` 经 nginx 200 | 07 §9.5 写「nginx 不可达 actuator」，与实际不符 |

**C. 真实未知（不猜，单独列）**

1. **R1/R2/R4 部门树越权**：端点确实缺少权限注解（R3 有数据泄露，R5 已修），但 R1/R2/R4 的 `treeData/0` 返回 `[]`。按 07 预期算 TP，按任务书「拿到数据」口径证据不足。需要确认 `scanner_low` 的数据范围是否本就只含空子树（靶场设计）还是端点行为差异。
2. **Thymeleaf SSTI**：4.8.3 修复说明存在，但未定位可利用端点；扫描器 UNKNOWN，暂无法判 FN。
3. **R4 `/monitor/online/list` orderBy**：存在 SQL 报错面（`Unknown column 'token_id'`），但 `(CASE...)`/`updatexml` 被过滤；是否可绕过未验证。
4. **R1 Shiro 默认密钥**：只有指纹，无 gadget，未验证。
5. **R9 工作流越权**：无低权账号，未测。

---

## 3. 问题清单（按影响排序）

### P0. `--auth-surface` 登录失败即崩溃（5/5 站点）

- **现象**：R1–R5 的 `--auth-surface` 全部 `rc=1`，`R*-surface.json` 未生成，主报告虽写出但功能完全不可用。
- **证据**：`R1-surface.log` traceback：
  ```
  File "...cli/runner.py", line 613, in run_mode
    surface_assets, surface_vulns, surface_status = run_auth_surface_mode(args, target_normalized)
  ValueError: not enough values to unpack (expected 3, got 2)
  ```
- **根因**：`lib/auth_surface.py:507` 与 `:512` 在「未提供凭证 / 高权登录失败」时 `return [], []`，而函数签名与调用方都按 3 元组解包（`assets, vulns, status`）。
- **影响面**：所有高权登录失败的目标；本靶场 5/5 单机版必现，R7/R9/R10 同样会触发。
- **修法**：两处改为 `return [], [], "login_failed"`；补一条「登录失败返回三态」的回归用例；`run_auth_surface_mode` 的 `variant` 参数与调用方保持签名一致。

### P1. 高权自动登录链不支持验证码 / context-path / Plus / Jeecg（最大召回杀手）

- **现象**：
  - R1–R5：`--auth-login admin:admin123` → `[!]登录可能失败（HTTP 200），未获取到新认证信息`；
  - R7/R9/R10：`[!]登录可能失败（HTTP 405）`（根 `/login` 被 nginx 拒绝）；
  - R6：唯一成功（根 `/login` 碰巧被便利映射到后端）。
- **证据**：
  - `lib/auth_scan.py:auto_login()` 默认 `login_url = urljoin(base, "/login")`，payload 只有 `{username, password}`；
  - 同文件 `_extract_token` 只认顶层 `token` / `data.token`，不认 Plus 的 `access_token`、Jeecg 的 `result.token`；
  - 登录表单不发送 `validateCode` / `rememberMe`，不调用 `core/captcha_solver.py`；
  - R7/R9/R10 根 `/login` 分别返回 nginx 405；真实入口是 `/prod-api/login`、`/prod-api/auth/login`、`/jeecg-boot/sys/login`。
- **影响面**：**所有需要登录才能验证的插件**——`sql_inject_role/dept`（dataScope）、`file_upload`、`file_read(_path)`、`default_password`、`druid_brute`、`ruoyi_swagger_unauth`、`unauth_batch`、R10 全部 Jeecg 插件。R1/R4 的两条 FN、R2 的两条 FN、R6/R7/R9/R10 的默认口令 FN 都由此产生。
- **补充（重要）**：低权 CVE 插件走的 `isolated_auth_session` + `core/auth_chain.RuoYiAuthChain` 是**有效**的——它内置 `CaptchaSolver`，能识别 4.x 算术验证码；R1/R2 的定时任务写入、R3 的部门树数据泄露都是真阳性。失败的只是 `--auth-login` 这条另行实现的 `lib.auth_scan.auto_login`。因此修法不是重写认证，而是**把高权登录合并到已验证可用的那条链上**。
- **修法**：
  1. 让 `--auth-login` 复用 `core.auth_chain.RuoYiAuthChain`（它已经支持 v4 表单 + 验证码 OCR + v5 JWT），而不是另写一套 `auto_login`；
  2. 登录 URL 先用 base-path（`/prod-api`、`/jeecg-boot`）再拼 `/login`；
  3. 增加 Plus 形态：`POST {base}/auth/login`，body 必填 `clientId` + `grantType` + `tenantId`，token 取 `data.access_token`；
  4. 增加 Jeecg 形态：`GET {base}/sys/randomImage/{key}` → OCR → `POST {base}/sys/login`（`captcha`+`checkKey`），token 取 `result.token`，后续头 `X-Access-Token`；
  5. 登录成功判据必须支持「HTTP 200 + code:0/200 + 业务 token」，而不是只看新 Cookie。

### P2. context-path / base-path 适配不完整（R10 近乎空扫）

- **现象**：
  - R10 仅 7.4s / 144 请求，0 CONFIRMED；`/jeecg-boot/v2/api-docs`（114KB）、`/jeecg-boot/doc.html`、CORS、admin/123456 全部漏报；
  - R10 指纹只命中 `path:/jeecg-boot/(any,200)`（SPA 兜底），version 为空；
  - R6 的根路径便利映射让 `detect_api_base` 在根路径就命中 `/captchaImage`，返回 `""`，插件不再尝试 `/prod-api`，导致 `/prod-api/v3/api-docs`、`/prod-api/swagger-ui/index.html` 被漏。
- **证据**：
  - `core/basepath.py:CANDIDATES = ("/prod-api", "/dev-api", "/api")` **没有 `/jeecg-boot`**；
  - `core/basepath.py:_probe_api_base` 只要根路径的 `/captchaImage` 命中就返回 `""`，不验证「根路径是否只是便利映射」；
  - `plugins/jeecgboot/*` 部分插件虽然写了 `/jmreport/list` 与 `/jeecg-boot/...` 两个候选，但 `default_password` 固定 `/jeecg-boot/sys/login` 且无验证码，`sql_inject_*` 等仍按根路径拼接。
- **影响面**：整个 JeecgBoot 变体；R9 Plus 的 base-path 虽被部分插件用上，但指纹/变体仍不感知；R6 的误判会连带漏 Swagger。
- **修法**：
  1. `CANDIDATES` 增加 `/jeecg-boot`、`/jeecg`；
  2. 根路径命中后再校验「根路径响应是否等于 SPA 兜底 / 是否是便利映射」；若 `{base}/prod-api/captchaImage` 也命中，优先返回前缀；
  3. 把 `api_base` 传给 `detect_version` / `detect_variant` / 所有插件，而不是只传 root target；
  4. 为 JeecgBoot 建立 path map（`/sys/*`、`/jmreport/*`、`/v2/api-docs`、`/doc.html`）。

### P3. 三个子模式 `-m / -p / -l` 被静默忽略

- **现象**：`-m`、`-p`、`-l` 三次扫描的日志都打印「当前扫描模式:[综合扫描]」，结果与 `-u` **逐项相同**（同样 3 条 CONFIRMED、26 条 UNKNOWN、request_count 7179），报告 `mode` 字段也全是「综合扫描」。
- **证据**：`cli/dispatcher.py:199-205`：
  ```python
  elif target_for:
      for k in _MODE_ARGS:
          if k in target_for:
              run_mode(k, target_for[k], args)
              break
  ```
  `-m -u URL` 时 `flag_for={"m": True}`、`target_for={"u": URL}`，循环按 `u→m→p→l` 命中 `u`，裸 `-m` 只被用于「必须有目标」的校验。
- **根因**：模式选择只看「哪个 flag 带了 target」，没有把裸模式开关（`flag_for`）与 target 组合。
- **影响面**：所有按文档使用 `-m/-p/-l -u URL` 的用户；子模式隔离性为零，无法做单插件/单类别降噪。
- **修法**：`elif target_for:` 分支先取 `mode = next(iter(flag_for)) if flag_for else next(iter(target_for))`，再用任意 `target_for` 值执行；补 `-m -u URL`、`-p -u URL`、`-l -u URL` 三条 CLI 回归用例。

### P4. 版本指纹：4.x 精确，3.x/Plus/Jeecg 全部丢失

- **现象**：
  - R1–R5：5/5 精确（4.5.1/4.6.2/4.7.8/4.8.0/4.8.3），依据 `?v=`；
  - R6/R7：空（3.x，设计如此）；
  - R9：空，尽管公开 `/prod-api/v3/api-docs` 写着 `版本号: 5.6.2`；
  - R10：空，尽管首页 HTML 含 `3.6.3`。
- **证据**：
  - `core/ruoyi_versions.py:26`：`VERSION_PATTERN = re.compile(r"\b(4|5)\.(\d+)\.(\d+)\b")`；
  - `core/fingerprint.py:351-367`：`detect_version` 只探测 `/login`、根路径、`/actuator/info`，不读 Swagger 文档，也不加 base-path；
  - `core/fingerprint_features.py` 的 `jeecgboot` 特征没有 version 提取规则。
- **影响面**：版本过滤、报告可信度、R9/R10 的变体路由；R1–R5 不受影响。
- **修法**：
  1. `detect_version` 增加来源：`{base}/v3/api-docs`、`{base}/v2/api-docs` 的 `info.version`，`{base}/` 的 `3.x` 文本；
  2. 对 `cms=jeecgboot` 增加 `3.6.3` 这类 `3.x.y` 提取（与 RuoYi 的 4/5 正则分开，避免误命中前端依赖）；
  3. 4.x 单机版继续优先 `?v=`，版权年份只做兜底（07 §4.1 已说明）。

### P5. 变体识别 10/10 为空

- **现象**：R1–R11 的 `variant` 字段全部为空；R9 Plus 未被识别，R6/R7 Vue 未被识别，R2 单机版为空（这一条符合预期）。
- **证据**：
  - `core/fingerprint.py:detect_variant()` 的 `ruoyi-vue3` 强特征只有 `{base}/prod-api/`（expect=json）；R7 的 `/prod-api/` 返回 `{"code":401,"msg":"认证失败..."}`，被 `_is_auth_failure_json` 排除 → 0 命中；
  - `ruoyi-plus` 强特征 `/auth/login`、`/auth/logout` 是 **根路径相对**，未加 base-path；R9 根路径是 SPA；
  - 没有 `ruoyi-vue`（Vue2）条目，也没有 Jeecg 变体。
- **影响面**：变体感知的版本来源、插件路由、报告可读性；R9 直接退化为「未知 CMS + fallback ruoyi 插件」。
- **修法**：
  1. 先探测 `api_base`，再对 `{base}` 做变体判定；
  2. 把「`/prod-api/` 返回 401 认证 JSON」作为「分离版存在」的**正证据**（单独特征），不要与「接口存在」混用；
  3. Plus 特征改为 `{base}/auth/login`（expect=json/405 JSON）+ `{base}/auth/code`；
  4. 注册 `ruoyi-vue`（Vue2）与 `ruoyi-vue3` 的产物差异（`app.<hash>.js` vs `index-<hash>.js`）。

### P6. Swagger 插件把 401 回显路径当文档证据

- **现象**：R7 的「Swagger API 文档泄露」CONFIRMED 列了 8 个路径，其中 `/swagger-ui/`、`/v3/api-docs/swagger-config`、`/api-docs` 实际是 `HTTP 200 + {"msg":"请求访问：...，认证失败...","code":401}`，不是文档。
- **证据**：`plugins/common/swagger_leak.py:verify`：
  - `_POSITIVE = ["swagger", "openapi", "api-docs", "knife4j"]`；
  - 对 `resp.text[:500].lower()` 做 `any(kw in text ...)`；
  - 401 回显正文包含请求路径（如 `/v3/api-docs/swagger-config`），于是路径名本身命中了 `api-docs`/`swagger`；
  - 没有调用 `_is_auth_failure_json` / `is_missing_resource_page`。
- **影响面**：所有「认证失败回显路径」的分离版站点（R6/R7/R9/R10 同框架），会把假端点算进证据；不影响 CONFIRMED 结论本身，但污染路径清单与计数。
- **修法**：在 `verify` 开头对每个 `resp` 先过 `_is_auth_failure_json` / `is_missing_resource_page`，命中即 `continue`；文档判定优先要求 `"swagger"`/`"openapi"`/`"paths"` JSON 键或 `swagger-ui` HTML 特征，不拿路径名当证据。

### P7. 默认口令插件：R6/R7 错误 SAFE，R1–R4/R10 只能 UNKNOWN

- **现象**：
  - R1–R4、R10：UNKNOWN（实际 admin/admin123 均可登录）；
  - R6、R7：**SAFE**（实际 admin/admin123 均可登录，且 R6/R7 验证码关闭）；
  - R5：UNKNOWN（灰色口令 `Admin@2026` 不在字典，属预期）。
- **证据**：`plugins/ruoyi/default_password.py:verify`：
  - `url = join_url(target, "login")`，无 base-path；
  - 先表单提交，只有 `400/415/运行时异常` 才回退 JSON；**405 不触发回退**；
  - 表单带 `validateCode=""`，不调用 OCR；
  - 成功判据只认 `token`、`code==200`、`Set-Cookie`，不认 Plus 的 `data.access_token`、Jeecg 的 `result.token`。
- **影响面**：默认口令是高危项，R6/R7 的「SAFE」是最危险的假阴性（用户会以为口令已改）。
- **修法**：复用 P1 的登录链；`405/404/No static resource` 也视为「换形态」触发器；无验证码场景走 JSON，验证码场景走 OCR；Jeecg/Plus 分别取 token。

### P8. Druid 弱口令插件不建立应用会话，R2 真实弱口令被判 UNKNOWN

- **现象**：R2 的 `/druid/submitLogin` 用 `ruoyi/123456` 返回 `success`（独立验证），扫描器为 UNKNOWN；R1 的 Druid 在 admin 会话下 `/druid/index.html` 200，但 `submitLogin` 500。
- **证据**：`plugins/ruoyi/druid_brute.py:verify` 直接用 `session.post(url, data=...)`，不先登录应用；单机版未登录访问 `/druid/**` 是 302 `/login`，因此爆破打不到 Druid 登录页。
- **影响面**：R1–R5 单机版的 Druid 弱口令/未授权面；R7 因为 base-path + Druid 匿名可达才命中。
- **修法**：先判断登录墙；若是单机版，使用 `isolated_auth_session(scanner_low)` 或高权会话登录后再打 `/druid/submitLogin`；同时把「Druid 页面在应用会话下 200」作为「Druid 未授权可读」的独立结论，而不是只报弱口令。

### P9. JeecgBoot 插件面浅、默认口令无验证码能力

- **现象**：R10 仅 144 请求，8 个 Jeecg 插件全 UNKNOWN，0 CONFIRMED；`/jeecg-boot/v2/api-docs`、`doc.html`、CORS、默认口令均漏。
- **证据**：`plugins/jeecgboot/default_password.py:81` 固定 `join_url(target, "/jeecg-boot/sys/login")`，只发 `{username,password}`，服务端返回「验证码无效」→ UNKNOWN；其余插件依赖 base-path/根路径，SPA 兜底把响应变成 200 HTML。
- **影响面**：JeecgBoot 变体整体；R10 的负样本结论（「没有若依误报」）成立，但「真实 Jeecg 暴露面」几乎没测。
- **修法**：接入 P1 的 Jeecg 登录（`randomImage` + OCR + `checkKey`）；把 `/jeecg-boot` 加入 base-path；对 `jmreport` 的 token 校验做「有 token/无 token」差分；CORS 用 `{base}/v2/api-docs` 做 Origin 测试。

### P10. R11（非若依）fallback 噪声与「伪登录成功」

- **现象**：R11 25 条 SAFE、6 条 UNKNOWN、0 CONFIRMED；日志出现「登录成功但任务列表不可读」，而 R11 根本没有 `/login`（404 JSON）。
- **证据**：`R11-anon.log` 中的 `无法判定定时任务调用目标未校验: 登录成功但任务列表不可读`；独立探测 `/login` → 404 `No static resource login`。
- **根因**：未知 CMS 时仍 fallback 加载 `plugins.ruoyi`；`isolated_auth_session` 的登录成功判据把某些 200/JSON 形态误判为成功（需在 Phase 5 具体定位 `core/auth_chain.py` 的成功分支）。
- **影响面**：非若依目标的报告噪声与可信度；不会产生 CONFIRMED 误报（0 条），但会让用户误以为「登录成功、只是没权限」。
- **修法**：CMS 未知且无 RuoYi 弱特征时只跑通用插件（07 §11.4 的建议）；`isolated_auth_session` 增加「目标必须存在登录端点」的前置校验；成功判据要求 token/新 Cookie/明确成功文案三者之一。

### P11. R7 单站耗时 336.7s，是 R6 的 10 倍

- **现象**：R7 852 请求/336.7s，R6 7169 请求/30.7s；同一套参数。
- **证据**：`R7-anon.log` 与 report 的 `duration_sec=336.73`；R7 的 Druid 爆破在 base-path 下可达，逐个口令尝试且响应慢。
- **影响面**：批量扫描的时间预算；不是判定错误，但会拖垮 CI。
- **修法**：先测量 Druid 单次响应时延；对爆破类插件加 `--rate`/超时/早停（命中即停已有）；不要用「缩短字典」掩盖真实时延。

---

## 4. 能力维度评分

| 维度 | 评分 | 依据 |
|---|---|---|
| 版本指纹精度（4.5.1/4.6.2/4.7.8/4.8.0/4.8.3） | **能** | 5/5 精确命中，靠 `?v=4.x.y`；R1–R5 无一年份误判 |
| 变体识别（单机/Vue/Plus/Jeecg/非若依） | **不能** | 10/10 `variant` 为空；R9 Plus 未识别，R6/R7 Vue 未识别；只有 `cms` 能分 ruoyi/jeecgboot/未知 |
| 未授权检测（登录墙下） | **勉强** | R7 的 Druid/Swagger/CORS/Actuator、R3 `/logs/` 命中且真实；但 R10 公开文档/CORS/默认口令、R6 公开 v3 文档全漏 |
| 鉴权后检测（带会话后提升） | **不能** | 9/10 站高权登录失败；R6 登录成功但 0 新增命中；`--auth-surface` 5/5 崩溃；dataScope/上传/默认口令全部 UNKNOWN |
| 上下路径适配（`/prod-api`、`/jeecg-boot`） | **不能** | R7/R9/R10 根 `/login` 405；R10 7.4s 空扫；R6 根便利映射误导 base-path；R9 仅靠 `/auth/code` 部分救回 |
| 三态判定质量（UNKNOWN 占比/兜底） | **勉强** | 60.3% UNKNOWN；登录墙 SAFE→UNKNOWN 正确；但 R6/R7 默认口令错误 SAFE、R10 文档/CORS 错误 SAFE、R1/R2/R4 部门树证据不足仍 CONFIRMED |
| 误报控制（SPA 兜底/401 回显） | **勉强** | SPA 兜底基本没造成 CONFIRMED；但 Swagger 401 回显路径 3 个假端点、R9 auth 405 当漏洞、部门树空数据 CONFIRMED |
| 可复现性（同站两次） | **能** | R2 两次逐项一致（3 CONFIRMED/0 SAFE/26 UNKNOWN，7179 请求，指纹 4.6.2/0.70） |

---

## 5. 不建议改的东西

以下「看起来像短板」的地方是设计取舍或靶场问题，下一阶段不要为了好看去改：

1. **R1–R5 无会话时 SAFE=0、UNKNOWN≈25 条**：登录墙下「没测到」就是 UNKNOWN，这是三态纪律的正确表现。不要为了降低 UNKNOWN 把登录墙路径判 SAFE。
2. **R5 0 CONFIRMED**：4.8.3 是误报检验站，0 命中是正确结果。不要去「补检出」。
3. **R7 的 CORS**：RuoYi-Vue 3.8.9 官方 `ResourcesConfig.corsFilter()` 就是 `addAllowedOriginPattern("*") + allowCredentials(true)`，是框架默认行为；它是真实风险，但不要按「站点配置错误」升级严重度，也不要因为「框架默认」降成 SAFE。
4. **3.x 版本不进 RuoYi 版本正则**：07 §4.3 明确这是保守策略，不算错。若要支持 3.9.2/3.8.9，应新增独立的「非 4/5 版本读取」逻辑，不要放宽现有 4/5 正则去误命中前端依赖版本。
5. **R11 的 25 条 SAFE**：对非若依目标，RuoYi 插件应输出「不适用」而不是 SAFE；但不要把它们改成 CONFIRMED，也不要把 0 命中当失败。
6. **靶场造错项**：R1/R2 的上传目录缺失、R1 的 `/backup`/`.svn`、R2 的 `.git`、R1 的 Druid `submitLogin` 500、R6 的注册关闭——这些是靶场没按设计建成，**不要改扫描器去「适配」它们**，只需在报告里记账。
7. **R7 336s**：先测时延再优化；不要为了缩短耗时直接砍爆破字典/跳过插件，那会把「慢但有效」改成「快而漏」。
8. **R1/R2/R4 部门树 CONFIRMED**：07 预期就是「缺权限注解即命中」，扫描器的判定与 07 一致；按任务书的严格数据口径它证据不足，但这属于「判定口径」问题，不是简单删掉该插件就能解决。应单独讨论「缺注解但无数据」的严重度/证据模板，而不是一刀切降级。

---

## 6. 复现与证据索引

| 内容 | 路径 |
|---|---|
| Phase 1 manifest（命令/时间/耗时/计数） | `artifacts/blind_20261031/manifest.md` |
| 扫描原始结果 + 不可变备份 | `artifacts/blind_20261031/R*/`、`raw-backup/`（含 `SHA256SUMS`） |
| 独立探测脚本 | `artifacts/blind_20261031/probe/`（`probe_common.py`、`login.py`、`probe_site.py`、`diff_lib.py`、`sites.py`） |
| 独立事实基线 | `artifacts/blind_20261031/ground_truth.md` |
| R1/R6/R7/R9/R10/R11 探测 JSON | `artifacts/blind_20261031/probe/evidence/` |
| 重复扫描对照 | `artifacts/blind_20261031/repro/R2-anon-2/` |
| 关键复现命令 | 见 `ground_truth.md` 各节；`curl` 片段均可直接复制 |

---

## 7. 下一步（等确认）

按任务书 Phase 5 的优先级，建议只先修**影响整类场景**的三项，不要一次改 20 个：

1. **P0 + P1（认证链）**：`--auth-surface` 返回值 + 高权登录复用 `RuoYiAuthChain`（含验证码/base-path/Plus/Jeecg）。这一项直接决定 11 条 FN 能否回收。
2. **P2 + P5（context-path + 变体）**：`/jeecg-boot` 候选、base-path 前置、变体特征下沉到前缀下。决定 R10 整站与 R9/R6/R7 的变体识别。
3. **P3（子模式）**：dispatcher 的 flag/target 组合逻辑，改动小、可独立回归。

P6–P11 属于插件级修复，等前三项落地、R12 未污染验证通过后再排期。

**本轮到此为止，未改任何扫描器代码、未改靶场。**
