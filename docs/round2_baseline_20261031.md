# R2B 回归基线缺口报告（2026-10-31）

- 分支：`feat/p1-blindtest`
- commit：`20bd530b380dc4c7dcfae11a5ec9897ff5e82563`（`20bd530 feat(fingerprint): P1-1 指纹消费 base_path + API 文档取证`）
- 插件：54 个
- 可用内存：2267.7 MB（R8 需要 ≥3200 MB，记 SKIP_LOW_MEM，未启动、未停其他站点）
- 执行器：`artifacts/round2/run_baseline.py`；明细 `artifacts/round2/manifest.md`
- 扫描器代码零改动，未 commit

---

## 一、总表

13 次矩阵扫描 + R2 对照；R8 因内存不足跳过。

| # | id | target | requests | cms | version | conf | C | S | U | exit | auth_status |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | c1-1-jolokia | 19301 | 141 | spring | - | 1.0 | 5 | 21 | 0 | 0 | MISSING |
| 2 | c1-2-h2-console | 19302 | 140 | spring | - | 0.5 | 1 | 25 | 0 | 0 | MISSING |
| 3 | c1-3-data-rest | 19303 | 140 | spring | - | 0.5 | 1 | 25 | 0 | 0 | MISSING |
| 4 | c1-4-config-server | 19304 | 140 | spring | - | 0.5 | 1 | 25 | 0 | 0 | MISSING |
| 5 | c2-1a-sba-server | 19311 | 141 | spring | - | 0.5 | 2 | 24 | 0 | 0 | MISSING |
| 6 | c2-1b-sba-client | 19312 | 141 | spring | - | 1.0 | 3 | 23 | 0 | 0 | MISSING |
| 7 | c2-2-spring4shell | 19313 | 7170 | - | - | 0.0 | 1 | 22 | 8 | 0 | MISSING |
| 8 | c2-3-cloud-function | 19314 | 7161 | ruoyi-cloud | - | 1.0 | 0 | 20 | 9 | 0 | MISSING |
| 9 | c3-honeypot | 19331 | 7165 | - | - | 0.0 | 5 | 17 | 9 | 0 | MISSING |
| 10 | d1-anon | 19321 | 7168 | - | - | 0.0 | 1 | 21 | 9 | 0 | MISSING |
| 11 | d1-auth | 19321 | 7168 | - | - | 0.0 | 1 | 21 | 9 | 0 | MISSING |
| 12 | a2-anon | 19341 | 7165 | ruoyi | 4.6.2 | 0.7 | 0 | 0 | 29 | 0 | MISSING |
| 13 | a2-auth | 19341 | 7165 | ruoyi | 4.6.2 | 0.7 | 0 | 0 | 29 | 0 | MISSING |
| 14 | r8-cloud | 19108 | - | - | - | - | - | - | - | - | SKIP_LOW_MEM |
| 15 | r2-control | 19102 | 7165 | ruoyi | 4.6.2 | 0.7 | 1 | 0 | 28 | 0 | MISSING |

全部扫描进程退出码为 0，无崩溃。扫描结束后 19301–19314、19321、19331、19341 全部释放。

### CONFIRMED 明细

| id | 插件 | URL | 判定 |
|---|---|---|---|
| c1-1 | Spring Boot Actuator Jolokia MLet 链远程代码执行 | `/actuator/jolokia/list` | 真实暴露 |
| c1-1 | Spring Boot Actuator Jolokia 远程代码执行 | `/actuator/jolokia` | 真实暴露 |
| c1-1 | Spring Boot Actuator /mappings 路由映射泄露 | `/actuator/mappings` | 真实暴露 |
| c1-1 | Spring Boot Actuator heapdump 敏感信息泄露 | `/actuator/heapdump` | 真实暴露 |
| c1-1 | Spring Boot Actuator 未授权访问 | `/actuator/env` | 真实暴露 |
| c1-2 | Spring Boot Actuator H2 Console 未授权 JNDI RCE | `/h2-console` | 真实暴露 |
| c1-3 | Spring Data REST 信息泄露 | `/api` | 真实暴露 |
| c1-4 | Spring Cloud Config 配置未授权获取 | `/application/default` | 真实暴露 |
| c2-1a | Spring Boot Actuator heapdump 敏感信息泄露 | `/actuator/heapdump` | 真实暴露 |
| c2-1a | Spring Boot Actuator 未授权访问 | `/actuator/env` | 真实暴露 |
| c2-1b | Spring Boot Actuator /mappings 路由映射泄露 | `/actuator/mappings` | 真实暴露 |
| c2-1b | Spring Boot Actuator heapdump 敏感信息泄露 | `/actuator/heapdump` | 真实暴露 |
| c2-1b | Spring Boot Actuator 未授权访问 | `/actuator/env` | 真实暴露 |
| c2-2 | 后台默认口令（admin/admin123） | `/login` | **误报（判定链）** |
| c3 | `.env 配置文件泄露` | `/.env` | A 类诱饵，可接受 |
| c3 | `.git 源码泄露` | `/.git/HEAD` | A 类诱饵，可接受 |
| c3 | `RuoYi Swagger 未授权访问` | `/swagger-ui.html` | A 类，页面存在但文档为空 |
| c3 | `Swagger API 文档泄露` | `/` | **B 类硬误报** |
| c3 | `未授权访问（批量）` | `/` | A 类诱饵（假 actuator + 空 Swagger） |
| d1-anon | 后台默认口令（admin/admin123） | `/login` | **误报（判定链，结论巧合）** |
| d1-auth | 后台默认口令（admin/admin123） | `/login` | **误报（判定链，结论巧合）** |
| r2 | 后台默认口令（admin/admin123） | `/login` | 真实暴露（OCR 过验证码） |

---

## 二、预期 vs 实测

| 靶场 | 预期 | 实测 | 归类 |
|---|---|---|---|
| C1-1 | jolokia×2 + actuator + mappings + heapdump | 5 条 CONFIRMED，恰为上述 5 类 | 正常 |
| C1-2 | H2 Console 未授权 | 1 条 CONFIRMED | 正常 |
| C1-3 | Data REST 信息泄露 | 1 条 CONFIRMED | 正常 |
| C1-4 | Config 配置泄露 | 1 条 CONFIRMED | 正常 |
| C2-1a | SBA 未授权 + actuator 暴露 | actuator 2 条；SBA 插件判 SAFE，但 `/applications` JSON 有 1 个实例 | 漏报（SBA） |
| C2-1b | 被监控服务 actuator 暴露 | mappings/heapdump/env 3 条 | 正常 |
| C2-2 | Spring4Shell 可达 | 0 条 Spring 插件结果；反而多出默认口令 CONFIRMED | 漏报（Spring4Shell）+ 误报（默认口令） |
| C2-3 | 无对应漏洞（预期 0 CONFIRMED） | 0 CONFIRMED，但指纹被标成 `ruoyi-cloud` 1.0 | 误报（指纹） |
| C3 | 0 条 B 类；A 类可接受 | 4 条 A 类 + 1 条 B 类（Swagger 文档泄露） | 误报（B 类） |
| D1 匿名 | cms 空、登录链失败 | cms 空；`/login` 404 被判成"无鉴权"→ 默认口令 CONFIRMED | 误报（判定链） |
| D1 凭据 | 登录链失败、不污染结论 | 与匿名完全相同，`auth_status=MISSING` | 静默降级 |
| A2 匿名 | 默认口令 UNKNOWN | 默认口令 UNKNOWN，证据含"动态口令不能为空" | 正常 |
| A2 凭据 | 默认口令 UNKNOWN + `auth_status=failed` | UNKNOWN 正确；`auth_status=MISSING`、退出码 0 | 静默降级 |
| R8 | 可选 | 内存 2267.7 MB < 3200 MB，未启动 | SKIP_LOW_MEM |
| R2 | 官方 4.6.2 基线 | 指纹 `ruoyi/4.6.2/0.7`；默认口令真实命中；SAFE 全转 UNKNOWN | 正常（登录墙策略） |

---

## 三、问题清单（按影响面排序）

### P0-1 登录链把 `/login` 404 当成"无鉴权"，直接判默认口令成功

- **现象**：C2-2（Spring4Shell，站点根本没有登录接口）和 D1（登录已改到 `/auth/signin`，`/login` 已下线）都被判 `后台默认口令（admin/admin123）` CONFIRMED。
- **证据**：
  - C2-2：`GET http://127.0.0.1:19313/login` → 404；报告 `evidence="默认口令登录成功（含验证码场景；独立会话验证，凭证已脱敏）"`，`extra.chain="captcha_login"`。
  - D1：`GET http://127.0.0.1:19321/login` → 404，`GET /portal/auth/signin` → 200；报告同样 CONFIRMED。
  - 对照：两站都没有发生任何真实登录请求。
- **根因**：
  - `core/auth_chain.py` `detect_auth_mode()`：`http_code == 404` 直接返回 `AUTH_NONE`（219–222 行）；`login()` 在 `AUTH_NONE` 下直接 `return True, LOGIN_OK`（272–274 行），不验证任何业务接口。
  - `plugins/ruoyi/default_password.py` `verify()`：只要 `isolated_auth_session` 的 `ok_chain=True` 就立即 CONFIRMED（135–147 行）。
  - `isolated_auth_session()` 的 `ok` 因此只代表"登录链认为无需登录"，不代表"默认口令可用"。
- **影响面**：所有自定义登录路径、无 `/login` 的 Spring 站点会被打上高危默认口令；C2-2、D1 两例已复现。任何 /login 404 的站点都可能中招。
- **建议修法**：
  1. `AUTH_NONE` 必须由"受保护接口在未登录时也返回数据"证明，不能由 `/login` 404 推出；
  2. `default_password` 只有在真实登录成功（code=0/token/Admin-Token）并访问一个鉴权接口拿到数据后才 CONFIRMED；`AUTH_NONE` 分支应返回 UNKNOWN；
  3. 若站点根路径/登录路径自定义，先做登录入口发现（表单 action、`/auth/*`），再判默认口令。

### P0-2 `--auth-login` 失败静默降级为匿名扫描，报告无 `auth_status`

> **勘误（lead，2026-11-01 复核）：** 本条部分不成立。
> `report.json` 有 `auth_status`，位置是 `meta.auth_status`，D1/A2 的带凭据运行均为
> `{"admin":"failed","surface":"not_attempted"}`；CLI 也会打印 RED 提示（`cli/runner.py:443-460`）。
> 真正成立的只有两点：①显式传了认证参数、登录失败时退出码仍是 0，CI 无法感知；
> ②A2 的 MFA 场景只记 `failed`，没有区分 `mfa_required`。
> 因此本条从 P0 降为 P1，修复见 F6-3。下面保留原始记录，便于对照。

- **现象**：D1、A2 的带凭据扫描与匿名扫描的计数、指纹、默认口令证据完全一致；报告没有 `auth_status`/`surface_auth_status` 字段，进程退出码 0。
- **证据**：
  - `d1-auth` 与 `d1-anon`：C=1 / S=21 / U=9，`auth_status=MISSING`。
  - `a2-auth` 与 `a2-anon`：C=0 / S=0 / U=29，`auth_status=MISSING`；默认口令 evidence 为"登录墙…原证据：登录失败：code=500 msg=动态口令不能为空"。
  - 报告顶层字段只有 `target/scan_time/duration_sec/request_count/mode/fingerprint/version_matrix/blocked/risk_distribution/vuln_count/results`。
- **根因**：
  - `lib/auth_scan.py` `auto_login()` 登录失败返回空 `{"cookies": {}, "headers": {}}`（202、277、285 行），不抛异常；
  - `cli/runner.py` 在 `_build_scan_request()` 中只合并 `cookies/headers`，为空时把 `auth_config` 置 `None`（149–151 行），随后按匿名扫描执行；
  - 报告 JSON 没有写入认证状态的字段，CLI 也不因登录失败改退出码。
- **影响面**：同 P0 级别。用户传了 `--auth-login` 会误认为做了认证后扫描；A2 这类 MFA 站点尤其危险（永远拿不到第二因子，但报告看不出来）。
- **建议修法**：
  1. `ScanRequest` 增加 `auth_status`（`ok|failed|not_attempted`），并在 `report.json` 顶层输出；
  2. 登录失败时 CLI 打印 RED 提示并返回非 0（或至少报告 `auth_status=failed`）；
  3. 对响应含 OTP/动态口令/二次验证关键字时，明确记 `MFA_REQUIRED`，不要静默当匿名。

### P1-1 指纹未识别 Spring → `plugins.spring` 整包不加载，Spring4Shell 直接漏测

- **现象**：C2-2 报告里没有任何 `Spring Boot Actuator *`/`CVE-2022-22965` 结果；Spring4Shell 插件根本没运行。
- **证据**：
  - C2-2 `fingerprint={"cms":"","version":"","confidence":0.0,"matched":[]}`；
  - 报告 31 条结果全部来自 `plugins.ruoyi` 与通用插件，无 `plugins.spring`；
  - 目标根路径是普通设备登记页，无 Whitelabel、无 `/actuator`，Spring 特征库因此没有强特征。
- **根因**：
  - `core/router.py` `candidates()`：`cms` 为空直接 `return []`（40–42 行）；
  - `core/fingerprint_features.py` 的 `spring` 只靠 `/actuator` 200、Whitelabel、root JSON 等特征（37–48 行），普通 Spring MVC 站点无法命中。
- **影响面**：所有"无 actuator、无默认错误页"的 Spring MVC 应用（尤其 war 部署的 Spring4Shell 场景）都拿不到 Spring 专项插件。
- **建议修法**：
  1. 指纹兜底：`X-Application-Context`、`/error` 结构、`SPRING` 响应头、常见 Spring MVC 404 页面等作为弱特征；
  2. 路由兜底：cms 为空但根路径返回 Spring MVC 特征时，仍加载 `plugins.spring` 的"低置信"子集（至少 Spring4Shell/actuator 探测）；
  3. 或者提供 `--cms spring` 的自动二次判定（当前只能手工指定）。

### P1-2 Spring4Shell 插件只探测 `/`，且把 405 当 SAFE

- **现象**：即使手工给 `--cms spring`，该插件也只会 POST `/`，对真实 POJO 端点无效。
- **证据**：
  - 实测 C2-2：`POST /` 带 `class.module.classLoader...` → **405 Method Not Allowed**；
  - 同参数 `POST /device/add` → **200** `{"code":200,"message":"设备登记成功",...}`；
  - 插件代码只发往 `join_url(target, "/")`（`plugins/spring/spring4shell.py` 65 行），405 不满足 200 条件 → 判 SAFE（94–111 行）。
- **影响面**：Spring4Shell 在真实业务里通常落在某个表单/POJO 接口，不在根路径；当前实现基本只能命中"根路径 POST 可达"的靶场。
- **建议修法**：
  1. 用爬虫/表单发现收集所有 POST 端点（含 `th:action`、`action=`），逐点探测；
  2. 对根路径 405/404 返回 UNKNOWN（测不到 ≠ 安全），不要落 SAFE；
  3. 保留 marker 判定用于对拍，但生产判定以"200 且无错误结构"为准。

### P1-3 Spring Boot Admin 插件不读 JSON API，SBA 服务端漏报

- **现象**：C2-1a（SBA server 19311）只报 actuator 2 条，`Spring Boot Admin 未授权访问` 判 SAFE；实际 `/applications` 有 1 个注册实例。
- **证据**：
  - `GET /applications`（默认 Accept）→ 200，1279 字节 SPA 壳；全文不含 `spring-boot-admin` / `applications`；
  - `GET /applications` + `Accept: application/json` → 200，1876 字节，含 1 个实例；
  - 插件 `plugins/spring/spring_boot_admin.py` 只用 `session.get()`（64–71 行），没有设置 `Accept`，也没有解析 JSON。
- **影响面**：SBA server 的核心暴露面（实例列表/环境/日志）无法确认；仅靠 actuator 插件只能看到部分风险。
- **建议修法**：
  1. 对 `/applications` 先带 `Accept: application/json` 请求，解析 JSON 数组/实例数量；
  2. SPA 壳场景下再尝试 `/instances`、`/actuator` 等端点；
  3. 关键字判定保留，但不再作为唯一依据。

### P1-4 `ruoyi-cloud` 指纹仅凭"路径 200"命中，把 Spring Cloud Function 误标为 Cloud 版

- **现象**：C2-3（Spring Cloud Function，19314）指纹 `cms=ruoyi-cloud`、`confidence=1.0`，`matched=['path:/nacos/(any,200)','path:/gateway/(any,200)']`。
- **证据**：
  - 实测 `GET /nacos/` → 200（空响应）；`GET /gateway/` → 200（空响应）；
  - 根路径返回业务 JSON（非空），因此"与根路径相同"的软 404 保护没有触发；
  - 报告随后只跑 `plugins.ruoyi`，9 条 UNKNOWN。
- **根因**：
  - `core/fingerprint_features.py`：`ruoyi-cloud.strong_paths` 用 `{"path": "/nacos/", "expect": "any"}` 与 `/gateway/`（54–57 行）；
  - `core/fingerprint.py` 的 `expect="any"` 只排除"与根路径完全相同的 body"（164–173 行），空 body ≠ 根 JSON body，于是两个强特征各 0.5，合计 1.0。
- **影响面**：任何对未知路径返回 200 空响应的 Spring 应用都可能被误标为 Cloud；后续插件路由、变体判定、报告结论全部跟着错。
- **建议修法**：
  1. `/nacos/` 必须命中 Nacos 控制台特征（HTML 标题/`nacos` JS/JSON 结构），`/gateway/` 必须命中 Gateway 特征；
  2. `expect="any"` 对空 body、204、纯文本 "OK" 一律不算强特征；
  3. 软 404 基线按路径族比较（同前缀），不要只与根路径比较。

### P2-1 C3 `Swagger API 文档泄露` 在 `paths={}` 时仍 CONFIRMED（B 类硬误报）

- **现象**：C3 的 `/v2/api-docs` 返回 `{"swagger":"2.0", ..., "paths":{}}`，插件仍报"发现 2 个 API 文档端点"。
- **证据**：C3 报告 `Swagger API 文档泄露` CONFIRMED，URL `/`，evidence `发现 2 个 API 文档端点: /swagger-ui.html, /v2/api-docs`；实际文档 `paths` 为空。
- **根因**：`plugins/ruoyi/swagger_leak.py`（或等价实现）以"端点存在/页面可访问"作为泄露证据，未解析 `paths` 是否为空。
- **影响面**：所有只挂 Swagger UI 壳、没有真实接口文档的站点会被误报；C3 的唯一 B 类误报即此条。
- **建议修法**：解析 `/v2/api-docs`、`/v3/api-docs` 的 JSON，`paths` 为空则降级为 SAFE/UNKNOWN；仅 UI 页面可访问最多算信息暴露（A 类）。

### P2-2 A2 默认口令的 UNKNOWN 依赖"登录墙"后处理，而非插件自身判定

- **现象**：A2 默认口令最终 UNKNOWN，但 evidence 来自登录墙转换（"目标存在登录墙…原证据：登录失败：code=500 msg=动态口令不能为空"），插件自身对 `code=500` 的分支是 SAFE（`default_password.py` 285–295 行）。
- **证据**：A2 报告该条 `status=UNKNOWN`，evidence 同时保留 `登录失败：code=500 msg=动态口令不能为空`。
- **影响面**：若后续调整登录墙策略，A2 会从 UNKNOWN 掉成 SAFE（把"需要第二因子"误报成"确认安全"）。
- **建议修法**：在 `default_password` 内识别 OTP/动态口令/二次验证关键字（如"动态口令""otp""verification code"），直接返回 UNKNOWN 并标注 `mfa_required`，不要依赖外层转换。

---

## 四、不确定项

1. **R8 未测**：可用内存 2267.7 MB < 3200 MB，按工单记 SKIP_LOW_MEM；未启动、未停其他站点。Cloud/Nacos/Gateway 结论本轮缺失。
2. **C2-3 的 9 条 UNKNOWN**：没有 Spring Cloud Function 专项插件，无法判断 functionRouter/uppercase 是否应被识别；只能确认指纹错误（见 P1-4）。
3. **C2-2 的 8 条 UNKNOWN**（代码生成 SSTI、定时任务、部门树等）：Spring 插件包未加载，无法区分"未测到"与"不存在"。
4. **D1 默认口令"结论巧合"**：D1 的 `admin/admin123` 在 `/portal/auth/signin` 确实有效，但扫描器从未请求该地址；CONFIRMED 的证据不成立。按"证据链"归为误报，按"事实"口令确为默认值，需人工区分。
5. **R2 的 28 条 UNKNOWN、0 条 SAFE**：登录墙策略会把未认证下的 SAFE 全转 UNKNOWN。是否应保留"SAFE"语义（已确认安全 vs 没测到）需产品口径确认，本轮不作判定。

---

## 五、复现命令

```bash
# 全量（推荐，自动启停 + 生成 manifest）
D:\tools\Python 3.12.9\python.exe artifacts\round2\run_baseline.py

# 单靶场示例
D:\tools\Python 3.12.9\python.exe C:\Users\HZR\Desktop\若依系统\scripts\c2_s4s.py start
D:\tools\Python 3.12.9\python.exe main.py -u http://127.0.0.1:19313/ --report artifacts/round2/c2-2-spring4shell --no-pause --no-cta
D:\tools\Python 3.12.9\python.exe C:\Users\HZR\Desktop\若依系统\scripts\c2_s4s.py stop

# D1 两遍
D:\tools\Python 3.12.9\python.exe C:\Users\HZR\Desktop\若依系统\scripts\d1_start.py start
D:\tools\Python 3.12.9\python.exe main.py -u http://127.0.0.1:19321/ --report artifacts/round2/d1-anon --no-pause --no-cta
D:\tools\Python 3.12.9\python.exe main.py -u http://127.0.0.1:19321/ --auth-login admin:admin123 --report artifacts/round2/d1-auth --no-pause --no-cta
D:\tools\Python 3.12.9\python.exe C:\Users\HZR\Desktop\若依系统\scripts\d1_start.py stop

# A2 两遍
D:\tools\Python 3.12.9\python.exe C:\Users\HZR\Desktop\若依系统\scripts\a2_start.py start
D:\tools\Python 3.12.9\python.exe main.py -u http://127.0.0.1:19341/ --report artifacts/round2/a2-anon --no-pause --no-cta
D:\tools\Python 3.12.9\python.exe main.py -u http://127.0.0.1:19341/ --auth-login admin:admin123 --report artifacts/round2/a2-auth --no-pause --no-cta
D:\tools\Python 3.12.9\python.exe C:\Users\HZR\Desktop\若依系统\scripts\a2_start.py stop
```
