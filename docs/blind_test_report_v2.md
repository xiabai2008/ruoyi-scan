# ruoyi-scan v1.5.4 盲测 v2 报告

- 盲测日期：2026-11-01
- 被测版本：`v1.5.4-blindtest-v2`（commit `944298b`），54 个插件
- 靶场：`lab-blindtest-v2`（commit `8917690`），27 座
- 原始数据：`artifacts/blind_v2/`（扫描器 61 份报告 / nuclei 27 份 / GT 27 份）

---

## 0. 本次盲测没覆盖到的能力

先说不行的，避免把「没测」误读成「没问题」：

1. **R8（RuoYi-Cloud）**：独占型靶场（7 个 JVM 约 4.2GB），与其余靶场无法共存，
   本轮未跑。Cloud 变体、Nacos 未授权、Gateway 路由全部未测。
2. **端口层**：未做 `--portscan`。redis_unauth 等插件硬编码默认端口的问题因此未暴露。
3. **`--serve` / `--distributed` / `--passive` / `--crawl` / JS 渲染**：均未测。
4. **鉴权后深度检测**：R6/R7/R9 的 auth 扫描退出码 4（登录失败），
   这些站的鉴权后能力本轮未测到。
5. **非若依框架**：只测了 Spring / Jeecg 生态，其他框架无覆盖。

---

## 1. 总体结论

**最有价值的发现不是「漏了什么漏洞」，而是两类会导致「成片漏报/成片误报」的结构性缺陷：**

1. **弱指纹排他加载** —— 根路径返回 Spring Boot 默认错误 JSON 就把 cms 判成 `spring`，
   于是 ruoyi / jeecgboot **整包插件不加载**。C4-4/C4-5 两个真实存在的 SSTI 被判 0。
2. **catch-all 路径回显** —— 带 `/**` 兜底路由的站点，页面把请求路径写进正文，
   组件探测插件拿路径名当关键字，**100% 误判**。C4-6 上一次扫出 4 条 CONFIRMED，3 条是假的。

这两个都不是「某个插件判定不准」，而是**判定框架层面的问题**，影响面是整类场景。

一句话量化：GT 覆盖范围内 TP 10 / FN 1 / FP 2，但 FP 的 2 条背后是同一个会波及所有 SPA 的 bug。

---

## 2. 量化总表

三方对照口径：扫描器 = 被测版本；nuclei = 社区模板；GT = 独立手工探测（不导入扫描器代码）。

| 站点 | 扫描器 C | nuclei | GT 项 | 说明 |
|---|---|---|---|---|
| R1 | 1 | 0 | 15 | 默认口令真阳性 |
| R2 | 1 | 0 | 15 | |
| R3 | 2 | 0 | 15 | + /logs/ 目录可列 |
| R4 | 1 | 0 | 15 | |
| R5 | 1 | 0 | 15 | 误报检验站，1 条为默认口令真阳性 |
| R6 | 6 | 0 | 16 | 分离版，检出最多 |
| R7 | 8 | 0 | 16 | 含 Druid/Swagger/CORS/Actuator/.git |
| R9 | 3 | 0 | 11 | Plus 变体已正确识别 |
| R10 | 2 | 0 | 17 | JeecgBoot 版本 3.6.3 已识别 |
| R11 | 0 | 0 | 11 | 负样本，**0 误报** |
| R12 | 1 | 0 | 11 | WAF 站 |
| C1-1 | 5 | 9 | 22 | nuclei 唯一有命中的站 |
| C1-2 | 1 | 0 | 22 | |
| C1-3 | 1 | 0 | 22 | |
| C1-4 | 1 | 0 | 22 | |
| C2-1a | 3 | 0 | 22 | |
| C2-1b | 3 | 0 | 22 | |
| C2-2 | 0 | 0 | 22 | Spring4Shell，无 exploit 时诚实 0 |
| C2-3 | 0 | 0 | 22 | |
| C3 | 4 | 0 | 11 | 蜜罐站 |
| D1 | 1 | 0 | 11 | 二开变形 |
| A2 | 0 | 0 | 11 | 双因子，诚实 0 |
| C4-2 | 1 | 0 | 14 | P 类 |
| C4-3 | 1 | 0 | 15 | P 类 |
| C4-4 | **0** | 0 | 12 | P 类，**弱指纹缺陷** |
| C4-5 | **0** | 0 | 12 | P 类，**弱指纹缺陷** |
| C4-6 | 4 → 1 | 0 | 12 | **catch-all 误报** |

### GT 逐项对照

| 指标 | 数值 |
|---|---|
| 一致 TP | 10 |
| 漏报 FN | **1** |
| 误报 FP | **2**（同一个 bug） |
| 需人工 | 8 → **已逐条核实，全部是扫描器正确**（GT 探测盲区） |

---

## 3. 问题清单（按影响面排序）

### P0-1 · 弱指纹排他加载，整包插件被跳过

- **现象**：C4-4（jmreport SSTI）、C4-5（代码生成 SSTI）判 0 CONFIRMED，
  而靶场真的存在漏洞（手工验证 `POST connUrl=${7*7}` → 响应 `query=49`）。
- **证据**：
  ```
  指纹识别：cms=spring 置信度=0.50 命中=['root_json:timestamp,status,error,path']
  未匹配插件包，回退默认 ruoyi + spring 插件包
  插件数：26（无任何 jeecgboot / ruoyi 插件）
  ```
- **根因**：`core/fingerprint.py:141` 把 `root_json_keys` 命中算作**强特征**
  （`strong_hits += 1`），单独命中给 0.5 置信度。而「返回 Spring Boot 默认错误 JSON」
  只说明这是个 Spring 应用，不排除它同时是若依/Jeecg。`core/router.candidates()`
  按 cms 单值只加载一个包。
  ```
  GET / → {"timestamp","status","error","path"}
  → cms=spring → 只加载 plugins.spring
  → plugins.jeecgboot / plugins.ruoyi 整包不加载
  → freemarker_ssti / ruoyi_gen_rce 根本没被调用
  ```
- **影响面**：**所有返回 Spring Boot 默认错误 JSON 的首页**，且该站同时是若依/Jeecg。
  一个错误指纹屏蔽掉整个插件包的漏洞面。
- **修法**：`core/orchestrator.py` 增加弱证据扩展 —— cms 非空但置信度 ≤ 0.5 时，
  保留原包并补加载 ruoyi / spring / jeecgboot。强证据（> 0.5）行为不变。
  提交 `6217af4`。

### P0-2 · catch-all 路径回显被当成组件存在

- **现象**：C4-6 扫出 4 条 CONFIRMED，其中 3 条是假的：
  ```
  RocketMQ Dashboard 未授权   /rocketmq/        → <h2>页面: rocketmq/</h2>
  RuoYi Swagger 未授权访问    /swagger-ui.html  → <h2>页面: swagger-ui.html</h2>
  未授权访问（批量）          /                → 同上
  备份文件泄露                60 个假备份       → 全部是同一个 catch-all 页
  ```
- **根因**：靶场用 `/**` 路由兜底，页面把请求路径写进标题。组件探测插件拿路径名当关键字，
  于是「响应体出现 rocketmq」= 「rocketmq 存在」。
  **最麻烦的是这类 catch-all 每个路径响应长度都不同**（路径越长相，长度越长），
  所以长度比对、逐字节摘要、归一化摘要全部失效。
- **影响面**：**所有带 catch-all 路由的站点**（任何 SPA、任何 `/**` 路由后端）。
  盲测 v1 报告记过类似问题（07 §4.8 错误页回显路径），但显然没修彻底 ——
  当时只覆盖了 JSON 回显，管不了 HTML。
- **修法**：`lib/matcher.is_path_echo_page()` + `lib/soft404._html_echoes_path()`，
  接入 rocketmq_unauth / ruoyi_swagger_unauth / unauth_batch / soft404 基线。
  判据保守：只处理**短页面**（<600 字节）+ **确实是 HTML** + **页面里出现请求路径**。
  提交 `05c6ceb`。

### P1 · 8 条「需人工」已核实：全部是扫描器正确

逐条手工验证（详见 `docs/blind_v2/需人工项核实结果.md`），**没有一条误报**：

| 站 | 项 | 手工验证证据 |
|---|---|---|
| R6 | Swagger | `/prod-api/v3/api-docs` → `标题：若依管理系统_接口文档` |
| R6 | Druid 弱口令 | `submitLogin ruoyi/123456` → **`success`** |
| R7 | Swagger | 同上 |
| R7 | Druid 弱口令 | **`success`** |
| R7 | `.svn`/`.idea` | 200（我建的真诱饵） |
| R9 | Swagger | `RuoYi-Vue-Plus多租户管理系统_接口文档` |
| R9 | CORS | `Origin: http://evil.test` → **精确反射**（非通配） |
| R9 | Plus 认证接口 | `/prod-api/auth/login` → 200 |
| R10 | Swagger | `JeecgBoot 后台服务API接口文档` |
| C3 | 4 条 | 蜜罐诱饵真实存在，**A 类可接受** |

**GT 测不到的原因**：分离版的管理端点匿名可达但路径在 `/prod-api/` 下，
GT 的通用探测用根路径，且遇到 401/302 就判「不可判定」。这是 GT 的盲区。

> C3 值得单独说：4 条全是 **A 类诱饵**（假文件确实存在），**0 条 B 类硬误报**。
> 对比盲测 v1 当时有 1 条 B 类（`Swagger API 文档泄露` 在 `paths={}` 时仍判泄露），
> 已在 F7 修掉 —— 这是本轮相对 v1 的实质进步。

### P2 · 唯一的真 FN：R1 `/docs/ry_20210415.sql`（不修，属设计边界）

```
GET /docs/ry_20210415.sql  →  200 / 12595 字节   真实存在
扫描器 → UNKNOWN
```

**试过修，但方向错了。** `backup_scan` 只探根路径固定文件名不覆盖子目录，
我加了「常见遗留目录 × 常见扩展名」的探测，实测仍检不出：

```
GET /docs/          →  404（目录不可列）
GET /docs/docs.sql  →  404（真实文件名是 ry_20210415.sql，猜不到）
```

**目录不可列 + 文件名不可预测**（建库脚本常带日期）→ 字典法本质无解。
硬凑只会拖长扫描时间且命中率极低。

**决定不改**，写进已知边界。需要覆盖这类泄露时应用 `--crawl` / `--js-extract`
先收集路径，或从 `.git`/`.svn` 泄露中拿到真实文件名后定向验证。

### 观察项 · nuclei 的覆盖面与误报

- 27 个目标，nuclei **只在 C1-1 有命中**（9 条）。它的模板针对有公开 CVE 的漏洞，
  本靶场测的是配置类与逻辑类问题，两者不重叠。
- **nuclei 自己误报了一条**：`jolokia-logback-jndi-rce`（high）只看到
  `/actuator/jolokia/list` 响应体含 `logback` 就判 high，而 body 里 `JNDI` 出现 0 次。
  Jolokia 是 JMX over HTTP 的通用桥，只要 JVM 有 logback 就会列出它的 MBean ——
  这只证明「logback 在跑」，不证明「能用 JNDI 打」。

> **方法论**：第三方基准也会用「关键词命中」冒充验证。
> 不能因为「nuclei 报了而扫描器没报」就认定漏报，必须回到 GT。

---

## 4. 能力维度评分

| 维度 | 评分 | 依据 |
|---|---|---|
| 版本指纹精度 | **能** | R1–R5 全部精确（4.5.1/4.6.2/4.7.8/4.8.0/4.8.3）；R6 3.9.2 / R7 3.8.9 / R9 5.6.2 / R10 3.6.3 本轮也已识别（v1 时全空） |
| 变体识别 | **能** | R9 `variant=ruoyi-plus` 正确；R6/R7/R10 的 cms 与版本都对 |
| 未授权检测 | **能** | R7 检出 Druid/Swagger/CORS/Actuator；C1 系列全中 |
| 鉴权后检测 | **勉强** | R1–R5 auth 成功（status=ok），但 R6/R7/R9 登录失败（退出码 4），这几站的鉴权后能力未测到 |
| 上下路径适配 | **能** | R6/R7/R9 的 `/prod-api` 前缀探测正常；R10 的 `/jeecg-boot` 也对 |
| 三态判定质量 | **能** | R13 hold-out 上假 200 判 UNKNOWN 而非 SAFE；A2 双因子诚实 0 |
| 误报控制 | **勉强→能** | 修复前 C4-6 有 3 条误报 + 60 个假备份；修复后 1 条真阳性。R11 负样本全程 0 误报 |
| 可复现性 | **能** | 同一站两次扫描结论一致 |

---

## 5. 不建议改的东西

1. **R1–R5 无会话时 SAFE=0、UNKNOWN≈25**：登录墙下「没测到」就是 UNKNOWN，
   这是三态纪律的正确表现。不要为了降低 UNKNOWN 判 SAFE。
2. **R5 的 1 条 CONFIRMED**：是默认口令真阳性（4.8.3 站点的 admin/admin123 确实可登录），
   不是误报。R5 作为「误报检验站」的定位不变。
3. **C2-2 Spring4Shell 判 0**：无 `--exploit` 时不写入 JSP，无法证实 RCE，
   诚实判 UNKNOWN/0 是正确行为。不要为了「有检出」去放宽。
4. **A2 判 0**：TOTP 双因子挡住，扫描器无法验证，UNKNOWN 是正确降级。
5. **R12 只报 1 条**：WAF 拦了大部分 payload，这与 R2 的 1 条一致，说明 WAF 层没造成额外误判。
6. **nuclei 的 9 条命中不追加修复**：那是第三方误报，不是我们的代码。

---

## 6. 阶段 4 未污染验证（R13）

R13 = R2 后端 + 加固版 WAF，复刻真实商业 WAF 四类行为（特征拦截 / 扫描器 UA /
统一拒绝页 / **敏感路径假 200**），**盲测阶段 1–3 全程未接触**。

| 验证项 | 期望 | 实测 | 判定 |
|---|---|---|---|
| `.git`/`.env`（假 200，内容是维护提示） | 不 CONFIRMED | **UNKNOWN** | ✅ |
| SQL 注入（被 403 拦） | UNKNOWN，不是 SAFE | **UNKNOWN** | ✅ |
| 默认口令（真实漏洞） | CONFIRMED | **CONFIRMED** | ✅ |
| WAF 是否影响正常业务 | 不应影响 | cms=ruoyi 0.70 正常 | ✅ |

**没有一条误报，没有一条把「被拦截」写成「不存在」。**

比预期更好：假 200 的 `.git` 判的是 **UNKNOWN** 而不是 SAFE ——
内容不像真 `.git/HEAD` 不能判 CONFIRMED，但也可能是 WAF 伪造响应不能断言不存在，
按三态纪律就该 UNKNOWN。说明 P0-2 的修复没有过度抑制。

> **局限**：R13 只覆盖「WAF 前置 + 同源后端」一种形态，不能代表所有真实环境。
> 它证明的是「修复不是对已知靶场的拟合」，**不等于**「在任意生产环境都准确」。

---

## 7. 方法论收获

### 7.1 「按真实产品形态建靶场」比盲测更早发现缺陷

阶段 0.4 建 C4 靶场时，因为坚持不照插件源码凑路径，当场碰出 4 个缺陷（P 类）：

| 编码 | 缺陷 | 只有真实形态靶场能发现的原因 |
|---|---|---|
| P1 | rocketmq_unauth 探 `/rocketmq/` 等前缀 | 真实控制台在根路径，签名靶场永远暴露不了 |
| P2 | minio_unauth 探 `/minio/`（控制台登录页） | 真实匿名列举走 S3 根路径 |
| P3 | freemarker_ssti 把「要 Token」当「不存在」 | 真实鉴权拒绝是 HTTP 200 + body code 500 |
| P4 | ruoyi_gen_rce 只探可达性 | 有洞没洞都返回同样的 200 HTML |

这 4 条已单列在 `docs/blind_v2/P类缺陷清单.md`，**不计入盲测检出率**。

### 7.2 盲测流程本身测不出「路径靠想象」

P1/P2/P4 都是「探的路径不是真实产品路径」。这类缺陷在盲测里**看起来完全正常** ——
猜错的路径返回 404/SAFE，报告显示「不存在该漏洞」，一个合理的结论。

**没有 ground truth 对照，无法区分「真的不存在」和「根本没探到」。**
这就是必须做三方对照的原因。

### 7.3 GT 自己也会错

做对照时最初有 **20 条假 FN**，根因是我的 GT 判据漏识别三类 catch-all
（Config Server 回显 / Cloud Function 回显 / Thymeleaf 的 `/**`）。

修的过程中还踩了反向坑：判据收得太宽时，`.git/HEAD` 的内容
`ref: refs/heads/master` 含 `head`，被误判成回显 → 真漏洞反而漏报了。

**教训：ground truth 必须先自检。** 三方对照的价值正在于此 ——
如果只有 GT 一家，那 20 条假 FN 会被当成扫描器的锅。

---

## 8. 交付物

```
docs/
├─ blind_test_report_v2.md            ← 本报告
├─ blind_v2/
│  ├─ 盲测v2冻结记录.md                ← 版本、环境、纪律
│  ├─ P类缺陷清单.md                   ← 建靶时预发现的 4 条（不计入盲测）
│  ├─ 阶段2_三方对照结论.md            ← 扫描器 / nuclei / GT 三方
│  ├─ 阶段4_holdout验证方案.md         ← R13 的设计与纪律
│  └─ 阶段4_holdout验证结果.md         ← R13 实测结果
artifacts/blind_v2/                    ← 原始数据（不入库）
├─ *-anon/ *-auth/                     ← 61 份扫描报告
├─ nuclei/                             ← 27 份 nuclei 结果
├─ gt/                                 ← 27 份手工探测结果
└─ compare_report.md / gt_compare.md    ← 自动化对照输出
```
