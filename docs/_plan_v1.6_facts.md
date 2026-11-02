# v1.6 规划 · 主 agent 核实的事实基线

> 这份文件记录「我自己核实过」的数据，与三个调研 agent 的报告合并后才形成最终计划。
> 每条都注明核实方式，便于复核。

---

## 一、盲测 v4 的 UNKNOWN 构成（决定 v1.6 的优先级）

从 `artifacts/blind_v4/*/report.json`（61 份报告）聚合全部 UNKNOWN 条目，按证据文本归类：

| 原因 | 条数 | 占比 | 性质 |
|---|---|---|---|
| **登录墙降级** | 168 | 41% | **其中大部分是误降级（缺陷 A/A2）** |
| 其它（SAFE 缺证据等） | 161 | 39% | 插件质量问题（缺陷 D） |
| **缺少低权账号** | 107 | 19% | 靶场供给问题（缺陷 C） |
| 「未取得高权会话」降级 | 72 | 18% | 3 个正确声明 requires_auth 的插件 |
| 兜底路由无法区分 | 23 | 6% | 设计边界 |

**总量口径**：61 份报告共 **1849 条结果，其中 UNKNOWN 567 条（30.7%）**。
上表按证据首要关键词归类（分类有重叠），能归类的约 530 条。

**结论：认证相关的「测不了」约 347 条（登录墙 168 + 低权账号 107 + 高权会话 72），
但实际上其中一大批是误降级——不是缺能力，是判定链把正确答案改错了。**
这比「再补几个插件」的 ROI 高得多。

> **v1.6 的第一优先级因此是「让 UNKNOWN 说真话」**：
> 567 条里有多少是「真测不了」、多少是「被自己降级掉的正确答案」，
> 这个比例决定了后续工作该投在判定链还是靶场。

---

## 二、已确认的真缺陷

### ⚠ 修正记录（重要）：我最初判断「登录墙降级过度」是**错的**

初稿把 168 条登录墙降级当成误降级。**实测推翻了该判断**：

```
R1（4.5.1 单机版，Shiro 全路径保护）实测：
  /.git/HEAD        → 302 → /login   （不是 200！）
  /.env             → 302 → /login
  /backup.bak       → 302 → /login
  /index.bak        → 302 → /login
  /minio/health/live        → 302 → /login
  /nacos/v1/auth/users      → 302 → /login
  /v3/api-docs              → 302 → /login
  /druid/index.html         → 302 → /login
```

若依（Shiro）默认**保护所有不在匿名白名单里的路径**——包括根路径的静态资源探测。
所以：

- `path_scope="root"` 的 `.git/.env/备份/IDE 残留`：SAFE 证据「状态码=200, 未检测到特征」
  里那个 200 是**登录页**，不是目标文件。**降级为 UNKNOWN 是正确的**。
- 未授权类（MinIO/Nacos/Swagger/Druid）：探测路径同样被 302 拦截，
  「未命中特征」不能证明「未授权接口不存在」。**降级也是正确的**。
- R11（无登录墙）正常判 SAFE、R1（有登录墙）判 UNKNOWN，是**真实差异**，不是缺陷。

**结论：登录墙降级链本身没有语义错误。** 原「缺陷 A / A2」撤回。

但这暴露了一个**真正的问题**（见缺陷 A'）。

### 缺陷 A'：降级后丢了「为什么测不了」的可操作信息（P1）

168 条降级后的证据统一是「目标存在登录墙（…），需登录后才能判定」，
读者只能知道「测不了」，不知道**该怎么办**。而实际上每条都有明确解法：

| 插件类 | 解法 | 说明 |
|---|---|---|
| `.git/.env/备份/IDE 残留`（root 类） | 加 `--auth-login` 后重扫 | 登录后 Shiro 放行，这些路径就能真实探测 |
| MinIO/Nacos/Swagger/Druid 等未授权类 | 同上，但**语义要变** | 登录后若能访问，那是「已认证可达」不是「未授权」；需改用未登录视角复核 |
| 越权类 3 插件 | 加 `--surface-account` | 需低权账号 |

**这里有一个真实的判定陷阱**：未授权类插件在**已认证**会话下跑，
拿到 200 会 CONFIRMED——但那是「登录后能访问」，不构成「未授权访问」漏洞。
这是**假阳性风险**，且当前代码没有防护。

**修复方向**：
1. 未授权类插件（`vuln_type in ("unauth","info_leak")` 或名称含「未授权」）
   必须用**独立无凭据会话**探测，不能用共享的已认证会话
   （`plus_job_unauth` 已有这个防护：`_has_auth_state()` 检测到认证态就用新会话，可推广）。
2. 降级证据里补上「解锁方式」：`需 --auth-login 后重扫` / `需 --surface-account`。

### 缺陷 B：requires_auth 声明不全（P2，需逐个判定）

只有 3 个插件声明 `requires_auth=True`（POST型报错注入 role/dept、代码生成 SSTI）。
但实际有 72 条「未取得高权会话」降级来自这 3 个，说明声明与行为基本对齐。

真正的问题是：**其他插件在缺会话时靠登录墙降级兜底，而不是自己声明依赖**。
这不算 bug（链式兜底有效），但让「哪些插件需要会话」这件事散落在两套机制里，
不好维护。属于可维护性债务，不是正确性缺陷。

### 缺陷 C：越权类插件「缺低权账号」——**是测试方法问题，不是产品缺陷**

> ⚠ 这条我连续判断错了三次，逐条记录以免后人重蹈：
>
> **第一次**：凭记忆写「靶场只有 R1-R5 建了 scanner_low」。
> **第二次**：grep `seed/r*_business.py` 看到 R2-R7 有 `scanner_low`，改口「R2-R7 有，R1 没有」。
> **第三次（最终，实测确认）**：
> - `scanner_low` 在 seed 里**只是** `build_logins()` 中用来生成伪造登录日志的假数据，
>   `staff += [("admin", ...), ("scanner_low", ...)]` 与真实账号创建无关；
> - 但数据库里**确实有**该账号（`ry_r2.sys_user` user_id=100, dept_id=105），
>   salt=`mtrx01`，密码 `LowPriv_2026`（md5 校验通过）；
> - 用**扫描器自己的登录链**登录 R2 成功（`login_with_password` → ok=True）。
>   裸 POST 失败只是因为 R2 是 4.6.2、登录必须带验证码。

**真实根因**：盲测 v4 驱动脚本 `run_blind_v4.ps1` 里，
**只有 R1-R5 的 surface 轮传了 `--surface-account`**（第 62 行），其余 40+ 轮都没传。
所以 107 条「缺少低权账号」是**扫描方式问题**。

证据：传了账号的 surface 轮次**完全正常**——

```
R1-surface: 定时任务调用目标未校验 CONFIRMED、重置密码页越权 CONFIRMED
R2-surface: 定时任务调用目标未校验 CONFIRMED、重置密码页越权 CONFIRMED
R3-surface: 重置密码页越权 CONFIRMED、部门树越权 CONFIRMED
```

**结论**：WP-U2 不需要补账号供给，需要的是**修正盲测方法**——
驱动脚本给所有 ruoyi 站点都传 `--surface-account`。这是测试脚本的事，不是产品代码的事。

### 缺陷 D：SAFE 缺证据 —— ✅ 已修（`f0e8ebe`）

盲测 v4 里「SAFE 缺少判定证据」降级 49 条，**全部来自 jeecgboot 的 7 处 SAFE 分支**。
已逐处补齐证据，并加了 AST 门禁 `test_no_plugin_returns_safe_without_evidence`
（全库 SAFE 缺证据已清零）。

### 缺陷 B：requires_auth 声明不全（P2，可维护性，非正确性）

只有 3 个插件声明 `requires_auth=True`（POST 注入 role/dept、代码生成 SSTI）。
其余插件在缺会话时靠登录墙降级兜底，而不是自己声明依赖。
链式兜底有效，不算 bug；但「哪些插件需要会话」散落在两套机制里，不好维护。

---

---

## 三、已核实的能力现状（避免重复建设）

### 组件 CVE 比对：20 个组件 / 44 条 CVE

数据在 `data/component_cve_map.json`（**不是** `lib/component_detect._COMPONENT_SPECS`，别找错地方）。
按组件：fastjson 3、spring-boot 3、shiro 5、nacos 3、log4j 4、druid 1、xxl-job 2、
solr 2、rabbitmq 1、elasticsearch 1、kibana 2、tomcat 5、jetty 2、shenyu 2、
jenkins 2、eureka 1、minio 1、grafana 2、sentinel 1、consul 1。

### 离线 CVE 库：20 条，时效滞后

`data/cve_offline.json`：`updated: 2026-09-09`（距 v1.6 规划约 2 个月），
`entries` 20 条，`aliases` **全为空**。
来源是 `scripts/build_offline_cve.py` 从 `component_cve_map.json` 生成。

**缺口**：CNVD/CNNVD 别名缺失（ROADMAP G1 已点名）；库容量只有组件映射那一层，
没有独立的 CVE 详情库。纯数据类任务，适合外部贡献。

### mypy 严格化：core/common 已清零，lib/api 仍 ignore_errors

```toml
[[tool.mypy.overrides]]
module = ["lib.*", "api.*"]
ignore_errors = true
```

`lib/` 60 个文件 + `api/`，共约 19000 行。抽查 `lib/matcher.py`、`lib/attribution.py`、
`lib/soft404.py`、`lib/reporter.py` 四个文件 strict 模式**零错误**，说明不是全盘烂，
而是「按模块逐步收紧」可行——ROADMAP G2 本身就是这个策略。

### 覆盖率棘轮：已按目录设阈值

`core 78% / common 84% / lib 72% / api 85% / plugins 75% / chains 95%`，
「只许升不许降」。机制健康，不需要重做。

### nuclei 兼容层：3 个自建模板

`contrib/nuclei-templates/`：`ruoyi-default-password.yaml`、`ruoyi-job-unauth.yaml`、
`ruoyi-unauth-api.yaml`。加载器只支持 http 协议 + status/word/regex/dsl 白名单。
ROADMAP G4 已记录「上游 PR 被拒，转自建包」的策略。

---

## 四、v1.6 待验证的问题（交给调研 agent / 需现场确认）

1. 那 240 条「缺会话」里，哪些是真需会话、哪些是被缺陷 A 误降级的？
2. 剩余 6 个零产出插件里，「任意文件读取 ×2」能否靠给现有站点开未授权读点解决？
3. 横向扩框架（yudao / SpringBlade / Pig）的成本与价值，是否该现在做？
