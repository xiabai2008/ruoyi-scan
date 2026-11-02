# v1.6 计划（草稿 v1）

- 制定：2026-11-02
- 前置：v1.5.6 已发布（48/54 插件有 CONFIRMED）
- 事实基线：`docs/_plan_v1.6_facts.md`（主 agent 核实）
- A2 已完成：`docs/_design_A2_unauth_session_isolation.md`

> 状态：**框架扩展部分已定稿，靶场部分待补**（靶场调研 agent 未回）

---

## 零、一句话定位

**v1.6 = 让 UNKNOWN 说真话 + 还技术债 + 只吃一个新框架（芋道）。**

不追插件数量。567 条 UNKNOWN 里有多少是被自己降级掉的正确答案，
这个比例决定了后续该投判定链还是投靶场。

---

## 一、已完成（A2，2026-11-02）

| 提交 | 内容 |
|---|---|
| `7a7bbd3` | 未授权类插件统一用匿名会话探测（4 个补 `anonymous()`；`looks_authenticated` 反向证据；`anonymous_probe` 声明 + 互斥校验） |
| `7308b9a` | 降级证据补「怎么才能测到」（按能力四类分流；7 个插件的登录墙文案统一） |

**核心教训（已写进设计文档）**：`core/session.py` 早就有了 `SessionManager.anonymous()`，
我的初版方案是重复建设。**动手前先 grep 现有 API**，比设计新机制便宜得多。

---

## 二、主优先级：让 UNKNOWN 说真话

数据（`docs/_plan_v1.6_facts.md` §一）：1849 条结果中 567 条 UNKNOWN（30.7%）。

| WP | 内容 | 依据 |
|---|---|---|
| **WP-U1** | JSON 信封鉴权墙识别（**P0，加新框架前必做**） | 见 §三 |
| **WP-U2** | 越权类插件缺低权账号（107 条） | 靶场只有 R1-R5 建了 `scanner_low` |
| **WP-U3** | SAFE 缺证据补齐（49 条） | 插件质量问题，适合 Good First Issue |

---

## 三、WP-U1：JSON 信封鉴权墙（**已核实，是真缺陷**）

### 问题

`lib/reachability.py` 的 `_DENY_RE` 要求 `code` 后紧跟 `[:=]`，
**认不出引号包裹的 JSON 形态**：

```python
_DENY_RE = re.compile(r"(?:状态码|status|code|HTTP)\s*[:=]?\s*(401|403|429)\b", re.I)
```

实测（2026-11-02 主 agent 验证）：

| 输入 | 是否认出 |
|---|---|
| `{"code":401,"msg":"账号未登录"}` | **False** ❌ |
| `{"code": 401}` | **False** ❌ |
| `{"code":403,"data":null}` | **False** ❌ |
| `状态码=401` | True ✅ |
| `HTTP 401` | True ✅ |

### 为什么是 P0

1. **芋道（yudao）的未授权响应正是这种形态**：
   `ServletUtils.writeJSON(response, CommonResult.error(UNAUTHORIZED))`，
   且 hutool 的 `write` **不设 HTTP status** → 响应是 `HTTP 200 + {"code":401,...}`。
   直接加芋道插件会重演「把没测到写成 SAFE」的 B 类缺陷。
2. **Jeecg 也有同类问题**：`{"success":false,"code":500,"message":"Token校验失败"}`。
   Jeecg 那次是在**插件内部**补的（`29f460b` 的 `_jmreport_auth_wall`），没上升到通用层。
3. 当前靶场无影响（若依用 HTTP 401/302）——**盲测 v4 实测 0 条受影响**，
   所以这是「未来必然踩、现在测不出」的缺陷，必须在扩框架前修。

### 修法

```python
# 允许引号包裹：{"code":401} / {"code":"401"} / code=401 / HTTP 401
_DENY_RE = re.compile(
    r'(?:状态码|status|code|HTTP)\s*[:=]?\s*["\']?\s*(401|403|429)\b', re.IGNORECASE
)
```

**关键约束：不能误伤 `code:0`**。芋道的成功码是 `0`（不是 `200`），
`{"code":0,"data":[]}` 是**正常业务响应**，绝不能当拒绝。上面正则只匹配 401/403/429，安全。

### 配套门禁

加一条测试：把三种主流框架的「未授权响应原样」作为语料——
若依 `{"code":401,"msg":"认证失败"}`、Jeecg `{"success":false,"code":500,...}`、
芋道 `{"code":401,"msg":"账号未登录"}`——断言 `upgrade_denied_safe_to_unknown()` 都能识别。
**用法**：以后加新框架，把它的未授权响应加进这份语料即可，不用改代码。

---

## 四、WP-F：横向扩展（只做芋道，已核实）

### 4.1 为什么是芋道，且只做它

| 判据 | 芋道 | SpringBlade | Pig | Guns |
|---|---|---|---|---|
| 装机量（GH+Gitee） | **~152k** | ~28k | ~7k | ~4k |
| 与若依血缘 | 直接 fork Pro 版，`/system/*` 同源 | 独立 RBAC | OAuth2 | 自研 kernel |
| 已公开 CVE | **22 条，持续新增** | 16 | 4 | 11（**全是噪声**） |
| 可复用现有插件 | 4 个 jeecg jmreport 插件可直接复用 | 仅 Druid/springdoc | 仅 Druid/springdoc | 低 |
| 通用能力收益 | 「JSON 信封鉴权墙」「日历版本号」是长期资产 | 低 | 最低 | 无 |

**Guns 建议从 ROADMAP 移除**：最后 push 2025-11-15（近一年停滞）、自研 kernel、
NVD 11 条命中全是「Quake3/Android 游戏」类噪声。
若要补第四家，用 **eladmin**（21.9k star / 25 条 CVE / 单机 Spring Security，无网关无租户无验证码），
比 Pig/Guns 都划算。

### 4.2 芋道的三条关键事实（agent 核实上游源码）

1. **内置 JeecgBoot 的积木报表**，且 `/jmreport/**` 在 `permitAll` 白名单：
   `jimureport.version = 2.3.4`。
   → `plugins/jeecgboot/` 的 4 个 jmreport 插件**可直接复用**，只需加
   `/admin-api/jmreport/*` 与 `/jmreport/*` 候选路径。
2. **有免鉴权探针**：`GET /system/tenant/simple-list`（`@PermitAll @TenantIgnore`，
   无需 token 无需租户头）→ 比现在靠验证码图片更稳，且可把「前缀探测」从
   「必须找到验证码」解绑（通用收益）。
3. **未授权响应是 `HTTP 200 + {"code":401}`**，见 WP-U1。

### 4.3 硬约束：芋道的验证码不可 OCR

芋道用 **aj-captcha 滑块**验证码，而 `core/captcha_solver.py` 是 ddddocr 字符识别 +
算术求值。滑块拼图需要 CV 求解器。

→ **芋道首版放弃 `--auth-login`**，只做匿名面 + 预置 token（`--auth-token`）。
否则会重复 F10 的 exit-4 循环（`--auth-login` 恒失败，依赖会话的插件全 UNKNOWN）。

### 4.4 现有架构的扩展成本（agent 实测，需复核）

「快乐路径」很便宜（3 处改动 ≈ 20 行），但 **Jeecg 的真实账单是 350 行核心 + 450 行测试**：

| 文件 | Jeecg 增量 | 耦合性质 |
|---|---|---|
| `core/auth_chain.py` | +183 行 | 含 `_login_v5_jeecg()` 42 行专属逻辑 |
| `core/fingerprint.py` | +146 行 | `_cms_from_doc_title()` 只认 jeecg/ruoyi 两 token |
| `core/basepath.py` | +70 行 | `_looks_like_jeecg_api()`、`_JEECG_BASES` |

**5 处「按 CMS 写死」的地方**，每加一个框架都要加一个 `or cms == "<新框架>"`：
`detect_cms()`、`_API_DOC_BASES`、`basepath.CANDIDATES`、`auth_chain.login_style`、
`orchestrator._EXPANDED_PACKAGES`。

> ⚠ 这些数字来自 agent 的 git numstat 统计，我未逐条复核。
> 但「5 处硬编码」我亲自 grep 确认存在。

### 4.5 工作包

| WP | 内容 | 依赖 |
|---|---|---|
| **WP-F0** | 通用能力数据化：`CANDIDATES` 加 `/admin-api` `/app-api`；前缀探测改成「每框架注册一个匿名探针」的数据表（不再写 `if`）；`_EXPANDED_PACKAGES` 改从 `discover_plugin_packages()` 派生 | WP-U1 |
| **WP-F1** | `plugins/yudao/` 6–8 个插件：4 个 jmreport 复用 + GoView SQL 注入 + 租户绕过 + Druid + 默认口令 | WP-F0 |
| **WP-F2** | `CMS_FEATURES["yudao"]` 指纹；日历版本号 `2026.xx` 提取 | WP-F1 |

---

## 五、WP-R：还 Jeecg 的注册债（**已核实全部是真 bug，必须同批做**）

Agent 报告了 6 处，我用命令逐条验证：

| 位置 | 问题 | 我的验证结果 |
|---|---|---|
| `main.py:99` | `--cms` 的 `choices=["ruoyi","spring"]` | ✅ **实测报错**：`invalid choice: 'jeecgboot'` |
| `lib/plugin_sdk.py:492`、`ai_generator.py:297`、`ai_validate.py:226` | `category not in ("ruoyi","spring","common")` 抛错 | ✅ grep 确认 3 处 |
| `lib/plugin_repo.py:113` | `export_plugins()` 只导 3 个包 | ✅ 确认遗漏 jeecgboot |
| `api/routes/plugin.py:41` | `cms="ruoyi"` 写死（注释还写着「扫描器面向若依框架」） | ✅ 确认，桌面端/Web 端把 jeecg 插件也标成 ruoyi |
| `data/acceptance_baseline.json` | 只有若依 vuln/safe 两个靶 | ✅ **实测**：`8080 vuln` / `8081 safe`，无 Jeecg |
| `scripts/verification_matrix.py` | 自动 glob，已含 jeecg | 无问题 |

**这意味着**：Jeecg 的 8/8 CONFIRMED 是**扫描能力**通了，**工程配套**没通。
`--plugin-new`、AI 生成插件、模板仓库签名分发、nightly acceptance 全都漏了它。

### WP-R 做法

不逐个打补丁，而是**改成派生 + 加门禁**：

1. `--cms` 的 choices、`category` 白名单、`export_plugins()` 的包列表
   **全部从 `discover_plugin_packages()` 派生**（一处改动解锁全部三条链路）。
2. 新增 `scripts/check_framework_registration.py`：扫 `plugins/` 下每个包，
   断言它出现在 router / `--cms` choices / `export_plugins` / acceptance 里。
   参照 `check_version.py` 的模式。
   **这是防止第 3 个框架再漏同一批的唯一办法。**
3. `data/acceptance_baseline.json` 加 Jeecg 靶（否则新框架插件永远没有回归门）。

---

## 六、待补：靶场规划

靶场调研 agent 未返回。已知需要：

| 靶场 | 目的 | 依据 |
|---|---|---|
| **C5：暴露但需认证** | 验证 A2 的 `looks_authenticated` | A2 设计文档 §3；现有靶场无法复现该边界 |
| **Y1：芋道真实站** | WP-F1 的 6–8 个插件 | 必须先有真实站才能验证 `permitAll` 是否生效 |
| 未授权文件读取点 | 解锁剩余 2 个零产出插件 | 盲测 v4 边界 |

---

## 七、明确不做

- **不做 SpringBlade / Pig / Guns 的 v1.6 版本**：Spring Boot 4 + WebFlux 网关 + Java 21
  是全新适配面，收益只有 16/4 条 CVE、合计 3.5 万 star。
- **不做「泛 Java 框架指纹库」**：ROADMAP 自己的「明确不做」写着不自建大而全指纹库。
- **不追插件数量**：567 条 UNKNOWN 说真话的收益，高于再加 10 个插件。

---

## 八、风险（开工前须现场核实）

1. **芋道生产 profile 的 Druid 控制台是否关闭**：agent 只核实了 `application-local.yaml`
   （开着、账号密码留空），`application-prod.yaml` 未验证。
2. **芋道 `/jmreport/**` 在真实部署里是否仍 `permitAll`**：二开项目常收紧。
   需在 Y1 验证后才能定 4 个插件是「直接复用」还是「路径复用、判据重写」。
3. **芋道验证码不可 OCR**：见 §4.3，首版放弃 `--auth-login`。
