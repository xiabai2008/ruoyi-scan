# 缺陷 A2 修复方案：未授权类插件的会话隔离

- 状态：**已实现**（2026-11-02）
- 前置阅读：`docs/_plan_v1.6_facts.md` §二（含一次判断被实测推翻的记录）

## 实施记录：方案在落地时被修正了两次

### 修正 1：不需要新建 `anonymous_probe` 引擎注入

初稿设计是「在 `PluginBase` 加 `anonymous_probe`，引擎在会话被污染时注入干净会话」。
实现时发现 **`core/session.py` 已有 `SessionManager.anonymous()`**，
而且它的注释记录的误报事故（2026-10-29 若依 v4.8.3「定时任务 RCE」5 个站点误报）
和我这次要修的是**同一类问题**。

更关键的是：`unauth_batch` 与 `ruoyi_swagger_unauth` **已经在用**这个 API 了。
我原本的方案是重复建设。

引擎层注入已回退，改为在缺防护的 4 个插件里直接用现有 API
（`minio_unauth` / `nacos_unauth` / `rocketmq_unauth` / `ruoyi_cloud_nacos`）。

> **教训**：动手前先 grep 一遍 `session.anonymous`，比设计一套新机制便宜得多。
> 这与 v1.5.6 的「先核实根因再动手」是同一条纪律。

### 修正 2：`anonymous_probe` 标志保留，但用途变了

保留 `PluginBase.anonymous_probe` 作为**声明**（表示「本插件判定未授权，必须用匿名视角」），
只是不再由引擎注入会话。它的价值在于：
- 让「哪些插件是未授权类」变成可查询的属性，便于审计与新插件检查；
- 与 `requires_auth` 的互斥校验（加载期硬报错）仍然有效——
  这两个标志同时为 True 是语义矛盾，早报错好过扫描时给一堆无法解释的 UNKNOWN。

### 修正 3：`looks_authenticated` 的正向特征要避开「列表数据」

测试暴露的坑：Nacos 未授权响应的 `pageItems` 里有 `username`/`password` 字段
（那是**用户列表数据**），如果按裸关键字匹配会被误判成「已认证」，
把真漏洞降级掉（假阴性）。

判据因此收紧为「**当前登录用户**身份回显」：
- ✅ 认：`"userName":"admin"` / `"nickName":` 出现在顶层、`"permissions":[...]`、`"access_token":`
- ❌ 不认：数组元素里的 `username`（列表数据）、普通埋点 cookie

两个测试用例专门锁住这条边界（`test_nacos_confirms_on_real_unauth_response` /
`test_nacos_unknown_when_response_has_login_user`）。

---

## 0. 先纠正一件事：这**不是**「语义反转」缺陷

初稿把「登录墙降级未授权类插件」判定为把答案改错。**实测推翻了该判断**：

```
R1（4.5.1 单机版，Shiro 保护全路径）实测：
  /minio/health/live     → 302 → /login
  /nacos/v1/auth/users   → 302 → /login
  /v3/api-docs           → 302 → /login
  /druid/index.html      → 302 → /login
```

这些插件的探测路径**确实被登录墙拦住了**，「未命中特征」不能证明「接口不存在」，
降级为 UNKNOWN 是正确行为。R11（无登录墙）判 SAFE、R1 判 UNKNOWN 是**真实差异**。

**真正的问题在别处，而且更危险**：见下。

---

## 1. 真问题：未授权类插件在已认证会话下会产生假阳性

### 1.1 现状核实

54 个插件里，**只有 1 个**做了会话隔离（用 `grep -c "_has_auth_state\|own_session"` 核实）：

| 插件 | 有会话隔离 |
|---|---|
| `plus_job_unauth.py` | ✅ 7 处防护 |
| `nacos_unauth.py` | ❌ 0 |
| `minio_unauth.py` | ❌ 0 |
| `unauth_batch.py` | ❌ 0 |
| `swagger_leak.py` | ❌ 0 |
| `ruoyi_swagger_unauth.py` | ❌ 0 |
| `ruoyi_cloud_nacos.py` | ❌ 0 |

### 1.2 为什么这是假阳性

未授权类插件的被测命题是「**不需要登录就能访问**」。它们用共享的 `SessionManager` 探测，
而该会话可能已被前置插件（如 `后台默认口令`）登录污染 —— 这是项目已知的「认证状态泄漏」
问题（`core/engine.py` 有长注释记录 v4.8.3 因此多出 6 个假 CONFIRMED 的历史事故）。

后果：

```
客户现场：Swagger 开了，但配了认证（登录后才能看）
→ 扫描器先跑「后台默认口令」拿到 admin/xxx 会话
→ swagger_leak 复用该会话 → 200 + 真实 Swagger 页面 → CONFIRMED「Swagger 未授权访问」
→ 但实际它需要登录才能访问，**不是未授权访问**
```

**这类报告拿去交付是会出事的**：客户复核时会说「我们明明加了认证」。
比漏报更损害信任。

### 1.3 为什么靶场测不出来

R1 是 4.5.1 单机版，这些端点**根本不存在**（登录后仍 302），所以现有靶场无法复现该风险。
**必须造一个「接口存在但需认证」的靶场**——见 §3。

---

## 2. 修复方案

### 2.0 已核实的技术前提

| 前提 | 结论 |
|---|---|
| `SessionManager.timeout` | ✅ 存在（`core/session.py:150`，默认 `settings.TIMEOUT`） |
| `SessionManager.authenticated` | ⚠️ 存在但**不可靠**——只在 orchestrator 显式设置，不反映插件中途登录造成的泄漏 |
| 可靠的认证态判断 | 已核实：检查 `session.session.cookies` 非空 + `Authorization` 头（`plus_job_unauth._has_auth_state` 的实现） |
| 同源 `SessionManager` 能否独立建 | ✅ `SessionManager(timeout=...)` 可直接实例化，`close()` 可释放 |

**结论**：`_has_auth_state` 这段逻辑要下沉到 `lib/`（如 `lib/session_state.py`），
因为它是「判断共享会话是否被污染」的唯一可靠手段，而 `session.authenticated` 不可用。

### 2.1 核心设计：能力下沉到基类，不让每个插件各写一套

`plus_job_unauth` 的实现是对的，但它是**手写在自己文件里的**——如果只推广「照着抄」，
6 个插件会各抄一遍，然后各自漂移（项目历史上已经吃过这种教训：
`file_read` / `file_read_path` 各自维护一份 passwd 判定，最后必须抽到 `lib/matcher.is_passwd_file`）。

**所以抽成 `PluginBase` 的能力**：

```python
# plugins/base.py
class PluginBase:
    # 未授权类插件：必须用无凭据会话探测，禁止复用可能已登录的共享会话。
    # 置 True 后，引擎会在调用 verify() 前注入一个干净的 session。
    anonymous_probe = False
```

引擎侧（`core/engine.py`）在 `_exec` 里：

```python
exec_session = session
own_session = None
if getattr(cls, "anonymous_probe", False):
    if _session_has_auth_state(session):
        own_session = SessionManager(timeout=session.timeout)
        exec_session = own_session
try:
    original = cast(ScanResult, inst.verify(exec_target, exec_session))
finally:
    if own_session is not None:
        own_session.close()
```

**为什么放在 engine 而不是每个插件**：
- 与现有的 `requires_auth`（引擎统一降级）、`path_scope`（引擎统一选基准）
  保持同一种设计语言：**能力声明在插件，执行策略在引擎**；
- 插件作者只需 `anonymous_probe = True` 一行，不需要理解会话泄漏；
- 未来新增未授权类插件自动获得防护，不会遗漏。

### 2.2 判定端补一道保险：响应里出现认证成功特征就不能判未授权

即使会话隔离做对了，还有一种情况：目标把「未授权可访问」和「登录后可访问」返回得一模一样。
所以判定端要有第二道防线——**看响应里有没有认证痕迹**：

```python
# lib/matcher.py 新增
def looks_authenticated(body: str, headers: Mapping[str, str]) -> bool:
    """响应是否透露出「当前会话已认证」的迹象。

    用于未授权类插件的反向证据：如果拿到的 200 是「已登录用户」的响应，
    就不能判「未授权访问」。

    识别特征（保守，只认不会误伤的业务字段）：
      - 响应里有用户身份回显：`"userName":"admin"` / `"nickName":` / `"userId":1`
      - 有权限菜单树：`"permissions":[` / `"roles":[`
      - Set-Cookie 里下发了新的会话 token（说明刚才被认证了）
    """
```

命中时：**降级为 UNKNOWN + 证据写明「响应疑似已认证，无法确认未授权」**，
而不是 CONFIRMED，也不是 SAFE（因为接口确实存在，只是不知道未授权能不能访问）。

### 2.3 降级证据补「解锁方式」（配套改进）

现有 168 条降级证据统一是「目标存在登录墙，需登录后才能判定」，读者不知道该怎么办。
补上可操作提示：

| 插件类型 | 降级证据追加 |
|---|---|
| `path_scope="root"`（.git/.env/备份） | `——可加 --auth-login 后重扫（登录后 Shiro 放行）` |
| 未授权类 | `——可加 --auth-login 复核，但需注意：登录后可访问≠未授权` |
| 越权类 | `——需 --surface-account user:pass 提供低权账号` |

实现位置：`lib/reachability.downgrade_auth_wall_safe()`，按插件属性选提示语。
注意该函数当前只拿到 `results`，需要额外传入插件元信息（或在 `ScanResult.extra`
里预先写入 `plugin_class_name` / `path_scope` / `vuln_type`）。

---

## 3. 需要造的靶场（这是本次修复的关键前提）

**问题**：现有靶场无法复现假阳性——R1 的端点根本不存在。

**方案**：造一座「认证后可达」的靶场，专门验证「登录后能访问 ≠ 未授权」这条边界。

| 项 | 设计 |
|---|---|
| 站点 | 复用 R2 或新建 C5（建议新建，语义清晰） |
| 形态 | Swagger / Druid / Actuator **存在且可访问**，但**需要登录** |
| 预期（未认证扫描） | 全部 SAFE（302 到登录页）✅ |
| 预期（已认证扫描） | **不得 CONFIRMED**，应为 UNKNOWN（响应疑似已认证）或 SAFE |
| 成本 | 低成本：nginx 加 `/prod-api/**` 的 auth_request 或 Spring Security 配一条规则即可，不改 Java 源码 |

**为什么不用现有的 C1（Spring Actuator 靶场）**：C1 是「暴露且未授权」的正样本，
正是上面要区分的那类。需要的是它的**镜像**——暴露但需认证。

---

## 4. 实施步骤

| 步骤 | 内容 | 验收 |
|---|---|---|
| 1 | `PluginBase.anonymous_probe` + engine 注入干净会话 | 单测：已认证 session 下，`anonymous_probe=True` 的插件拿到的是新 session |
| 2 | 7 个未授权类插件声明 `anonymous_probe = True` | `plus_job_unauth` 的手写逻辑可删除，改由基类统一处理 |
| 3 | `lib/matcher.looks_authenticated()` | 单测：登录态响应特征命中；普通 200 不命中 |
| 4 | 未授权类插件判定端接入反向证据 | 已认证扫描「需认证的 Swagger」→ UNKNOWN，不 CONFIRMED |
| 5 | 降级证据补解锁提示 | 3 类插件的证据文案各有对应提示 |
| 6 | 新靶场 C5（需认证的暴露面） | 未认证 SAFE、已认证 UNKNOWN，两态都可复现 |
| 7 | 回归 | `test_fp_baseline` 零误报；盲测 v5 复测，v4 产出 0 丢失 |

---

## 5. 风险与边界

1. **会话隔离有成本**：每个未授权插件多建一个 `SessionManager`（一次 TCP 连接池）。
   7 个插件 ≈ 7 个额外会话，可接受；但若未来插件涨到 50 个未授权类，需要改成
   「引擎共享一个匿名会话」。

2. **`looks_authenticated` 可能误伤**：如果目标把 `"roles":[]` 之类字段印在公开页面上，
   会误判成已认证 → 降级为 UNKNOWN。这是**保守方向的误伤**（宁可 UNKNOWN 不 CONFIRMED），
   符合三态纪律。需要在实现时用真实靶场校准特征表。

3. **不做的事**：不试图「自动判断目标是否真的需要认证」——那需要成对请求
   （有凭据/无凭据）做差集，成本高且易受速率限制。当前方案的边界就是
   「用干净会话探 + 看响应有无认证痕迹」，宁可 UNKNOWN。

4. **与 `requires_auth` 的关系**：两者正交，不冲突。
   - `requires_auth=True`：我需要登录才能测（登录后 CONFIRMED 是有效的）
   - `anonymous_probe=True`：我必须**不登录**才能测（登录后 CONFIRMED 是无效的）
   - 一个插件不应同时为 True（语义矛盾），实现时加校验。
