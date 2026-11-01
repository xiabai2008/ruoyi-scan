# 工单 F6：认证链 P0——`/login` 404 不等于"无鉴权"

> 执行者：opencode。验收者：lead。
> 工作区 `D:\HZR_PROJECTS\ruoyi-scan-p1`（feat/p1-blindtest，HEAD `20bd530`）。
> **只改认证链与默认口令插件；不碰靶场；不 commit。**

---

## 零、问题（R2B 基线实测，lead 已复核）

C2-2（Spring4Shell，无登录功能的 Tomcat 应用）和 D1（登录地址改成 `/portal/auth/signin`）
都被判了：

```
[CONFIRMED] 后台默认口令（admin/admin123） | http://127.0.0.1:19313/login
evidence: 默认口令登录成功（含验证码场景；独立会话验证，凭证已脱敏）
```

但这两站的 `/login` 都是 **404**，根本没有发生过登录。

根因（已定位）：

1. `core/auth_chain.py` 约 222 行：

```python
# 404 / 无响应 → 无鉴权
if http_code == 404:
    self.auth_mode = AUTH_NONE
```

2. `core/auth_chain.py` 约 272 行：

```python
if self.auth_mode == AUTH_NONE:
    # 无鉴权，直接返回成功
    return True, LOGIN_OK
```

3. `plugins/ruoyi/default_password.py` 约 135 行：`ok_chain` 为真就直接 CONFIRMED。

于是：**任何没有 `/login` 的站点，都会被判"默认口令可用"**。这是本轮最严重的误报。

另外，D1 的真实登录入口是 `/portal/auth/signin`，未登录访问受保护接口会 302 到那里。
扫描器现在既不跟随这个 302 找登录页，也不试替代路径。

---

## 一、F6-1 登录入口发现（core/auth_chain.py）

1. 删掉 `404 → AUTH_NONE` 的捷径。
2. 新增 `AUTH_UNKNOWN` 模式。
3. `detect_auth_mode()` 改成：

   a. 先试 `GET {target}/login`：
      - 200 + HTML/表单/JSON → 现有 v4/v5 判定（保持不变）
      - 302/301，且 `Location` 指向登录页 → 跟随 Location，用该地址作为 `login_url`，
        再按返回内容判定 v4/v5
      - 404 → 进入下一步
   b. **用受保护接口判断"到底有没有鉴权"**：
      - 依次试 `GET/POST {target}/system/user/list`、`/monitor/job/list`、`/system/dept/list`
      - 返回 200 且 JSON 含 `rows`/`data`/`total` → 无鉴权（`AUTH_NONE`）
      - 返回 302/401/403 → 有鉴权但没找到登录页（`AUTH_UNKNOWN`）
      - 全部 404/异常 → `AUTH_UNKNOWN`
   c. `AUTH_UNKNOWN` 时 `login()` 返回 `(False, "login_endpoint_not_found")`，
      **绝不能返回 True**。
4. 登录页地址存到实例上（`self.login_url`），后续 `_login_once` 用它，不要硬编码 `/login`。

> 不许把 `/portal/auth/signin` 这种具体路径写死。D1 的入口要靠 302 Location 发现，
> 这是通用能力，不是为这一座靶场特判。

## 二、F6-2 默认口令必须证明"登录后有数据"（plugins/ruoyi/default_password.py）

`isolated_auth_session` 返回 ok 之后，**必须再做一步**：

1. 用同一个 `iso` 会话访问 `GET/POST {target}/system/user/list`（或 `/system/user/list` 的
   实际路径，能拿到 200 业务 JSON 即可）；
2. 响应含 `rows` 且至少 1 行，或 `total > 0` → 才判 CONFIRMED；
3. 拿到 302/401/403/404/空数据 → 不判 CONFIRMED，按 UNKNOWN，evidence 写明
   「登录接口返回成功但受保护接口未取到数据，证据不足」。

这条是双保险：即使登录链再出错，也不会把"没登录"写成"默认口令"。

## 三、F6-3 认证状态与退出码（降级为 P1，但仍要做）

先纠正一个事实：`report.json` **有** `auth_status`，在 `meta.auth_status` 下，
D1/A2 的带凭据运行已经是 `{"admin":"failed"}`；CLI 也会打印 RED 提示
（`cli/runner.py:443-460`）。所以"报告没有字段"不成立。

真正要补的只有两点：

1. **退出码**：显式传了 `--auth-login` / `--auth-file` 且 `auth_status=failed` 时，
   进程退出码用 `EXIT_PARTIAL=4`（已有定义），CI 才能感知覆盖不全；
   没传认证参数时保持 0。
2. **MFA 识别**：登录响应正文含 `动态口令|OTP|MFA|二次验证|验证码已发送` 时，
   `auth_status` 记 `mfa_required`（不要笼统 `failed`），CLI 提示改成
   「目标启用了二次验证，无法自动登录」。

`core/report.py` 的 `_normalize_auth_status` 已支持字符串，补上 `mfa_required` 的归一即可。

---

## 四、测试（新增 `tests/test_f6_auth_endpoint.py`）

1. `/login` 404 + 受保护接口 404 → `AUTH_UNKNOWN`，`login()` 返回 False
2. `/login` 404 + 受保护接口 302 到 `/portal/auth/signin` → `login_url` 指向该地址，
   且 `login()` 会向它 POST，不再向 `/login` 发
3. `/login` 404 + 受保护接口 200 `{"rows":[...]}` → `AUTH_NONE`
4. `default_password`：登录 ok 但受保护接口返回 404 → **不 CONFIRMED**（UNKNOWN）
5. `default_password`：登录 ok 且受保护接口返回 `total=26` → CONFIRMED
6. 显式 `--auth-login` 失败 → 退出码 4；不带认证参数 → 退出码 0
7. 登录响应含「动态口令」→ `meta.auth_status.admin == "mfa_required"`

---

## 五、门禁

```
"D:\tools\Python 3.12.9\python.exe" -m pytest tests/test_f6_auth_endpoint.py tests/test_auth_chain.py tests/test_fp_baseline.py tests/test_d7_plugins.py tests/test_session_isolation_gate.py tests/test_logging_hygiene.py -q
"D:\tools\Python 3.12.9\python.exe" -m ruff check core/ plugins/ tests/
"D:\tools\Python 3.12.9\python.exe" -m ruff format --check core/auth_chain.py plugins/ruoyi/default_password.py tests/test_f6_auth_endpoint.py
"D:\tools\Python 3.12.9\python.exe" -m mypy core/ --strict --ignore-missing-imports --no-warn-unused-ignores
"D:\tools\Python 3.12.9\python.exe" tests/regression_ruoyi.py
```

全绿。

---

## 六、回扫验证（只跑固定靶场，不改靶场）

依次启动 → 扫描 → 停止：

| 靶场 | 期望 |
|---|---|
| C2-2 Spring4Shell（19313） | **默认口令不再是 CONFIRMED**；应为 UNKNOWN |
| D1（19321）匿名 | 不再 CONFIRMED；能发现 `/portal/auth/signin` 则为 CONFIRMED（D1 口令确实有效），**证据必须含受保护接口数据** |
| D1 带 `--auth-login` | 能登录成功（默认口令有效）；或明确记录失败原因；退出码按 F6-3 |
| A2（19341）匿名 | UNKNOWN，evidence 含动态口令 |
| A2 带 `--auth-login` | `meta.auth_status.admin=mfa_required`，退出码 4 |
| R2（19102）对照 | 默认口令仍 CONFIRMED（真实有效），不许退化 |

报告写到 `artifacts/f6/`，贴每站的 CONFIRMED 明细与 `meta.auth_status`。

---

## 七、停点

1. 贴 7 条测试结果与门禁输出。
2. 贴回扫 6 个场景的计数、CONFIRMED 明细、`meta.auth_status`、退出码。
3. 贴 `git status --short`（只允许新增本工单、测试与 artifacts/f6）。
4. **不 commit，不碰其他 P1 问题（Spring 路由 / SBA / 指纹 / Swagger 另开 F7）。**
