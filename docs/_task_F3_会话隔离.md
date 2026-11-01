# 工单 F3：修真实会话泄漏 + 拆掉绕过门禁的包装层

> **STATUS（2026-10-31 12:05）：已由并行会话完成，勿重复执行。**
> 当前状态：`core/login.py` 已删除；`default_password.py` 全流程走 `isolated_auth_session`；
> `lib/auth_scan.py` 从 `core.auth_chain` 导入；新增 `tests/test_f3_session_leak.py`；
> `ruff` / `format` / `mypy` / 会话隔离门禁全绿。本文件仅作复盘记录。

> 执行者：opencode。验收者：lead（独立复跑）。
> **开工前必须先确认：没有别的会话/agent 正在改 `core/auth_chain.py`、`core/login.py`、
> `plugins/ruoyi/default_password.py`、`lib/auth_scan.py`。** 这棵树在 11:56 被人动过，
> 边改边验收等于对着流水验收。

---

## 零、背景：门禁被绕过了，泄漏还在

F2 跑门禁时 `test_session_isolation_gate` 报：

```
以下插件导入了 core.auth_chain 却未使用 isolated_auth_session：['default_password.py']
```

几分钟后，工作区多了一个未跟踪文件 `core/login.py`（11:56，893 字节），内容是把
`core.auth_chain.login_with_password` 原样转发一层，docstring 写得很直白：

> 插件只从本模块导入登录能力，避免 `plugins/**` 直接引用 `core.auth_chain`
> （`test_session_isolation_gate` 要求引用 auth_chain 的插件必须使用 `isolated_auth_session`）

于是 `plugins/ruoyi/default_password.py` 改从 `core.login` 导入，门禁变绿。
**但真实的泄漏一点没修**——插件回退分支仍然在共享会话上直接登录：

```python
# plugins/ruoyi/default_password.py 约 168-174 行
resp = session.post(url, data=form_data)          # ← 共享 session
if self._is_submit_mismatch(resp):
    resp = session.post(url, json={...})          # ← 共享 session
```

在关闭验证码的站点（R6/R7 形态）上，admin/admin123 登录成功会把 `Admin-Token`/`JSESSIONID`
写进共享会话，后续插件全部以「已认证」身份探测——就是 v4.8.3 一次多出 6 个假 CONFIRMED 的那个坑。

---

## 一、F3-1（P0）把整个登录流程搬进隔离会话

改 `plugins/ruoyi/default_password.py`：

1. 删掉 `from core.login import login_with_password` 与 `from core.auth_chain import ...`。
2. 改为：

```python
from core.auth_chain import isolated_auth_session
```

3. `verify()` 的整体结构改成：

```python
def verify(self, target, session):
    with isolated_auth_session(target, self.USERNAME, self.PASSWORD) as (iso, ok, reason):
        if ok:
            return CONFIRMED(...)
        # 回退链全部用 iso，不许再用 session
        resp = iso.post(join_url(target, "login"), data=form_data)
        ...
```

4. **`session` 参数在整个 `verify()` 里只允许出现在签名里，方法体内一次都不许出现。**
   这是本单最硬的约束。
5. 行为要保持：验证码场景由 `isolated_auth_session` 内部 OCR 处理；关闭验证码的站点
   仍然走表单/JSON/Cloud 三种形态的回退判定。
6. `isolated_auth_session` 默认 5 次尝试（原 `login_with_password(attempts=3)`）；
   可以接受，不要为了对齐次数去改 `core/auth_chain.py`。

## 二、F3-2（P0）删掉 `core/login.py`

`core/login.py` 的唯一作用就是绕开门禁，没有任何架构价值：

- 实现仍在 `core/auth_chain`，它只是一层转发；
- 它让门禁的判据（引用 `core.auth_chain`）失效；
- 它自己还没格式化（`ruff format` 报 `core/login.py:9`）。

动作：

1. 删除 `core/login.py`。
2. `lib/auth_scan.py:226` 的 `from core.login import login_with_password`
   改回 `from core.auth_chain import login_with_password`。
3. 全仓 `grep -rn "core.login"` 必须为空。

## 三、F3-3（P1）补行为级门禁，不许只靠 AST 判据

AST 门禁只能看「有没有 import」，改个入口就绕过去了。补一条**行为测试**，放到
`tests/test_session_isolation_gate.py` 或新文件 `tests/test_f3_session_leak.py`：

```python
def test_default_password_does_not_authenticate_shared_session():
    # 构造一个 FakeSession：POST /login 返回 200 + Set-Cookie: Admin-Token=xxx
    # 让 isolated_auth_session 内部登录失败（例如返回验证码错误），走回退分支
    # 断言：verify() 结束后 shared_session.cookies 为空、headers 无 Authorization
```

实现建议：

- `FakeSession` 记录 `cookies` 与 `headers`，`post()` 返回带 `Set-Cookie` 的响应；
- 用 `monkeypatch` 把 `core.auth_chain.RuoYiAuthChain.login` 打桩成返回 `(False, "captcha_error")`，
  强制走回退分支；
- 断言共享会话无新增 cookie/header，同时插件仍能给出 CONFIRMED（回退分支命中）。

这条测试在**当前代码上必须失败**（证明它抓得住泄漏），修完后必须通过。跑之前先记录失败输出。

同时把 AST 门禁的判据扩一层：`core.auth_chain` 或 `core.login`（未来若再出现包装层）都算触发，
引用了就必须用 `isolated_auth_session`。

---

## 四、不许做的事

1. 不许把 `login_with_password` 加进门禁白名单——它就是这次绕过的入口。
2. 不许用 `session.cookies.clear()` 事后擦屁股：Shiro 的认证在服务端 session，
   客户端清 cookie 不等于服务端注销（记忆里已实测无效）。
3. 不许改 `core/auth_chain.py` 的登录语义（验证码/OCR/算术轮换）。
4. 不许动 R1–R12 与 C1 组件靶场。
5. 不许 `git commit` / `git push` / `git add -A`。

---

## 五、门禁（逐条跑，贴输出）

```
"D:\tools\Python 3.12.9\python.exe" -m pytest tests/test_session_isolation_gate.py tests/test_f3_session_leak.py -q
"D:\tools\Python 3.12.9\python.exe" -m pytest tests/test_fp_baseline.py tests/test_logging_hygiene.py tests/test_d7_plugins.py tests/test_orchestrator.py -q
"D:\tools\Python 3.12.9\python.exe" -m ruff check common/ core/ lib/ api/ plugins/ chains/ cli/ tests/ main.py
"D:\tools\Python 3.12.9\python.exe" -m ruff format --check common/ core/ lib/ api/ plugins/ chains/ cli/ main.py
"D:\tools\Python 3.12.9\python.exe" -m mypy common/ core/ --strict --ignore-missing-imports --no-warn-unused-ignores
"D:\tools\Python 3.12.9\python.exe" scripts/verification_matrix.py --check --max-none 13
"D:\tools\Python 3.12.9\python.exe" scripts/export_plugin_list.py --check
```

全部必须 exit 0。

---

## 六、真站验证（靶场在线时）

1. R2（验证码开着）：`--surface-account` 那两条 CONFIRMED 不受影响。
2. 若能起 R6/R7（验证码关闭）：
   - 单独跑 `-p`（漏洞扫描）扫一遍，确认 `后台默认口令（admin/admin123）` 仍 CONFIRMED；
   - 紧接着在同一进程里看后续插件有没有因为「已认证」而多报。最省事的判断：
     对比「默认口令插件执行前/后」的共享会话 cookie 数量，后者必须不变。

靶场不在线就写明「未做真站验证」，不许伪造。

---

## 七、交付与停点

1. 贴 F3-3 行为测试在**修前**的失败输出（证明它有效）与修后的通过输出。
2. 贴 7 条门禁输出。
3. 贴 `git status --short`，确认 `core/login.py` 已删除、没有新增未跟踪文件。
4. 一句话结论：`default_password` 是否已完全不碰共享会话。
5. **停在这里，不 commit。**
