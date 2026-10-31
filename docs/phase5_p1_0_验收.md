# Phase 5 补充验收（auth_status 分链 + P1-0 公共登录器）

- 日期：2026-10-31
- 范围：仅两项补充；P1-1/P1-2 未做
- 靶场：R1、R2、R6（本轮按需恢复）；R12 未触碰
- 环境：`RUOYI_SCAN_LOWPRIV_USER/PASS` 全程 unset

---

## 一、auth_status 拆成 {admin, surface}

### 改前问题

`R1-withlowpriv` 的 HTML 一边写「需登录的结论已统一降级为 UNKNOWN」，一边因为 surface/低权结果挂着 3 条 CONFIRMED，自相矛盾。根因是 `auth_status` 只有一个字符串，且 **surface 扫描在报告生成之后才执行**——surface 的结果与状态根本没进同一份报告。

### 改后

1. `ScanRequest` 拆成两个字段：
   - `auth_status`：主扫描（`--auth-login` / `--auth` / `--auth-file`）
   - `surface_auth_status`：`--auth-surface` 的独立会话
2. `report.json`：
   ```json
   "meta": {
     "auth_status": {"admin": "ok", "surface": "ok"}
   }
   ```
   兼容旧字符串输入（字符串视为 admin，surface 记为 `not_attempted`）。
3. HTML 横幅按链路分别措辞：
   - 主扫描 failed：只写「主扫描（--auth-login）高权登录失败，主扫描中需要会话的插件结论已降级为 UNKNOWN」；
   - surface ok 且主扫描非 ok：追加「--auth-surface 使用独立会话成功完成，surface 结论（CONFIRMED）未降级，不要与主扫描的 UNKNOWN 混为一谈」；
   - 主扫描 ok、surface failed：只提示 surface 未执行；
   - 两者都 ok：不显示横幅。
4. **顺序修正**：`--auth-surface` 块移到报告生成之前，surface 的 CONFIRMED 与状态会进入同一份报告（旧实现报告先写、surface 后跑，正文/meta 必然对不上）。
5. 单测：`tests/test_auth_status_gate.py` 新增 3 条报告级用例（admin failed + surface ok、meta 分链、admin ok + surface failed），共 6 条。

### 验收

**R1：admin + surface 都成功**

```bash
unset RUOYI_SCAN_LOWPRIV_USER RUOYI_SCAN_LOWPRIV_PASS
python main.py -u http://127.0.0.1:19101 \
  --auth-login admin:admin123 --auth-surface \
  --surface-account scanner_low:LowPriv_2026 \
  --surface-output artifacts/p5/R1-withlowpriv3-surface.json \
  --report artifacts/p5/R1-withlowpriv3 --no-pause --no-cta
```

结果：

- `meta.auth_status = {"admin": "ok", "surface": "ok"}`
- HTML 无「未认证/降级」横幅（自相矛盾消失）
- surface 结果进入报告：`合计 20`（surface 13 + 主扫描 7），不是旧实现的「正文没有 surface、meta 说未尝试」
- 终端：`[+]登录成功（验证码/表单链路）`、`认证后深度扫描完成：盘点资产 32 个，越权/未授权发现 13 个`

**R1：错误口令**

```bash
python main.py -u http://127.0.0.1:19101 --auth-login admin:wrongpass \
  --report artifacts/p5/R1-badauth2 --no-pause --no-cta
```

结果：

- `meta.auth_status = {"admin": "failed", "surface": "not_attempted"}`
- HTML 只出现「主扫描（--auth-login）高权登录失败…」；不出现「surface 成功」文案
- `合计 0`，需会话插件全 UNKNOWN

---

## 二、P1-0 公共登录器（验证码能力接入 auto_login）

### 改前问题

`lib/auth_scan.auto_login` 只 POST `username/password` 到根 `/login`，不处理验证码。R1–R5 必带验证码，因此 `--auth-login` 永远失败，依赖会话的插件全部 UNKNOWN。

### 改后

1. `core/captcha_solver.py`：
   - `solve(math_op_index: int = 0)`；
   - `_eval_math_captcha(text, math_op_index)`：OCR 保留算式时直接求值；OCR 把 `7-2=?` 读成 `7247`（运算符丢失）时，取前两位数字，按 `+,-,*,/` 轮换候选答案（Phase 2 盲测验证过的策略），不再 5 次重试都提交同一个错误答案。
2. `core/auth_chain.py`：
   - `login()` 把重试序号传给 `_login_once` → v4/v5 登录 → `CaptchaSolver.solve(math_op_index=...)`；
   - 新增公共登录器 `login_with_password(target, username, password, timeout=None, attempts=5)`：
     - **不内置任何默认账号**，凭据必须显式传入；
     - v4 表单 / v5 JWT 由 `RuoYiAuthChain` 自动探测；
     - 返回 `{"cookies", "headers", "type"}`，供 `apply_auth_to_session` 注入。
3. `lib/auth_scan.auto_login`：
   - 默认 RuoYi 形态（未显式指定 `login_url`、`login_type=form`、默认字段名）先走 `login_with_password`；
   - 失败后保留原有通用表单/JSON 回退，不影响非若依应用；
   - 成功时打印 `[+]登录成功（验证码/表单链路）`。
4. 配套修正 `plugins/ruoyi/sql_inject_dept.py`：删除硬编码的 `"Cookie": ""`。登录成功后该头会覆盖 SessionManager 的会话 Cookie，导致 dept 请求退回登录墙（role 正常、dept SAFE 的差异就是这个）。

### 验收

**R1：`--auth-login admin:admin123`**

```bash
python main.py -u http://127.0.0.1:19101 --auth-login admin:admin123 \
  --report artifacts/p5/R1-authfixed2 --no-pause --no-cta
```

结果：

- `[+]登录成功（验证码/表单链路）`
- `meta.auth_status = {"admin": "ok", "surface": "not_attempted"}`
- `POST型报错注入（role）` → **CONFIRMED**（`XPATH syntax error`，基线无此特征）
- `POST型报错注入（dept）` → **CONFIRMED**
- 合计 4（另有 2 条 Swagger 文档类结论，见「残余问题」）
- 旧实现同一命令：登录失败、dataScope 两条 UNKNOWN

**R2：登录器单点验证（4.6.2，dataScope 已修）**

```python
from core.auth_chain import login_with_password
ok, reason, cfg = login_with_password("http://127.0.0.1:19102", "admin", "admin123")
# ok=True, reason=ok, type=cookie, cookies=1
```

`lib.auth_scan.auto_login` 直接调用同样返回 cookie 配置（`type=cookie, cookies=1`），证明接入点在 `auto_login` 而非仅测试专用函数。

说明登录器不依赖 R1 的特定版本；R2 的 dataScope 已修，因此不应出现 CONFIRMED（未跑全量，避免 R2 靶场 502 时卡在软 404 重试）。

**R1：错误口令**

- `[-]统一登录器未成功：fail: 用户不存在/密码错误`
- `meta.auth_status.admin = "failed"`，合计 0，需会话插件 UNKNOWN

---

## 三、测试

```bash
python -m pytest tests/test_fp_baseline.py -q
python -m pytest tests/test_logging_hygiene.py -q
python -m pytest tests/test_session_isolation_gate.py -q
```

| 测试 | 结果 |
|---|---|
| `test_fp_baseline` | exit 0 |
| `test_logging_hygiene` | exit 0 |
| `test_session_isolation_gate` | exit 0 |
| `test_captcha_solver` | exit 0 |
| `test_auth_chain` | exit 0 |
| `test_auth_status_gate` | exit 0（6 条） |
| `test_report` | exit 0 |
| `test_auth_surface` | exit 0 |
| `test_anon_session_plugins` | exit 0 |
| `regression_ruoyi` | exit 0 |

汇总：`artifacts/p5/gates_p1_0.txt`

---

## 四、改动文件

- `core/captcha_solver.py`（算术运算符轮换）
- `core/auth_chain.py`（公共登录器 `login_with_password` + 重试序号）
- `lib/auth_scan.py`（`auto_login` 接入公共登录器）
- `core/orchestrator.py`（`surface_auth_status` 字段 + 报告 summary 分链）
- `core/report.py`（`meta.auth_status` 分链 + 按链路的 HTML 横幅）
- `cli/runner.py`（surface 移到报告前、分链状态、终端措辞）
- `plugins/ruoyi/sql_inject_dept.py`（移除空 Cookie 头）
- `tests/test_auth_status_gate.py`（报告级分链用例）

---

## 五、残余问题（下一批）

1. **Swagger 文档类结论在高权会话下仍标「未授权」**（已在 P1-0c 修复）：R1 `--auth-login` 成功后曾命中 `/swagger-ui.html`、`/v2/api-docs` 并报「未授权」；P1-0c 已把两个 Swagger 插件改为 `session.anonymous()` 判定，R1 复扫已转为 SAFE。详见 [phase5_p1_0bc_验收.md](phase5_p1_0bc_验收.md)。
2. **R7/R9/R10 的 context-path 登录仍未修**：公共登录器目前只覆盖根 `/login` 的 RuoYi v4/v5；R7 的 `/prod-api/login`、R9 的 `/prod-api/auth/login`、R10 的 `/jeecg-boot/sys/login` 仍是 P1-1 的 base-path 工作。
3. `RuoYiAuthChain.__init__` 仍保留既有默认参数 `admin/admin123`（历史代码，非本轮新增）；新公共登录器强制显式传参，没有新增默认凭据依赖。
4. R2 全量扫描在 502 时曾卡在软 404 重试，已停止；恢复后只做了登录器单点验证，未把 R2 全量结果写入本验收。

**本轮停在 P1-0；P1-1/P1-2 等确认。**
