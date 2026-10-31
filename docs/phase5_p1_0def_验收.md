# Phase 5 P1-0d / P1-0e / P1-0f 验收

- 日期：2026-10-31
- 范围：P1-0d（默认口令走验证码登录）、P1-0e（登录后上传维度）、P1-0f（低权登录成功的 dept tree 实测）
- 靶场：R1（主验）、R4（登录后上传真实站点）；R12 未触碰
- 环境：`RUOYI_SCAN_LOWPRIV_USER/PASS` 全程 unset

---

## 一、P1-0d：默认口令插件接入验证码登录

### 改后

`plugins/ruoyi/default_password.py` 的 `verify()` 先走 `isolated_auth_session`
（内部就是 `RuoYiAuthChain.login`，具备 v4/v5 + 验证码 OCR + 算术运算符轮换），
成功即返回 CONFIRMED；失败后用同一个隔离会话回退原有的表单/JSON/Cloud 判定。
不再直接使用共享会话登录，满足 `test_session_isolation_gate`。

验证码重试上限由 5 提到 8（`core/auth_chain.py` 的 `login()` 默认值与
`login_with_password()` 默认值），降低 OCR 偶发失败导致的演示抖动。

### R1 验收

- `[+]登录成功（验证码/表单链路）`
- `后台默认口令（admin/admin123）` → **CONFIRMED**
- evidence：`默认口令登录成功（含验证码场景；独立会话验证，凭证已脱敏）`
- 单测：`test_confirmed_via_captcha_login_helper`（mock `RuoYiAuthChain.login` 返回成功）

---

## 二、P1-0e：file_upload 增加「登录后上传」维度

### 改后

`plugins/ruoyi/file_upload.py` 现在有两个维度：

1. **匿名上传**（原逻辑）：匿名会话 POST `/common/upload`，成功即「未授权上传」。
2. **登录后上传**（新增）：仅当 `session.authenticated`（主扫描 `--auth-login`/`--auth` 成功）
   时启用；上传良性 `.html` 探针（`ruoyi_scan_probe.html`），解析 `url/fileName` 后
   **回读上传 URL**，确认文件真的可访问，才判 CONFIRMED。
3. 若登录后上传返回 500/`FileNotFoundException`（R1 的 profile 目录不存在），判 UNKNOWN，
   不把基础设施异常写成 SAFE。
4. 兼容若依 `AjaxResult` 成功码 `code:0`（此前只认 200，R4 上传成功被误判 SAFE）。

`core/orchestrator.py` 在会话上设置 `session.authenticated = (auth_status == "ok")`，
供该维度判断是否具备已认证会话。

### R4 真实验收（upload 目录正常）

```
login True ok
status CONFIRMED
evidence 登录后上传：上传响应 JSON：code=0
         url=http://127.0.0.1:19104/profile/upload/2026/10/31/ruoyi_scan_probe_...html
         fileName=/profile/upload/...html（.html 已上传且可回读）
```

R1 因 `profile` 目录不存在返回 500：
`任意文件上传 -> UNKNOWN | 登录后上传接口返回 code=500，疑似上传目录不存在/服务端异常`。

单测：

- `test_file_upload_authenticated_dimension_confirmed`（匿名 401、登录后 `.html` 上传+回读成功 → CONFIRMED，`code:0`）
- `test_file_upload_authenticated_dimension_500_unknown`（登录后 500 → UNKNOWN）

---

## 三、P1-0f：低权登录成功的 dept tree 实测

之前 R1 的 dept tree UNKNOWN 容易被误读成 captcha 失败。这次单独做了一次真实低权登录：

证据文件：`artifacts/p5/R1-dept-tree-lowpriv.json`

```json
{
  "login": {"ok": true, "reason": "ok"},
  "probes": {
    "treeData": {"status": 200, "body": "[]", "len": 2},
    "selectDeptTree": {"status": 500, "len": 243}
  },
  "plugin_status": "UNKNOWN",
  "plugin_evidence": "低权账号 scanner_low 登录成功；业务层在无权限下执行（treeData 返回 2 字节、selectDeptTree 返回 243 字节），但未返回任何部门数据行；空列表/空页面不能证明越权，不予判定"
}
```

同时把「登录成功」写进了空数据分支的 evidence，并在
`regression_ruoyi` 的 `test_unknown_when_business_layer_executes_without_data`
中断言 evidence 含「登录成功」、不含「登录失败」。

结论：这条 UNKNOWN **不是** captcha 失败，而是「登录成功 + 空数据，不能证明越权」。

---

## 四、R1 最终复扫（P1-0d/e/f 后）

```bash
unset RUOYI_SCAN_LOWPRIV_USER RUOYI_SCAN_LOWPRIV_PASS
python main.py -u http://127.0.0.1:19101 \
  --auth-login admin:admin123 --auth-surface \
  --surface-account scanner_low:LowPriv_2026 \
  --surface-output artifacts/p5/R1-p1_0def4-surface.json \
  --report artifacts/p5/R1-p1_0def4 --no-pause --no-cta
```

| 指标 | 数值 |
|---|---|
| CONFIRMED | **5** |
| SAFE | 19 |
| UNKNOWN | 5 |
| surface 发现 | 0 |
| auth_status | `{admin: ok, surface: ok}` |

**5 条真实 CONFIRMED（全部 high）：**

1. `POST型报错注入（role）` — `XPATH syntax error`，基线无此特征
2. `POST型报错注入（dept）` — 同上
3. `后台默认口令（admin/admin123）` — 验证码场景登录成功
4. `定时任务调用目标未校验` — 写入 → 回读 → 还原成功
5. `重置密码页数据权限绕过` — 低权渲染出 `userId=1`，泄露 `loginName=admin`

其余关键状态：

- `任意文件上传` → UNKNOWN（R1 profile 目录不存在，500）
- `部门树越权访问` → UNKNOWN（低权登录成功，但 treeData 为空）
- `RuoYi Swagger 未授权访问` / `Swagger API 文档泄露` → SAFE（匿名会话判定）

**目标 ≥5 达成。**

---

## 五、测试

| 测试 | exit |
|---|---|
| `test_fp_baseline` | 0 |
| `test_logging_hygiene` | 0 |
| `test_session_isolation_gate` | 0 |
| `test_captcha_solver` | 0 |
| `test_auth_chain` | 0 |
| `test_auth_status_gate` | 0 |
| `test_report` | 0 |
| `test_auth_surface` | 0 |
| `test_anon_session_plugins` | 0 |
| `regression_ruoyi` | 0 |
| `test_d7_plugins` | 0 |

汇总：`artifacts/p5/gates_p1_0def_final.txt`

---

## 六、改动文件

- `plugins/ruoyi/default_password.py`（验证码登录 + 隔离会话 + 回退）
- `plugins/ruoyi/file_upload.py`（登录后上传维度、`.html` 回读、500 降级、`code:0` 兼容）
- `plugins/ruoyi/cve_2025_70986_select_dept_tree.py`（空数据 evidence 明确「登录成功」）
- `core/orchestrator.py`（`session.authenticated`）
- `core/auth_chain.py`（验证码重试默认 8 次）
- `lib/auth_scan.py`（公共登录器重试 8 次）
- `tests/test_anon_session_plugins.py`（登录后上传用例）
- `tests/regression_ruoyi.py`（默认口令验证码用例 + dept tree 登录成功断言）

---

## 七、残余

1. R7/R9/R10 的 context-path 登录（`/prod-api/login`、`/prod-api/auth/login`、`/jeecg-boot/sys/login`）仍是 P1-1。
2. 越权矩阵目前要求「双方都有数据行」，但未逐行比对权限归属；「低权只看到自己的行」仍可能被算垂直越权，需权限元数据或逐行 ID 归属判断。
3. R2 全量因靶场 502 未纳入本轮数字；R12 未触碰。

**停在 P1-0f；P1-1/P1-2 等确认。**
