# Phase 5 P1-0b / P1-0c 验收（越权证据门槛 + Swagger 匿名判定）

- 日期：2026-10-31
- 范围：P1-0b、P1-0c；P1-1/P1-2 未动
- 靶场：R1（`restore_demo.py R1`），R12 未触碰
- 环境：`RUOYI_SCAN_LOWPRIV_USER/PASS` 全程 unset；低权账号只通过 `--surface-account` 显式提供

---

## 一、P1-0b：空列表不再算越权证据

### 改前

`lib/auth_surface.py:authz_matrix()` 对匿名/低权重放的判据是：

```python
code == 200 and len(body) > 0 and not _looks_like_html_document(body)
```

R1-withlowpriv3 的 20 条 CONFIRMED 里 13 条是 32B 的
`{"total":0,"rows":[],"code":200}`，被当成「低权拿到了管理数据」。
这些接口带 `@RequiresPermissions`，低权实际只拿到空列表——`len(body) > 0`
不是「拿到业务数据」的证据。

### 改后

1. `lib/auth_surface.py` 新增 `_extract_data_rows(body)`：
   - JSON `rows`/`records`/`list`/`items`/`data`/`result` 中解析真实数据行；
   - `{"total":0,"rows":[],"code":200}`、`{"data":{"total":0,"rows":[]}}`、
     只有 `code/msg` 的信封对象 → `[]`；
   - 非 JSON 只接受 ≥32B 的多行业务文本，短错误文案不算；
   - HTML 一律不算。
2. `SurfaceAsset` 增加 `admin_body`（不序列化），`inventory()` 保存高权响应体。
3. `authz_matrix()` 的匿名/低权分支改为：
   ```python
   rows = _extract_data_rows(body)
   if rows and admin_rows:
       CONFIRMED
   else:
       UNKNOWN   # 空列表/空对象，绝不冒充 CONFIRMED
   ```
   必须同时满足「匿名/低权拿到数据行」和「高权盘点确实有数据行」。
4. `plugins/ruoyi/cve_2025_70986_select_dept_tree.py` 同类修正：
   `leaked`、`tree_name`、`anon_open` 全为空时返回 UNKNOWN，
   evidence 写明「业务层执行但未返回部门数据行，空列表/空页面不能证明越权」。
   R3（真的泄露 `工程技术部`）仍 CONFIRMED；R1/R2/R4（`[]`）转 UNKNOWN。

### 测试

- `tests/test_auth_surface.py`：
  - `test_anon_200_empty_rows_unknown`（32B 空列表 → UNKNOWN、无漏洞）
  - `test_extract_data_rows_rejects_empty_nested_data`（嵌套 `data.total=0` 也返回 []）
  - 原 `test_anon_200_confirmed` / `test_low_privilege_escalation_confirmed` /
    `test_run_end_to_end_with_page_discovery` 的 fixture 改为真实非空 rows。
- `tests/regression_ruoyi.py`：
  - 原 `test_confirmed_when_business_layer_executes_without_data` 按新规则改为
    `test_unknown_when_business_layer_executes_without_data`，断言 UNKNOWN。

---

## 二、P1-0c：Swagger 未授权判定改用匿名会话

### 改前

`plugins/ruoyi/ruoyi_swagger_unauth.py`、`plugins/common/swagger_leak.py`
直接用调用方共享会话。P1-0 修好 admin 登录后，R1 用 admin 会话能打开
`/swagger-ui.html`、`/v2/api-docs`，插件却报「未授权访问 / 文档泄露」——
请求带的是 admin 凭据，不能叫未授权。

### 改后

两个插件都增加 `verify()` 包装：

```python
anon = getattr(session, "anonymous", None)
probe = anon() if callable(anon) else session
try:
    return self._verify_with_session(target, probe)
finally:
    if probe is not session:
        probe.close()
```

与 `file_upload` / `unauth_batch` 同一口径：未授权判定只看匿名会话。
匿名真能读文档 → 仍 CONFIRMED（修复不能把真暴露一起漏掉）。

### 测试

`tests/test_anon_session_plugins.py` 新增：

- `test_ruoyi_swagger_uses_anonymous_session`（admin 可读、匿名 401 → 非 CONFIRMED）
- `test_swagger_leak_uses_anonymous_session`（同上）
- `test_swagger_leak_anon_public_confirmed`（匿名真可读 → CONFIRMED）

---

## 三、R1 重扫：真实 CONFIRMED 数

```bash
unset RUOYI_SCAN_LOWPRIV_USER RUOYI_SCAN_LOWPRIV_PASS
python main.py -u http://127.0.0.1:19101 \
  --auth-login admin:admin123 --auth-surface \
  --surface-account scanner_low:LowPriv_2026 \
  --surface-output artifacts/p5/R1-p1_0bc-surface.json \
  --report artifacts/p5/R1-p1_0bc --no-pause --no-cta
```

结果：

| 指标 | 修复前（R1-withlowpriv3） | 修复后（R1-p1_0bc） |
|---|---|---|
| CONFIRMED | 20 | **4** |
| SAFE | 3 | 19 |
| UNKNOWN | 19 | 6 |
| surface 发现 | 13（全是空列表） | **0** |
| 部门树越权 | CONFIRMED（`[]`） | UNKNOWN |
| Swagger 未授权/文档 | 2 条 CONFIRMED | 2 条 SAFE |
| auth_status | — | `{admin: ok, surface: ok}` |

**4 条 CONFIRMED（全部 high，全部有数据/状态证据）**：

1. `POST型报错注入（role）` — `XPATH syntax error`，基线无此特征
2. `POST型报错注入（dept）` — 同上
3. `定时任务调用目标未校验` — 写入 → 回读 → 还原成功
4. `重置密码页数据权限绕过` — 低权渲染出不可见用户 `userId=1`，泄露 `loginName=admin`

这 4 条就是当前可以拿去演示的数字；其余全部是 SAFE/UNKNOWN，不再把空列表当越权。

---

## 四、测试汇总

```bash
python -m pytest tests/test_fp_baseline.py -q
python -m pytest tests/test_logging_hygiene.py -q
python -m pytest tests/test_session_isolation_gate.py -q
```

| 测试 | exit |
|---|---|
| `test_fp_baseline` | 0 |
| `test_logging_hygiene` | 0 |
| `test_session_isolation_gate` | 0 |
| `test_auth_surface` | 0 |
| `test_anon_session_plugins` | 0 |
| `regression_ruoyi` | 0 |
| `test_captcha_solver` / `test_auth_chain` / `test_auth_status_gate` / `test_report` / `test_d7_plugins` | 0 |

---

## 五、改动文件

- `lib/auth_surface.py`（`admin_body`、`_extract_data_rows`、行级越权判据）
- `plugins/ruoyi/cve_2025_70986_select_dept_tree.py`（空数据 → UNKNOWN）
- `plugins/ruoyi/ruoyi_swagger_unauth.py`（匿名会话）
- `plugins/common/swagger_leak.py`（匿名会话）
- `tests/test_auth_surface.py`（空列表/嵌套空数据用例 + fixture 修正）
- `tests/test_anon_session_plugins.py`（Swagger 匿名用例）
- `tests/regression_ruoyi.py`（dept tree 空数据断言改为 UNKNOWN）

---

## 六、残余

1. R7/R9/R10 的 context-path 登录（`/prod-api/login`、`/prod-api/auth/login`、`/jeecg-boot/sys/login`）仍是 P1-1 的 base-path 工作。
2. 非空但只含「低权自己的行」的响应仍可能被判垂直越权（当前规则要求双方都有数据行，但没有逐行 ID 对比权限归属）；若要进一步降噪，需要引入目标接口的权限元数据或逐行 ID 归属判断，属后续增强。
3. R2 全量扫描曾因靶场 502 卡在软 404 重试，未纳入本轮数字；R12 未触碰。

**本轮停在 P1-0c；P1-1/P1-2 等确认。**
