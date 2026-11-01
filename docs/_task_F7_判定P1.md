# 工单 F7：判定 P1 批次（Spring 路由 / SBA / 指纹 / Swagger / Spring4Shell 探针）

> 执行者：opencode。验收者：lead。
> 工作区 `D:\HZR_PROJECTS\ruoyi-scan-p1`（feat/p1-blindtest）。
> **不改靶场，不 commit。**

---

## 零、来源

R2B 基线（`docs/round2_baseline_20261031.md`）里的 5 条 P1/P2，lead 已复核。逐条修，每条带测试。

---

## 一、F7-1 Spring 插件包在 cms 空时完全不加载

**证据**：C2-2（Spring4Shell，19313）`cms=""`，报告里没有任何 Spring 插件结果；
`core/orchestrator.py:697` 在 cms 空时只回退 `plugins.ruoyi`，`plugins.spring` 从未加载。

**改法**：

1. `core/orchestrator.py` 约 697 行，回退时同时加载两个包：

```python
all_plugins = load_plugins("plugins.ruoyi") + load_plugins("plugins.spring")
```

去重（按类对象），`plugin_fallback` 事件里写清加载了哪几个包和各自数量。
2. `plugins.spring` 加载失败只 warning，不影响 ruoyi/common。
3. 不加新的指纹特征，不做"猜 CMS"，只补回退覆盖面。

**测试**（`tests/test_f7_spring_fallback.py`）：

- 构造 cms 为空的目标，断言 `plugins.spring` 的类出现在候选里；
- 断言 `plugins.common` 仍然追加；
- 断言不重复加载同一个类。

---

## 二、F7-2 SBA 插件不请求 JSON API

**证据**：C2-1a `/applications` 默认返回 1279 字节 SPA 壳，插件判 SAFE；
带 `Accept: application/json` 返回 1876 字节、1 个实例。

**改法**（`plugins/spring/spring_boot_admin.py`）：

1. 三个路径（`/applications`、`/instances`、`/wallboard`）先带
   `headers={"Accept": "application/json"}` 请求；
2. 能解析 JSON 且是非空 list（或 dict 里有 `instances`/`applications`）→ CONFIRMED；
3. JSON 不成立再回退现有 HTML 关键字判定；
4. 空 body / 解析失败不算命中。

**测试**：JSON 实例列表 → CONFIRMED；SPA 壳 → SAFE；空 200 → SAFE。

---

## 三、F7-3 ruoyi-cloud 指纹把空 200 当强特征

**证据**：C2-3（Cloud Function）`/nacos/`、`/gateway/` 都是 200 + **0 字节**，
`matched=["path:/nacos/(any,200)","path:/gateway/(any,200)"]`，confidence 1.0。

**改法**：

1. `core/fingerprint.py` 的 strong_paths 循环支持可选 `min_length`（默认 0）：
   `if len(body) < item.get("min_length", 0): continue`。
2. `core/fingerprint_features.py` 的 `ruoyi-cloud` 两条强特征加
   `"min_length": 20`，并要求 `expect` 仍为 `any`。
3. 不要改成 json 判定——真实 Nacos 3.x 的 `/nacos/` 可能是 404/410，改成 json 会误杀 R8。

**测试**：空 200 → 不命中；20 字节以上含 `nacos` → 命中；R8 指纹用例不退化。

---

## 四、F7-4 Swagger 插件在 `paths={}` 时报"文档泄露"

**证据**：C3 蜜罐 `/v2/api-docs` 返回 `{"swagger":"2.0","paths":{}}`，
`swagger_leak` 仍 CONFIRMED（B 类硬误报）。

**改法**（`plugins/common/swagger_leak.py`）：

1. JSON 文档：解析后要求 `paths` 是 dict 且**非空**才计入；
   `swagger-resources` 数组要求非空且元素含 `swaggerVersion`；
   `swagger-config` 要求 `urls` 非空。
2. 只有 UI 页面（`/swagger-ui.html`）而文档 JSON 为空 → 不计入 `swagger_leak`，
   交给 `ruoyi_swagger_unauth` 报"UI 可访问"。
3. 不允许退回子串匹配。

**测试**：空 paths → SAFE；1 条 path → CONFIRMED；config 空 urls → SAFE；C3 复扫不再出这条。

---

## 五、F7-5 Spring4Shell 插件只探根路径

**证据**：C2-2 `POST /` 返回 405，真实接口 `/device/add` 200；插件固定 `join_url(target, "/")`。

**改法**（`plugins/spring/spring4shell.py`）：

1. 先 `GET /` 解析 `<form action="...">`，收集同源 action；
2. 对每个 action 用良性参数发一次 POST（`name=probe&value=probe`）；
3. 判定：
   - 任一 action 返回 200 且正文无 4xx/5xx 错误特征 → **UNKNOWN**，
     evidence「表单端点可达，未验证代码执行」；
   - 根路径 405/404 且无表单 → UNKNOWN，不许判 SAFE；
   - 保留现有 `S4S_MARKER` 分支（内置签名靶场仍要过）。
4. 不许把"200 无错误"直接判 CONFIRMED——那是假阳性。

**测试**：根 405 + 表单 action 200 → UNKNOWN；根 200 带 marker → CONFIRMED；
根 404 无表单 → UNKNOWN；内置签名靶场用例不退化。

---

## 六、门禁

```
"D:\tools\Python 3.12.9\python.exe" -m pytest tests/test_f7_spring_fallback.py tests/test_f7_sba_json.py tests/test_f7_cloud_fingerprint.py tests/test_f7_swagger_paths.py tests/test_f7_spring4shell_form.py tests/test_fp_baseline.py tests/test_fingerprint.py tests/test_fp_lab.py tests/test_d7_plugins.py -q
"D:\tools\Python 3.12.9\python.exe" -m ruff check core/ plugins/ tests/
"D:\tools\Python 3.12.9\python.exe" -m ruff format --check core/ plugins/ tests/
"D:\tools\Python 3.12.9\python.exe" -m mypy core/ --strict --ignore-missing-imports --no-warn-unused-ignores
"D:\tools\Python 3.12.9\python.exe" tests/regression_ruoyi.py
```

全绿。

---

## 七、回扫（固定靶场，逐座启停）

| 靶场 | 期望 |
|---|---|
| C2-2 19313 | 报告里出现 Spring 插件结果；Spring4Shell 不再是 SAFE（UNKNOWN 可接受） |
| C2-1a 19311 | SBA 未授权 **CONFIRMED** |
| C2-3 19314 | 指纹不再是 `ruoyi-cloud` |
| C3 19331 | 不再有「Swagger API 文档泄露」；A 类可保留 |
| R8 19108（内存够才跑） | 仍识别 `ruoyi-cloud`，Nacos/Gateway 特征不退化 |
| R2 19102 | 指纹/默认口令不退化 |

报告写 `artifacts/f7/`。

---

## 八、停点

1. 贴 6 个新测试文件结果与门禁输出。
2. 贴回扫 5–6 个场景的指纹、CONFIRMED/SAFE/UNKNOWN 与关键 evidence。
3. 贴 `git status --short`（只允许工单/测试/artifacts/f7 新增）。
4. **不 commit，不碰 F6 的认证链改动。**
