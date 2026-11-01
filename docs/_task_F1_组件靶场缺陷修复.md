# 工单 F1：组件靶场暴露的 6 处扫描器缺陷

> 执行者：opencode。验收者：lead（会独立复跑，不采信自检结论）。
> 本工单只改扫描器，**不改靶场**。靶场在 `C:\Users\HZR\Desktop\若依系统`，禁止读写。

---

## 零、边界（违反即返工）

1. 工作区 `D:\HZR_PROJECTS\ruoyi-scan`。不要读写工作区外任何路径。
2. **不要 `git commit` / `git push` / `git add -A`。** 工作区已有 28 个未提交改动（Phase 5 在制品），
   不许回滚、不许整包提交。动手前先 `git status --short` 留一份基线，结束再比一次。
3. 只改本工单点名的文件 + 新增测试。别顺手重构无关模块。
4. 库代码（`core/` `lib/` `plugins/`）**禁裸 `print()`**，走 `from lib.reporter import emit`。
5. 判定只许收紧或补证据，**不许为了让结果好看而放宽**。
6. Python 一律用 `"D:\tools\Python 3.12.9\python.exe"`（PATH 里那个没装依赖）。

---

## 一、复现证据（先自己跑一遍确认现象）

靶场 4 个组件在 19301–19304，当前在线。扫码命令：

```
"D:\tools\Python 3.12.9\python.exe" main.py -u http://127.0.0.1:19302 --report artifacts/f1/h2 --no-pause --no-cta
"D:\tools\Python 3.12.9\python.exe" main.py -u http://127.0.0.1:19303 --report artifacts/f1/dr --no-pause --no-cta
"D:\tools\Python 3.12.9\python.exe" main.py -u http://127.0.0.1:19304 --report artifacts/f1/cfg --no-pause --no-cta
```

| 站点 | 事实（已独立验证） | 扫描器现状 | 结论 |
|---|---|---|---|
| 19301 Jolokia | `/actuator/jolokia/list` 200 含 JMXConfigurator | 5 条 CONFIRMED | 正确，作为回归基准，不许退化 |
| 19302 H2 Console | `/h2-console/` 200，`<title>H2 Console</title>` | **0 条**，`cms=""` | 漏报：`plugins.spring` 整包没加载 |
| 19303 Data REST | `/api` 200，HAL `_links` | **0 条**，`cms=""` | 同上 |
| 19304 Config Server | `/application/default` 200，`propertySources` 泄露 DB/Redis 配置 | **2 条误报**（IDE 残留、Swagger 泄露），真问题漏报 | 三重问题，见 F1-2/F1-3/F1-4 |

关键证据：

```
GET http://127.0.0.1:19304/sys/login
200 application/json
{"name":"sys","profiles":["login"],"label":null,"version":null,"state":null,
 "propertySources":[{"name":"file:config/application.yml","source":{...}}]}

GET http://127.0.0.1:19304/package-lock.json
200 {"server":{"port":8088},"spring":{...}}

GET http://127.0.0.1:19302/
404 {"timestamp":"...","status":404,"error":"Not Found","path":"/"}
```

根因定位（已核实）：

- `core/fingerprint_features.py:40-42`：spring 的 `strong_paths` 只有 `/actuator` 一条
- `core/router.py:47-49`：`cms` 为空直接 `return []`；`core/orchestrator.py:697-716` 只补 `plugins.common`
- `lib/soft404.py:62-74`：`_digest_canonical` 只归一化「连续路径 token」，
  Config Server 把路径拆成 `"name":"swagger-ui"` + `"profiles":["index.html"]`，归一化匹配不上
- `core/fingerprint_features.py:67`：jeecgboot 的 `/sys/login` 只要 JSON 200 就算强特征，不校验响应体
- `plugins/spring/spring_cloud_config.py:48-61`：只认靶场自定义头 `X-Spring-Vuln`，是桩

---

## 二、F1-1（P0）恢复 spring 插件包的路由

**改法**

1. `core/fingerprint_features.py` 的 `"spring"` 增加根路径 JSON 特征：

```python
"root_json_keys": ["timestamp", "status", "error", "path"],
```

2. `core/fingerprint.py::FeatureBasedFingerprint.detect` 第 1 步（主页特征，约 114-133 行）里，
   在弱关键字之后增加：如果根响应正文能 `json.loads`，且 `root_json_keys` 全部存在，
   则 `strong_hits += 1`，`matched.append("root_json:%s" % ",".join(keys))`。
   解析失败静默跳过（`logger.debug`），不许抛异常。

3. 不要用「cms 空就加载全部插件」这种兜底。路由仍按 CMS，只把指纹补准。

**测试**（新增 `tests/test_f1_fingerprint_json.py`）

- H2/DataREST/Config 的真实根 404 JSON 样本 → `cms="spring"`
- 若依 4.x 登录页 HTML 样本 → 仍 `cms="ruoyi"`
- Jeecg 登录页 HTML 样本 → 仍 `cms="jeecgboot"`
- 普通 nginx 404 HTML → `cms=""`
- 非法 JSON（`{timestamp:` 截断）→ 不抛异常、`cms=""`

**验收**：19302/19303 扫描后 `fingerprint.cms == "spring"`，`h2_console_rce` / `spring_data_rest` 出 CONFIRMED。

---

## 三、F1-2（P0）路径回显归一化 + Swagger 语义化

**改法**

1. `lib/soft404.py`：

- `_digest_canonical(body: bytes, tokens: Iterable[str] = ()) -> str`：在现有 `_PATH_TOKEN_RE`
  归一化之后，再把 `tokens` 里每个 token（UTF-8 编码）替换成 `b"*"`，再算 sha256。
- `Soft404Baseline` 增加 `echo_tokens`（`__slots__` 同步）：由 `probe_path` 派生——
  完整路径、去前导斜杠、basename、每个长度 ≥3 的路径段。
  计算 `canonical_digest` 时传入自己的 tokens。
- `looks_like_real_file(resp, path: str = "")`：用 `path` 或 `urlparse(resp.url).path`
  派生 tokens 再比对。`resp` 没有 `url` 属性（测试替身）时退化为现有行为。

  设计意图：Config Server 对 `/swagger-ui/index.html` 返回的 JSON 与对基线
  `__probe__/does-not-exist.txt` 返回的 JSON，归一化后应得到同一摘要。

2. `plugins/common/swagger_leak.py`：

- JSON 判定必须有 `swagger` / `openapi` / `paths` 键之一（解析 JSON，不做子串）；
- HTML 判定必须有 `swagger-ui` / `knife4j` 标记；
- `_POSITIVE` 里的 `api-docs`、`swagger` 这类**纯路径词**不得单独作为正向证据
  （它们会被 `{"name":"v2","profiles":["api-docs"]}` 这类回显命中）。

**测试**（新增或扩展 `tests/test_auth_failure_noise.py` 旁边的新文件）

- Config Server 通配 JSON（`name/profiles/propertySources`）→ 不报 Swagger、不报 IDE 残留
- 真 Swagger：`{"swagger":"2.0","paths":{...}}` → 仍 CONFIRMED
- SPA 里 `<symbol id="icon-swagger">` → 仍不报（已有 `TestSwaggerSpaFalsePositive` 不许退化）

**验收**：19304 扫描 **0 条 CONFIRMED**；真 Swagger 站点（R9 19109 在线）仍能报。

---

## 四、F1-3（P0）jeecgboot 指纹不许只看状态码

**改法**

1. `core/fingerprint.py`：`strong_paths` 项支持可选 `"json_keys": ["success"]`；
   `detect_cms`（约 147-148 行）与 `_expect_ok`（约 241-249 行）都要消费。
   解析失败／键缺失 → 该强特征不命中。
2. `core/fingerprint_features.py::jeecgboot`：

```python
{"path": "/sys/login", "expect": "json", "json_keys": ["success"]},
```

**测试**

- Config Server 的 `/sys/login` 响应 → `cms != "jeecgboot"`
- 真 Jeecg 失败响应 `{"success":false,"message":"验证码无效","code":500}` → `cms="jeecgboot"`
- 真 Jeecg 成功响应 `{"success":true,"result":{...}}` → `cms="jeecgboot"`

**验收**：19304 的 `fingerprint.cms` 不得为 `jeecgboot`；R10（若在线）仍为 `jeecgboot`。

---

## 五、F1-4（P1）把 `spring_cloud_config.py` 从桩改成真检测

当前实现只认 `X-Spring-Vuln: cloud-config` 头，零实战价值。

**改法**（`plugins/spring/spring_cloud_config.py`）

1. 探测 `{target}application/default`、`{target}application`：
   `200` + `Content-Type` 含 json + 正文可解析 + `propertySources` 是非空 list → CONFIRMED。
2. 证据写清泄露了什么：命中 `spring.datasource.password` / `spring.redis.password` 时
   在 evidence 里点名（只写键名，**不要复制真实值**）。
3. `name` 改为「Spring Cloud Config 配置未授权读取」，`cve` 置 `"N/A"`，
   `description` / `fix` / `fix_detail` / `reproduce` 同步改（类名 `SpringCloudConfigPlugin` 不变）。
4. CVE-2020-5410 的 `..%252F` 目录穿越作为**附加证据**（命中则追加 evidence），
   不作为主判定；探测失败不影响已确认的未授权读取。
5. 三态：全部请求网络异常 → UNKNOWN；端点存在但解析失败 → UNKNOWN；明确无 `propertySources` → SAFE。

**测试**（`tests/test_f1_cloud_config.py`）

- mock config server 响应 → CONFIRMED，evidence 含 `propertySources`
- 普通 Spring 404 JSON → SAFE
- 全部超时 → UNKNOWN

---

## 六、F1-5（P1）base-path 补 `/jeecg-boot`

`core/basepath.py:25` 的 `CANDIDATES` 增加 `"/jeecg-boot"`、`"/jeecg"`。
注意：**不要**用 `/jeecg-boot/` 根路径（SPA 兜底 200）作判据，仍按验证码接口响应判定。
补齐 `tests/test_basepath.py` 的 Jeecg 用例。

---

## 七、F1-6（P1）子模式开关被静默忽略

`cli/dispatcher.py:198-205`：`-m -u URL` 时 `target_for={"u":URL}`、`flag_for={"m":True}`，
循环按 `u→m→p→l` 命中 `u`，裸 `-m` 被吞。改成：

```python
elif target_for:
    mode = next(iter(flag_for)) if flag_for else next(iter(target_for))
    target = next(iter(target_for.values()))
    ...
    run_mode(mode, target, args)
```

补 CLI 回归：`-m -u URL`、`-p -u URL`、`-l -u URL` 分别进入对应模式（断言报告 `mode` 字段）。

---

## 八、门禁（逐条跑，把输出贴在最后）

```
"D:\tools\Python 3.12.9\python.exe" -m pytest tests/test_fp_baseline.py tests/test_fingerprint.py tests/test_fp_lab.py tests/test_d3_version_matrix.py tests/test_d7_plugins.py tests/test_basepath.py tests/test_plugin_unknown_contract.py -q
"D:\tools\Python 3.12.9\python.exe" -m pytest tests/test_logging_hygiene.py tests/test_session_isolation_gate.py -q
"D:\tools\Python 3.12.9\python.exe" tests/regression_ruoyi.py
"D:\tools\Python 3.12.9\python.exe" -m ruff check common/ core/ lib/ api/ plugins/ chains/ cli/ tests/ main.py
"D:\tools\Python 3.12.9\python.exe" -m ruff format --check common/ core/ lib/ api/ plugins/ chains/ cli/ main.py
"D:\tools\Python 3.12.9\python.exe" -m mypy common/ core/ --strict --ignore-missing-imports --no-warn-unused-ignores
"D:\tools\Python 3.12.9\python.exe" scripts/verification_matrix.py --check --max-none 13
"D:\tools\Python 3.12.9\python.exe" scripts/export_plugin_list.py --check
"D:\tools\Python 3.12.9\python.exe" scripts/check_version.py
```

`test_fp_baseline.py` 必须零 CONFIRMED。任何放宽都要在 `KNOWN_FALSE_POSITIVES` 登记理由，
不许删语料、不许加 skip。

---

## 九、交付与停点

1. 先跑第一节的三条命令留「改前」结果到 `artifacts/f1/before/`。
2. 改完再跑一次到 `artifacts/f1/after/`，逐站对比 CONFIRMED 数量与名称。
3. 输出一张对照表：

| 站点 | 改前 CONFIRMED | 改后 CONFIRMED | 说明 |

期望：19301 保持 5 条；19302 新增 1 条；19303 新增 1 条；19304 从 2 条误报变成 1 条真阳性。

4. 贴 `git status --short`，确认只多了本工单涉及的文件与新增测试。
5. **停在这里，不要 commit，不要继续改别的。**
