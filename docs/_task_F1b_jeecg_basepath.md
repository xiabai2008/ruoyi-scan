# 工单 F1b：F1-5 返工（Jeecg base-path 探针）+ Swagger 两个端点补回

> 执行者：opencode。验收者：lead（会独立复跑，不采信自检）。
> 只改扫描器，不改靶场；不要 `git commit` / `git push` / `git add -A`。

---

## 零、背景：F1-5 被判无效

F1-5 只往 `core/basepath.py` 的 `CANDIDATES` 加了 `/jeecg-boot`、`/jeecg`，
但探针 `_looks_like_ruoyi_api` 只认 `captchaEnabled`，而真实 JeecgBoot 的验证码接口是：

```
GET /jeecg-boot/sys/randomImage/{key}
200 {"success":true,"message":"","code":200,"result":{"img":"data:image/png;base64,..."}}
```

实测（lead 用真实响应形态起 mock 验证）：`detect_api_base()` 仍返回 `""`。
更严重的是 `tests/test_basepath.py` 里的
`test_basepath_detected_for_jeecg_boot` 用了 `/jeecg-boot/captchaImage`——
**这个端点在 JeecgBoot 里根本不存在**，测试是照着假想写的，属于假测试。

---

## 一、F1b-1（必做）Jeecg base-path 真探测

### 改法（`core/basepath.py`）

1. 新增探针路径常量（固定 key，便于测试且真实 Jeecg 接受任意 key）：

```python
JEECG_CAPTCHA_PATH = "/sys/randomImage/ruoyi_scan_probe"
```

2. 新增判定函数，**不许**放宽成「JSON 里有个 success 就算」：

```python
def _looks_like_jeecg_api(resp) -> bool:
    # 要求：200 + json + dict + success 为 True + result 是 dict 且 img 非空、
    # 且 img 以 "data:image" 开头（真实 Jeecg 返回 base64 data URL）
```

3. `_probe_api_base(base, session)` 增加：先跑现有 `CAPTCHA_PATHS`，都不中且
   `base` 以 `/jeecg-boot` 或 `/jeecg` 结尾时，再探 `base + JEECG_CAPTCHA_PATH`，
   命中 `_looks_like_jeecg_api` 返回 True。

4. 不要给 `/prod-api`、`/dev-api`、`/api` 也加这个探针（Jeecg 不走这些前缀，省请求）。

### 测试（改 `tests/test_basepath.py`）

**删掉**这两条假测试：
- `test_basepath_detected_for_jeecg_boot`（用 `/jeecg-boot/captchaImage`）
- `test_basepath_detected_for_jeecg_short_prefix`（用 `/jeecg/code`）

替换为：

```python
JEECG_JSON = '{"success":true,"code":200,"result":{"img":"data:image/png;base64,iVBORw0KGgo="}}'

def test_basepath_detected_for_jeecg_boot():
    sess = FakeSession({"http://target/jeecg-boot/sys/randomImage/ruoyi_scan_probe": FakeResp(JEECG_JSON)})
    assert detect_api_base("http://target/", sess) == "/jeecg-boot"

def test_basepath_jeecg_requires_real_image_payload():
    # 只有 success 没有 result.img → 不认
    sess = FakeSession({"http://target/jeecg-boot/sys/randomImage/ruoyi_scan_probe": FakeResp('{"success":true}')})
    assert detect_api_base("http://target/", sess) == ""

def test_basepath_jeecg_captcha_path_does_not_exist():
    # /jeecg-boot/captchaImage 是错误假设，不能作为判据
    sess = FakeSession({"http://target/jeecg-boot/captchaImage": FakeResp(CAPTCHA_JSON)})
    assert detect_api_base("http://target/", sess) == ""
```

同时保留 `test_basepath_jeecg_spa_root_not_used_as_evidence`（SPA 根 200 不能当证据）。

---

## 二、F1b-2（必做）Swagger 两个端点补回

F1-2 改成「JSON 必须有 swagger/openapi/paths 键」后，丢了两个真实端点：

- `/swagger-resources` 返回的是 **数组**：
  `[{"name":"default","url":"/v2/api-docs","swaggerVersion":"2.0"}]`
- `/v3/api-docs/swagger-config` 返回配置对象：
  `{"configUrl":"/v3/api-docs/swagger-config","url":"/v3/api-docs","urls":[...]}`

### 改法（`plugins/common/swagger_leak.py`）

在 JSON 分支里，除现有 `dict + swagger/openapi/paths` 外，再接受两种**结构化**形态：

1. `payload` 是 `list`，且任一元素是 dict，同时含 `swaggerVersion` 与 `url`；
2. `payload` 是 dict，且含 `configUrl`，或（`url` 且 `urls`）。

**不许**退回子串匹配（`"api-docs" in text`），否则 Config Server 的路径回显误报会复现。

### 测试（`tests/test_f1_swagger_config_noise.py` 追加）

- 真 `/swagger-resources` 数组 → 计入 found；
- 真 `swagger-config` 对象 → 计入 found；
- Config Server 回显 `{"name":"v3","profiles":["api-docs"]}` → **不**计入（现有用例，不许退化）。

---

## 三、不许做的事

1. 不要改 `CANDIDATES` 的现有顺序，不要加新前缀。
2. 不要放宽 `_looks_like_ruoyi_api`。
3. 不要动 F1 已通过的 5 项（指纹 root_json_keys、soft404 token、jeecg json_keys、
   cloud config、dispatcher），也不要重排 Phase 5 在制品文件的格式。
4. 不要新增插件，插件数仍为 54。

---

## 四、门禁（逐条跑，贴输出）

```
"D:\tools\Python 3.12.9\python.exe" -m pytest tests/test_basepath.py tests/test_f1_swagger_config_noise.py tests/test_fp_baseline.py tests/test_fingerprint.py -q
"D:\tools\Python 3.12.9\python.exe" -m pytest tests/test_logging_hygiene.py tests/test_session_isolation_gate.py -q
"D:\tools\Python 3.12.9\python.exe" -m ruff check core/basepath.py plugins/common/swagger_leak.py tests/test_basepath.py tests/test_f1_swagger_config_noise.py
"D:\tools\Python 3.12.9\python.exe" -m ruff format --check core/basepath.py plugins/common/swagger_leak.py tests/test_basepath.py tests/test_f1_swagger_config_noise.py
"D:\tools\Python 3.12.9\python.exe" -m mypy core/basepath.py --strict --ignore-missing-imports --no-warn-unused-ignores
"D:\tools\Python 3.12.9\python.exe" scripts/export_plugin_list.py --check
```

`test_fp_baseline.py` 必须零 CONFIRMED。

---

## 五、自证（必须跑，输出要能看出实际执行几项）

写 `artifacts/f1b/selfcheck.py`，起一个本地 mock（不要依赖外部网络），打印 PASS/FAIL：

1. 真实 Jeecg 形态（`/jeecg-boot/sys/randomImage/x` 返回 success+result.img）→ `detect_api_base == "/jeecg-boot"`
2. 只有 `{"success":true}` → `""`
3. `/jeecg-boot/captchaImage` 返回 captchaEnabled → `""`
4. 真 `/swagger-resources` 数组 → swagger 插件 CONFIRMED
5. Config Server 回显 `{"name":"v3","profiles":["api-docs"]}` → swagger 插件不 CONFIRMED

最后打印「实际执行 5 项，通过 N 项」。不许用一个大 try 包住导致跳过。

---

## 六、停点

1. 贴出门禁输出与自证结果。
2. 贴 `git status --short`，确认只多出本工单涉及的 4 个文件（`core/basepath.py`、
   `plugins/common/swagger_leak.py`、`tests/test_basepath.py`、
   `tests/test_f1_swagger_config_noise.py`）+ `artifacts/f1b/`。
3. 停在这里，不要 commit，不要接着建 C2。
