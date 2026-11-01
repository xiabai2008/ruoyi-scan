# 工单 F5：清掉 main 继承下来的 format 红灯（2 个文件）

> 执行者：opencode。验收者：lead。
> 只改 2 个文件，不碰 P1-1 在制品，不 commit 除本单以外的任何内容。

---

## 零、背景（lead 已核实）

F4 的 p1 门禁 `ruff format --check` 报 23 个文件，其中：

- **21 个是 `tests/`**：CI 的 format 门禁**不检查 tests/**（`.github/workflows/ci.yml:49`
  写的是 `common/ core/ lib/ api/ plugins/ chains/ cli/ main.py`），属于假红灯，不要动。
- **2 个是真实红灯**：`api/routes/report.py`、`core/storage.py`。
  这两个文件最后一次提交都是 `a6a2fa3`（= `origin/main` HEAD），
  也就是说**红灯是 main 带进来的，不是 F4/P1 造成的**。

已用 CI 同版本 `ruff==0.16.2` 复现，确认只需改两处：

```
api/routes/report.py:  for event in (record.events or []):   -> for event in record.events or []:
core/storage.py:       列表推导式折行 -> 单行
```

---

## 一、F5-1 格式化 2 个文件

在 p1 工作区 `D:\HZR_PROJECTS\ruoyi-scan-p1`：

```
"D:\tools\Python 3.12.9\python.exe" -m ruff format api/routes/report.py core/storage.py
```

要求：

1. 跑完 `git diff -- api/routes/report.py core/storage.py` 必须只有上面两处改动，
   多一行都停下来报告。
2. 不许顺手格式化其他文件。
3. 不许碰 p1 工作区里 P1-1 的在制品：
   `cli/runner.py`、`core/basepath.py`、`tests/test_basepath.py`、`tests/test_fingerprint_apidoc.py`。

## 二、F5-2 提交

```
git add api/routes/report.py core/storage.py
git diff --cached --name-only        # 必须只有这两个
git commit -m "style: 修复 a6a2fa3 带入的 format 门禁红灯（report/storage）"
```

---

## 三、门禁（CI 原范围，format 不含 tests/）

```
"D:\tools\Python 3.12.9\python.exe" -m ruff check common/ core/ lib/ api/ plugins/ chains/ cli/ tests/ scripts/ main.py
"D:\tools\Python 3.12.9\python.exe" -m ruff format --check common/ core/ lib/ api/ plugins/ chains/ cli/ main.py
"D:\tools\Python 3.12.9\python.exe" -m mypy common/ core/ --strict --ignore-missing-imports --no-warn-unused-ignores
"D:\tools\Python 3.12.9\python.exe" -m pytest tests/test_fp_baseline.py tests/test_f1_fingerprint_json.py tests/test_f1_jeecg_json.py tests/test_f1_swagger_config_noise.py tests/test_f1_cloud_config.py tests/test_f1_cli_submode.py tests/test_basepath.py tests/test_f3_session_leak.py tests/test_session_isolation_gate.py -q
```

四条必须全绿。

> 如果本机 ruff 是 0.16.6 而 CI 是 0.16.2，format 结论可能仍有偏差。
> 需要严格对齐时用：
> `"D:\temp\ruff0162\bin\ruff.exe" format --check common/ core/ lib/ api/ plugins/ chains/ cli/ main.py`

---

## 四、停点

1. 贴 `git diff` 的两处改动。
2. 贴 `git diff --cached --name-only`。
3. 贴 4 条门禁输出。
4. 贴 `git status --short`，确认 P1-1 的 4 个在制品原样未动。
5. **不 push，不开分支，不碰 19 个无关在制品，不碰 main。**
