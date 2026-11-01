# 工单 F4：清场与分批提交（两棵树归位）

> 执行者：opencode。验收者：lead。
> **本单有删除/还原操作，必须先做备份，再动文件。**
> 目标：让 main 工作区回到只剩「无关在制品 + 垃圾 + 工单文档」，把 F1/F3 归到
> `feat/p1-blindtest` 分支，历史可读、可回滚。

---

## 零、现状（lead 已核实，2026-10-31 12:20）

- `main` 工作区 `D:\HZR_PROJECTS\ruoyi-scan`：HEAD `a6a2fa3`，**73 条未提交**。
- `feat/p1-blindtest` 工作区 `D:\HZR_PROJECTS\ruoyi-scan-p1`：
  - `2152a56` 盲测 P0/P1（32 文件）
  - `4323758` F1b basepath（2 文件）
  - 工作区干净，仅 `?? artifacts/`
- main 里 34 个文件与分支 HEAD **逐字节一致**（32 个来自 2152a56 + basepath/test_basepath 来自 4323758）。
  也就是说：上一轮是「复制到分支」，不是「移动到分支」，main 没清。

---

## 一、F4-0 备份（不备份不许往下做）

```bash
mkdir -p /d/HZR_PROJECTS/_backup_20261031_1225
cd /d/HZR_PROJECTS/ruoyi-scan
git diff > /d/HZR_PROJECTS/_backup_20261031_1225/main-tracked.patch
git ls-files -o --exclude-standard > /d/HZR_PROJECTS/_backup_20261031_1225/untracked.txt
tar -czf /d/HZR_PROJECTS/_backup_20261031_1225/untracked.tar.gz -T /d/HZR_PROJECTS/_backup_20261031_1225/untracked.txt
```

备份完检查三个文件都存在且非空，把 `ls -l` 贴进报告。

---

## 二、F4-1 校验 34 个重复文件确实一致（不一致就停）

写一个临时脚本 `artifacts/f4/check_dup.py`，逐个比对
`git show feat/p1-blindtest:<path>` 与本地文件字节；34 个必须全部 `一致`。

名单：

```
cli/runner.py
config/settings.py
core/auth_chain.py
core/captcha_solver.py
core/orchestrator.py
core/report.py
core/session.py
lib/auth_scan.py
lib/auth_surface.py
plugins/base.py
plugins/common/swagger_leak.py
plugins/ruoyi/cve_2025_46174_resetpwd_scope.py
plugins/ruoyi/cve_2025_70986_select_dept_tree.py
plugins/ruoyi/default_password.py
plugins/ruoyi/file_upload.py
plugins/ruoyi/job_invoke_target.py
plugins/ruoyi/ruoyi_gen_rce.py
plugins/ruoyi/ruoyi_swagger_unauth.py
plugins/ruoyi/sql_inject_dept.py
plugins/ruoyi/sql_inject_role.py
tests/regression_ruoyi.py
tests/test_anon_session_plugins.py
tests/test_auth_surface.py
tests/test_captcha_solver.py
common/paths.py
core/lowpriv.py
docs/blind_test_report_20261031.md
docs/phase5_p0_验收.md
docs/phase5_p1_0_验收.md
docs/phase5_p1_0bc_验收.md
docs/phase5_p1_0def_验收.md
tests/test_auth_status_gate.py
core/basepath.py
tests/test_basepath.py
```

**任何一个不一致就停下报告**，不要强行还原。

---

## 三、F4-2 清掉 main 上的 34 个重复项

1. 24 个已跟踪文件 + `core/basepath.py` + `tests/test_basepath.py`：

```
git restore -- cli/runner.py config/settings.py core/auth_chain.py core/captcha_solver.py core/orchestrator.py core/report.py core/session.py lib/auth_scan.py lib/auth_surface.py plugins/base.py plugins/common/swagger_leak.py plugins/ruoyi/cve_2025_46174_resetpwd_scope.py plugins/ruoyi/cve_2025_70986_select_dept_tree.py plugins/ruoyi/default_password.py plugins/ruoyi/file_upload.py plugins/ruoyi/job_invoke_target.py plugins/ruoyi/ruoyi_gen_rce.py plugins/ruoyi/ruoyi_swagger_unauth.py plugins/ruoyi/sql_inject_dept.py plugins/ruoyi/sql_inject_role.py tests/regression_ruoyi.py tests/test_anon_session_plugins.py tests/test_auth_surface.py tests/test_captcha_solver.py core/basepath.py tests/test_basepath.py
```

2. 8 个未跟踪文件（内容在分支里，已备份）：

```
rm common/paths.py core/lowpriv.py docs/blind_test_report_20261031.md
rm "docs/phase5_p0_验收.md" "docs/phase5_p1_0_验收.md" "docs/phase5_p1_0bc_验收.md" "docs/phase5_p1_0def_验收.md"
rm tests/test_auth_status_gate.py
```

3. 校验：`git status --short | wc -l` 应从 73 降到 **39**。
   若数字不对，停下报告，不要继续。

---

## 四、F4-3 把 F1 剩余改动与 F3 守卫搬到 p1 分支

main 上保留的 39 条里，以下 13 条属于 F1/F3，**复制**到
`D:\HZR_PROJECTS\ruoyi-scan-p1` 对应路径（复制后先 `cmp` 校验一致，再执行 F4-2 的还原）：

```
# F1 判定修复（6）
cli/dispatcher.py
core/fingerprint.py
core/fingerprint_features.py
lib/soft404.py
plugins/spring/spring_cloud_config.py
docs/promo/ruoyi-scan-plugins.txt
# F1 测试（5）
tests/test_f1_cli_submode.py
tests/test_f1_cloud_config.py
tests/test_f1_fingerprint_json.py
tests/test_f1_jeecg_json.py
tests/test_f1_swagger_config_noise.py
# F3 守卫（2）
tests/test_f3_session_leak.py
tests/test_session_isolation_gate.py
```

复制后在 **p1 工作区**分 3 个 commit：

```
# commit 1
git add core/fingerprint.py core/fingerprint_features.py tests/test_f1_fingerprint_json.py tests/test_f1_jeecg_json.py
git commit -m "fix(fingerprint): spring 根路径错误 JSON 指纹 + jeecg 登录响应键校验"

# commit 2
git add lib/soft404.py plugins/spring/spring_cloud_config.py cli/dispatcher.py docs/promo/ruoyi-scan-plugins.txt tests/test_f1_cloud_config.py tests/test_f1_swagger_config_noise.py tests/test_f1_cli_submode.py
git commit -m "fix(judgement): 路径回显归一化 + Cloud Config 真检测 + 子模式开关"

# commit 3
git add tests/test_f3_session_leak.py tests/test_session_isolation_gate.py
git commit -m "test(gate): F3 行为级会话隔离门禁 + 覆盖登录入口包装层"
```

每个 commit 前必须先 `git diff --cached --name-only`，确认只有本批文件。

---

## 五、F4-4 收尾 main 与 .gitignore

1. main 上剩余应该是：19 个无关在制品 + 3 个垃圾 + 4 个工单文档。把 `git status --short` 贴出来。
2. `artifacts/`、`desktop/dist_prev_*/` 加进 `.gitignore`（当前只有 `desktop/artifacts/`）。
   在 p1 分支提交一条 `chore(gitignore): 忽略 artifacts 与 dist_prev 构建残留`，然后把 main 的
   `.gitignore` 同步过去（或直接在 main 提交，二选一，写清选择）。
3. **19 个无关在制品不许动**（`lib/ai_*`、`tests/test_ai_*`、`api/routes/report.py`、
   `core/report_sarif.py`、`core/storage.py`、`lib/notifier.py`、`lib/nuclei_loader.py`、
   `desktop/*`、`CHANGELOG.md`、`tests/test_api_scan.py`、`tests/test_report.py`、
   `tests/test_nuclei_loader.py`、`tests/test_d20_d21_d22_d26.py`），它们属于另一批工作。

---

## 六、门禁（在 p1 工作区跑）

```
"D:\tools\Python 3.12.9\python.exe" -m ruff check common/ core/ lib/ api/ plugins/ chains/ cli/ tests/ main.py
"D:\tools\Python 3.12.9\python.exe" -m ruff format --check common/ core/ lib/ api/ plugins/ chains/ cli/ main.py
"D:\tools\Python 3.12.9\python.exe" -m mypy common/ core/ --strict --ignore-missing-imports --no-warn-unused-ignores
"D:\tools\Python 3.12.9\python.exe" -m pytest tests/test_fp_baseline.py tests/test_f1_fingerprint_json.py tests/test_f1_jeecg_json.py tests/test_f1_swagger_config_noise.py tests/test_f1_cloud_config.py tests/test_f1_cli_submode.py tests/test_basepath.py tests/test_f3_session_leak.py tests/test_session_isolation_gate.py -q
"D:\tools\Python 3.12.9\python.exe" scripts/verification_matrix.py --check --max-none 13
"D:\tools\Python 3.12.9\python.exe" scripts/export_plugin_list.py --check
```

全绿才算完成。

---

## 七、停点

1. 贴备份文件清单。
2. 贴 34 个文件的一致性校验结果。
3. 贴 main `git status --short | wc -l`（必须是 39）与完整清单。
4. 贴 p1 的 `git log --oneline -5` 与三次 commit 的 `git diff --cached --name-only`。
5. 贴门禁输出。
6. **不许 push，不许开新分支，不许碰 19 个无关文件。**
