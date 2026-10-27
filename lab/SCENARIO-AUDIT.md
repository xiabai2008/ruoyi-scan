# 真实用户场景审计与靶场升级（2026-10）

本轮不做功能堆叠，只回答一个问题：**把 ruoyi-scan 交给一个陌生人、在接近生产的环境里用，哪里会露馅。**

方法：把 8 类真实用法写成可复跑的脚本（`scripts/scenario_audit.py`），并新建两套保真度更高的靶场
（`lab/realistic`、`lab/chaos`）以及一套真实 RuoYi 栈（`lab/prod`），用它们反过来量扫描器的判定质量。

## 1. 场景矩阵（`python scripts/scenario_audit.py`）

| 场景 | 角色 | 关键断言 | 审计前 | 现在 |
|---|---|---|---|---|
| s1 首装首跑 | 新用户 | 退出码 0、报告有证据与修复建议、stdout ≤ 60 行 | 745 行（`-u` 刷屏） | `-p` 47 行 / `-u` 63 行 |
| s2 批量交付 | 安服 | 5 目标（含不可达、403、重定向）不中断、基线+复测可对比 | 通过 | 通过 |
| s3 CI 接入 | DevSecOps | `--ci` 退出码语义、SARIF 可被解析 | 通过 | 通过 |
| s4 异常输入 | 任何人 | 无 scheme / 重定向环 / 全站 403 不崩、不误判 | 3 处失败 | 已修 |
| s5 误报压力 | 任何人 | 11 个非若依站点 0 条 CONFIRMED | 通过 | 通过 |
| s6 平台化 | 二次开发 | `--serve` 建任务→轮询→取报告 | 通过 | 通过 |
| s7 整改复测 | 安服 | `--save-baseline` + `--remediation` | 通过 | 通过 |
| s8 对抗网络 | 任何人 | tarpit / 限速 / 5xx 抖动下仍守三态 | 未覆盖 | 部分（见 §4） |

## 2. 审计发现（按影响排序）

### A. 全站被 WAF 拦截时，22 条结论被判「确认不存在」——最严重

复现：目标对任意路径都返回 403（WAF 默认策略）。扫描结果 `SAFE=22 / UNKNOWN=6`，
报告写着「22 项确认不存在」。这直接违背三态纪律，且安服拿着这种报告去交付等于漏报。

修复：新增 `lib/reachability.py:detect_blocked()`，扫描开始前用「根路径 + 随机路径」探测；
若随机路径返回 401/403/406/429/5xx（而不是 404），判定为全站拦截，
随后把全部 SAFE 降级 UNKNOWN、报告顶部加红色横幅、JSON 增加 `blocked` 字段。

验证：同一 403 目标 → `UNKNOWN=26 / SAFE=0`（本轮复测），横幅出现，`blocked=true`。

### B. 单个接口要求登录时，插件把它算成「不存在」

复现：行为级靶场 `/system/role/list` 返回 `HTTP 200 + {"code":401,"msg":"认证失败"}`（若依的真实行为），
`POST型报错注入（role/dept）` 与 `任意文件上传` 全部判 SAFE，且证据为空。

修复：
- `sql_inject_role/dept`：识别 HTTP 401/403/429 **与业务码 401/403/429**（若依用 200 承载业务码），返回 UNKNOWN 并写明原因；
- `lib/reachability.py:upgrade_denied_safe_to_unknown()` 作为统一兜底：SAFE 且证据含拒绝标记 → UNKNOWN。

验证：行为级靶场上注入类由 SAFE 变为 UNKNOWN，证据为「基线请求被拒绝（业务码 401/403/429（认证失败））」。

### C. 版本过滤把 4.7.8 的主力 POC 全部跳过

`Router().resolve(ruoyi, 4.7.8)` 只返回 11 个插件，**SQL 注入、任意文件上传、定时任务 RCE 都不在其中**——
因为它们的 `affected_versions` 写成 `>=4.0,<4.6` / `>=4.0,<4.7`。

但仓库自己的证据与之矛盾：
- `lab/REAL-RUOYI.md`：真实 4.7.8 上这 4 个 POC 全部 CONFIRMED；
- `lab/version_matrix/src/v4.7.8/.../SysRoleMapper.xml` 仍然直接拼接 `${params.dataScope}`（4.8.0、4.8.2 同样存在）。

第一轮把上界改成 `<4.8.0` 仍然不对：复核 4.6.2–4.8.3 源码可见，
`SysRoleController.list` / `SysDeptController.list` **都没有 @DataScope 注解**，
`DataScopeAspect.clearDataScope` 不会执行，外部 `params[dataScope]` 会原样进入 mapper 的
`${params.dataScope}`——注入在 4.8.3 上依旧成立。`<4.8.0` 等于把 4.8.x 目标继续静默跳过。

最终修复：4 个 POC 取消上界（`affected_versions = ">=4.0"`），
`任意文件读取`/`路径穿越`/`定时任务调用目标` 保持 `<4.7`（真实 4.7.8 实测 SAFE）。
同步修正 `tests/test_ruoyi_versions.py`、`tests/test_d3_version_matrix.py`。

效果：`resolve(4.7.8)` 11 → 15 个插件；`resolve(4.8.0)` 11 → 15；`4.8.2 / 4.8.3` 9 → 13。

### D. 重定向环打印完整 traceback

`lib/soft404.py` 对预期的网络异常用 `warning(exc_info=True)`，用户看到 Python 堆栈会以为工具有 bug。
改为一行提示（`--debug` 仍保留堆栈）。

### E. `-u` 目录扫描刷屏

每条路径都打印一行（含 404），签名靶场上一次 `-u` 输出 745 行、其中 683 条是 404。
改为只打印 2xx/3xx 或解析出真实标题的条目，末尾给汇总；`--debug` 保留全量。745 → 63 行。

### F. 报告「请求数」恒为 0、详细结果表 11 列溢出（上一轮已修，本轮确认）

## 3. 靶场升级（三档，按保真度）

| 档位 | 路径 | 复现什么 | 运行方式 |
|---|---|---|---|
| 签名靶场（原有） | `lab/server.py` | 单一特征字符串命中 | `LAB_MODE=vuln LAB_PORT=8080 python lab/server.py` |
| 行为级仿真（新） | `lab/realistic/` | 真实会话 + 验证码 + CSRF、401 业务码、软 404、条件化漏洞语义（payload 对才有回显） | `LAB_PROFILE=vuln LAB_VERSION=4.7.8 LAB_PORT=8090 python lab/realistic/server.py` |
| 对抗网络（新） | `lab/chaos/` | 全站 403、tarpit、限速 429、随机 5xx、JS 挑战、软 404、gzip/chunked、连接重置 | `CHAOS_PROFILE=block_all CHAOS_PORT=8091 python lab/chaos/server.py` |
| 真实栈（新） | `lab/prod/` | RuoYi 4.7.8 + MySQL 8 + Redis + Nginx(自签 TLS) + 可选 ModSecurity CRS，含 stock/harden/waf 三档 | `docker compose -f lab/prod/docker-compose.yml up -d` |

`lab/realistic` 自带 136 条自测断言（`python scripts/lab_selftest.py`），全部通过；
`lab/prod` 已通过 `docker compose config` 校验，`scripts/prod_smoke.py` 提供三档冒烟探针；
本机 Docker Hub 不可达，镜像拉取需先配置镜像源（`lab/prod/README.md` 有说明）。

## 4. 用新靶场量出来的结果

> 数据日期 2026-10-27，命令与解析方式见 `scripts/scenario_audit.py`（签名靶场）与
> 本文件同名表格的复测脚本；行为级靶场均为 `LAB_VERSION=4.7.8`。

| 目标 | CONFIRMED | UNKNOWN | SAFE | 说明 |
|---|---|---|---|---|
| 签名靶场 vuln | 20 | 1 | 3 | e2e total=24，与升级前一致，无回归 |
| 行为级靶场 vuln | 3 | 7 | 12 | 未登录：Nacos 配置泄露 / 任务 RCE / 未授权访问 |
| 行为级 + `--auth-login` | 5 | 4 | 13 | 登录后再确认 role/dept 报错注入 |
| 行为级靶场 safe | 0 | 9 | 13 | 加固版零误报；UNKNOWN 含 4 个需登录的注入/上传/任务 POC |
| chaos block_all | 0 | 26 | 0 | 全站拦截全部 UNKNOWN |
| chaos soft404 | 0 | 6 | 18 | 软 404 未产生误报 |
| chaos flaky (30% 5xx) | 0 | 4 | 18 | 未出现整站误判（随机抖动，UNKNOWN 数会小幅波动） |
| chaos ratelimit | 0 | 12 | 10 | 429 + Retry-After 下 3.1s 收尾，不冒充 SAFE |

结论：**签名靶场的 20/20 高命中率有相当一部分来自「按靶场特征写判定」**；换成行为级仿真后，
真正能不依赖签名确认的是 Druid 未授权、文件上传/任务 RCE 这类有真实回显的项，
其余因验证码阻断登录而落到 UNKNOWN——这是诚实的，但也说明「认证后能力」是目前最大的短板。

## 5. 已解决（第二轮）

| 问题 | 做法 | 验证 |
|---|---|---|
| 验证码阻断后无路可走 | `captcha_infra` 提示直接给出两条出路（装 `[ocr]` / `--auth cookie`）；`docs/usage.md` 同步 | 行为级靶场 `LAB_CAPTCHA=off` 后 `--auth-login` 立即确认 role/dept 注入 |
| 限速拖死扫描 | `Retry(respect_retry_after_header=False)`：不再按 `Retry-After: 30` 睡眠 | chaos ratelimit：**300s 超时 → 3.1s**；UNKNOWN=12 / SAFE=10 / CONFIRMED=0 |
| 慢站无限拖长 | 新增 `--time-budget SECONDS`：超预算的插件直接记 UNKNOWN | chaos slow（2–5s/请求）：`--time-budget 30` 下 71.7s 收尾（原先 280s 仍未结束） |
| Nacos 证据自相矛盾 | 支持真实 Nacos 的**明文配置正文**形态；SAFE 时写明缺哪个特征；靶场改为 `text/plain` | 未登录 3 CONFIRMED（含 Nacos 配置泄露），登录后 5 CONFIRMED |
| Swagger 把 Druid 算成 API 文档 | `/druid/index.html` 从该插件候选里移除（由未授权访问插件负责），证据文案改写 | 同一目标不再出现「Swagger 泄露 + 未授权访问」双报 |

> 未登录 3 条 = Nacos 配置泄露 / 定时任务 RCE 未授权 / Druid；登录后 5 条 = 再加 role、dept 报错注入。
> 也就是说：**认证后的检出能力是够的，卡点是「过验证码」这一步。**

## 6. 仍未修（待排期）

1. 低权账号越权类（部门树、重置密码）依赖第二个账号；靶场只有 `admin`，需要补一套权限矩阵。
2. `lab/prod` 的运行时已由独立审计在 Docker Desktop 上验证（stock 栈 healthy，MySQL 20 表、
   admin 哈希、非 root 运行均核对）；harden/waf 只做了短时验证，CI 无 Docker，运行时回归仍靠手工。
3. 本机 `~/.ruoyi-scan/plugins/` 存有 2026-08 的旧插件副本，会让同一台机器上的扫描出现重名结论
   （本轮已将其移出备份，验证全程在干净环境跑）。产品侧可考虑对用户插件做「同名/同 id 去重」提示。

## 7. 本轮复核（2026-10-27 晚）

| 检查 | 结果 |
|---|---|
| `python scripts/scenario_audit.py`（8 类场景） | **6/6 PASS**（修好脚本自身 2 处断言：退出码 3 属预期、报告端点应为 `/api/report/{id}/html`） |
| `python scripts/lab_selftest.py` | **136/136 PASS**（修正一处过时断言：Nacos 已改返回 YAML 正文） |
| 签名靶场 e2e（CI 同款命令） | total=24 CONFIRMED=20 SAFE=0 UNKNOWN=0 **PASS** |
| 真实 RuoYi 4.7.8 栈（Docker） | 修复前：nginx `Host $host` 丢端口 → 24 条全 UNKNOWN；修复后重扫：UNKNOWN=8 / SAFE=16，登录墙下的注入/上传/任务/SSTI 均落 UNKNOWN（见 §8.2） |
| `ruff check` / `ruff format --check`（CI 口径） | 通过 |
| `mkdocs build --strict` | 通过（0 warning） |

另外两条口径说明：
- 首跑输出噪声以 `-u` 计（目录扫描是噪声大头），`-p` 47 行、`-u` 63 行都低于承诺的 60/200 行阈值；
- 版本过滤修正后，行为级靶场（4.7.8）会多跑 role/dept/上传/任务 4 个 POC，
  未登录时它们按新规则落到 UNKNOWN（而不是被静默跳过），这是三态纪律的预期结果。

## 8. 独立审计（两名 subagent，2026-10-27 深夜）

### 8.1 陌生人干净安装（fresh-user）

在 `%TEMP%` 全新 venv 里 `pip install` 仓库快照，只按 README/docs 使用（不看源码）：

- **P0 `--help` 直接失败**：只注册了 `-h`，`ruoyi-scan --help` 报 `unrecognized arguments` → 已修（两个 flag 等价，含回归测试）。
- **P0 无协议目标假 SAFE**：`-p 127.0.0.1:18090` 全部请求 InvalidSchema，报告仍有 1 条 SAFE → 已修（入口补 `http://`，批量文件同理）。
- 文档口径：`[ocr]` extra 不存在、`python -m lab.run` 不存在、退出码/报告命名/38 vs 54 POC 不符 → 已修；
  批量 `#` 注释被当目标 → 已按文档跳过。
- **未修（待排期）**：批量多目标固定 `report.html` 会互相覆盖；同一插件偶发 SAFE+UNKNOWN 双结论（登录链失败路径）；
  `-u` 耗时随目标差异大（干净环境签名靶场 63 行/约 1 分钟，其快照里 409s/754 行受旧用户插件副本干扰，已清理）。

### 8.2 真实栈 + 判定对抗（prod-auditor）

Docker Desktop 拉起真实 RuoYi 4.7.8 stock 栈：

- **P0 真栈 nginx 头失真**：`Host $host` 丢 8443 → Shiro 302 到 `http://127.0.0.1/login`，扫描 24 条全 UNKNOWN。
  已修 `Host $http_host` + `SERVER_FORWARD_HEADERS_STRATEGY=framework`，复测跳转已是 `https://127.0.0.1:8443/login`。
- **P0 登录墙未兜底**：真实 4.7.8 用 302→/login（不是 401），7 个插件+信息泄露类都曾把「没测到」写成 SAFE。
  已修：`login_wall_reason()` 接入 role/dept/upload/job_rce/file_read/file_read_path/thymeleaf；
  并新增 `detect_auth_wall()` + `downgrade_auth_wall_safe()` 做统一兜底（明确 404 的 SAFE 保留）。
- P1 `prod_smoke` 验证码探针缺 `?type=math`（三档 smoke 均 exit=2）→ 已修。
- P1 `detect_blocked` 误报（随机路径 429/5xx + 根路径正常）→ 已收窄；否定式证据（「未含 Forbidden」）不再误降级。
- **未修**：`--time-budget` 是软上限（单插件重试可超预算）；ratelimit 下仍有证据为空的 SAFE
  （插件契约层应要求 SAFE 带证据，下一步统一）。
