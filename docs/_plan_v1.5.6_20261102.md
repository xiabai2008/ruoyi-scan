# v1.5.6 计划：从「能报」到「报得准、报得全」

- 制定：2026-11-02（承接 v1.5.5 盲测 v3 的剩余边界）
- 前置：v1.5.5 已发布（46/54 插件有 CONFIRMED）；盲测 v3 剩余 8 个零产出全部是**已识别边界**
- 本版目标：**清掉「便宜即可达成」的边界**，并把「口径正确性」补上——
  v1.5.5 解决的是「该报的能报」，本版解决「报出来的能不能直接信、能不能直接用于交付」

---

## 一、起点（2026-11-02 已完成的 WP2+WP6）

| 提交 | 内容 | 实测 |
|---|---|---|
| `226423b` | 归属判定：区分站点级/宿主级资产 | R1/R7 + 批量两站点，标注正确；终端与报告口径一致 |
| `1fd4ff4` | Redis 探测端口可配（`--redis-port`） | R1/R7 `--redis-port 16379` → CONFIRMED |

**这两个 WP 暴露的重要事实**：盲测 v3 记录的「Redis 零产出＝需无认证 Redis 靶场」**归因错了**。
真实根因是插件把 `port = 6379` 写死，而靶场 C4-1 刻意跑在 16379（避开宿主已占用的 6379）。
→ **本版第一纪律：先把「边界」当成待验证假设，逐条核实根因，再决定是否要建靶场。**

## 二、v1.5.6 工作包（按 ROI 排序）

### WP1 · 自定义 context-path 识别（最高 ROI，影响所有路径类插件）

**已核实的真实残余**（MEMORY 五-0 的「base_path 没贯通」表述已部分过时）：

`core/basepath.py:25` 的 `CANDIDATES` 是写死的 5 个前缀（`/prod-api /dev-api /api /jeecg-boot /jeecg`），
且**只靠验证码接口**判定（`CAPTCHA_PATHS = ("/captchaImage", "/code", "/auth/code")`）。
自定义前缀（D1 二开的 `/portal`）落不进候选表 → 识别不出 → 路径类插件整类探错基准。

- **做法**：
  1. **被动提取**（不增加请求）：从任意一次响应里读 context-path 线索——
     `Set-Cookie` 的 `Path=`、302 的 `Location`、HTML 里 JS 的 `baseURL`/`VUE_APP_BASE_API`、
     `/v3/api-docs` 的 `servers[].url`。
  2. **主动探测兜底**：把候选表改为「常见前缀 + 从 SPA 首页/JS 里正则抽出的前缀」，
     仍以「验证码接口返回真图片」为判据（不放松判定，只扩充候选来源）。
  3. **`--base-path` 手动指定**（最后手段）：现场运维知道前缀却识别不出时可用；
     优先级最高，跳过自动探测。
- **验收**：D1（`/portal`）不加 nginx 兼容映射也能命中 job RCE / gen SSTI；
  R6/R7/R9/R10 既有结论零回归；新增单测覆盖「被动提取」四条线索。
- **风险**：往候选表里加前缀会成倍增加请求数。必须给被动提取优先、主动兜底设上限（≤8 个候选）。

### WP2 · Windows 靶场文件读取（能力缺口，非判定缺陷）

**已核实**：`lib/matcher.py:252` 的文件特征只有 `root:x:0:0:` 系列 + `[boot loader]`（boot.ini），
**没有 win.ini 特征**；`is_passwd_file` 也只认 /etc/passwd 格式。
`plugins/ruoyi/file_read.py` 的 `reproduce` 里写了 win.ini 的 curl，但**判据不支持**——
文档承诺了、代码没实现，这是典型的「能力虚报」。

- **做法**：
  1. `lib/matcher.py` 新增 `is_windows_ini(text)`：识别 `[fonts]`/`[extensions]`/`[mci extensions]` 段
     + `for 16-bit app support` 特有关键字（win.ini 的真实结构），**要求 ≥2 个段头**避免单行误报。
  2. `file_read` / `file_read_path` 双载荷：Linux 探 `/etc/passwd`，Windows 探 `/windows/win.ini`；
     任一命中即 CONFIRMED，证据里写明命中的是哪个系统。
  3. 靶场侧：在 R1–R5 任一站点放一份真实 win.ini（`C:\Windows\win.ini` 的原样拷贝），
     并让 `/common/download/resource` 真能读到（已有 profile 绝对路径链路，见 `4b15a05`）。
- **验收**：Windows 靶场上两插件 CONFIRMED；Linux 特征零回归；`test_fp_baseline` 零误报。
- **约束**：`[boot loader]`（boot.ini）**不算** win.ini 特征——XP 时代的 boot.ini 与 win.ini 是不同文件，
  混用会让判定在 Win10/11 上漏报。

### WP3 · RuoYi-Plus 定时任务未授权（**已改为判定层修复**，2026-11-02 实测推翻原方案）

**原计划**：给 R9 加 vuln 模式（`security.excludes` 追加 `/monitor/**`），让插件 CONFIRMED。

**实测发现（推翻原计划）**：RuoYi-Vue-Plus **5.6.2 的定时任务已迁到 SnailJob**
（独立调度中心，`snailjob.version=1.10.0`，依赖 `snail-job-client-*`），
源码里**根本没有 SysJobController**，`/monitor/job/**` 返回
`HTTP 200 + {"code":404,"msg":"请求地址不存在","data":null}`。
→ **不是误配能造出来的**：这个端点在 5.6.2 里不存在，任何配置都变不出来。

**真正的问题在判定层**：插件把「端点不存在」和「鉴权生效」都判成 SAFE，
等于用「地址错了」冒充「系统是安全的」。三态纪律里 SAFE = 测过了、确认不存在；
端点不存在时没有可测的东西，应当 UNKNOWN。

- **已做**：`plus_job_unauth` 按若依 AjaxResult 业务码判「端点不存在」→ UNKNOWN；
  `affected_versions` 补 `>=5.0,<5.6`（按 5.6.2 实测 + 5.6 引入 SnailJob 推定，
  5.0–5.5 未逐版本验证，注释里已标明）。
- **靶场侧**：R9 的 `--lab-mode vuln`（SPRING_APPLICATION_JSON 追加 excludes）仍保留，
  供 **Plus 5.5 及更早** 形态复用；对 5.6.2 无效，因为端点不存在。
- **重要**：版本过滤只在指纹识别出版本时生效。R9 的 api-docs 需认证（401）、
  根路径是纯 SPA，版本识别不出 → 过滤不生效。**这就是必须在插件判定层修的根本原因。**
- **验收**：R9（5.6.2）上插件判 UNKNOWN 且证据写明 SnailJob；5.5 及更早的真实误配站
  仍需另行建站才能验证 CONFIRMED（列为后续候选）。

### WP4 · 备份文件靶场（✅ 已完成，`24382f0`）

**已核实**：`backup_scan` 的字典是**可预测名**（`base_names = ["index", "config", ".env", "web", "app"]`
× 12 后缀）。2026-11-01 回退过的「常见目录 × 后缀」是**另一回事**（猜不可预测的带日期文件名，本质无解）。

- **做法**：`lab_assets/R7-ui-backup/` 放 `index.bak` / `config.old`，由 `lab_assets.py` 铺到 `ui/`。
  内容是原文件的陈旧拷贝（不是 marker）。
- **踩到的坑**：第一版造了 `index.html.bak` / `config.js.old`——**扫描器根本不探这两个名字**
  （字典是 `{base}{suffix}` 拼接，base 只有 index/config/.env/web/app）。
  资产名必须**命中插件字典**，否则靶场再真也检不出。
- **验收**：`backup_scan` 在 R7 上 CONFIRMED，证据列出 `/index.bak, /config.old`；
  且站点有兜底路由时判定正确（兜底页 12623 字节 vs 备份文件 217 字节）。
- **约束**：**禁止**重做 2026-11-01 已回退的「目录 × 后缀字典扩充」——那是已知无效方向。

### WP5 · 能力虚报清理与口径对齐（质量债，必做）

已核实的三处不一致：

1. **Shiro 插件能力虚报**：`plugins/common/shiro_rememberme.py` 挂 `CVE-2016-4437` + `severity=high`，
   但只做指纹识别、**永远 CONFIRMED 不了**（设计边界）。矩阵里标 L1「已验证」，误导读者。
   → 决策点（见下）：要么实现密钥爆破+回显验证，要么去掉 CVE、降级 severity、名称去掉「反序列化」。
2. **`lab/README.md:89` 与 `lab/server.py:320`** 仍描述旧的「读 2.txt」oracle，与现行
   `resourceDownload` 判定（`docs/version-matrix.md` 已有准确描述）漂移。
3. **`docs/verification-matrix.md` 计数**：表头写 57 个插件，实际 `--plugin-list` 为 54。
   （57 含 3 个 chain 步骤类，口径需在文档里写明区分。）

- **验收**：三处文档与代码一致；`verification_matrix.py --check --max-none 13` 仍过；
  若选「去 CVE」路径，需同步检查 `data/` 与报告里的 CVE 统计口径。

### WP6 · 盲测 v4 + 修复

- 冻结 lab tag + manifest（沿用 v1.5.5 流程），跑同一套扫描矩阵（anon/auth/safe/独占）。
- 重点看三件事：① WP1 是否让路径类插件在自定义前缀站点上产出；② 宿主级归属是否在全部站点
  正确标注、有无漏标；③ 新增 CONFIRMED 是否全部为真（B 类误报必须 0）。
- 产出 `docs/blind_test_report_v4.md`。

### WP7 · 发布 v1.5.6

版本位 6 处 + CHANGELOG + release-notes；全量 pytest/ruff/mypy/签名靶场 E2E；
push → CI 绿 → tag → GitHub Release / PyPI / 桌面端核验。
**新增**：`--redis-port` 与 `--base-path` 需同步进 `docs/usage.md` 与命令手册（`docs/promo/`）。

## 三、验收标准（可发布条件）

- 盲测 v3 的 8 个零产出中：recon ×2 与 Shiro ×1 维持「设计边界」表述（不追）；
  **其余 5 项中 ≥4 项转 CONFIRMED**（文件读取 ×2、Plus job、备份 = 4 个新建靶场目标；
  Redis 已在 v1.5.6 WP2 完成）。
- **B 类硬误报 = 0**（每个新靶场必须带 safe/负样本对拍）。
- 归属标注在**全部**中间件类发现上生效，终端/HTML/CSV/JSON/批量报告五处口径一致。
- 全量 pytest、ruff check/format（CI 范围）、mypy strict、check_version、verification_matrix 全绿。
- **记忆与文档时效性**：本轮已核实的过时表述（五-0、Redis 归因、lab README）全部修正并留痕。

## 四、决策点（需要人拍板）

**Shiro 插件怎么处理？** 三条路，成本与收益差异大：

| 方案 | 成本 | 收益 | 风险 |
|---|---|---|---|
| A. 去掉 CVE + 降 severity + 改名 | 半天 | 消除能力虚报，口径诚实 | 报告里少一条 high，star 叙事略损 |
| B. 实现默认密钥爆破 + 回显验证 | 2–3 天 | 真正能 CONFIRMED，能力实打实 | 需可控靶场（R1 的 ShiroConfig 已配默认 key）；爆破有速率/锁定风险 |
| C. 置为 `category=recon` | 1 小时 | 口径上承认它是侦察项 | 仍有 CVE 编号，读者仍会误解 |

**建议 A**（v1.5.6 内），把 B 留给 v1.6（需要真实回显靶场 + 速率控制设计，不该挤在收尾版）。

## 五、约束（沿用 v1.5.5 纪律）

1. **先核实根因再建靶场**：Redis 的教训——「缺靶场」可能只是「配置缺一个参数」。
2. 禁止对着插件源码写 mock 当真实靶场；签名靶场只用于 CI 回归。
3. 新判定必须过 `tests/test_fp_baseline.py`；新增 CONFIRMED 同步 `data/acceptance_baseline.json`。
4. 时间盒：单工作包超过 1 天无进展 → 降级/换 ROI 更高项。
5. **报告加列必须同步 colspan**（已改为按表头列数动态校验，但新增列仍要核 CSV/SARIF/XLSX 三处）。
