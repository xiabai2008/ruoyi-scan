# Ruoyi-Scan 深度研究：实际使用效果 / 代码结构质量 / GitHub 数据 / 后续迭代方向

> 数据截止：2026-11-16（GMT+8）
> 一手数据源：GitHub REST/GraphQL API（`xiabai2008/ruoyi-scan`，已认证）、PyPI JSON API、pypistats.org、本地 git（`main` @ `890b7f2`）、本地代码库 AST 统计、本地 `docs/` 与 `.workbuddy/memory/`
> 说明：本报告只读，未修改任何现有文件。本地工作区存在并行会话的在制品（`README.md` 已改、`AUTHOR.md` 已删、若干未跟踪图片），统计时已排除生成物目录。
> 版本基线：v1.6.0（tag），PyPI 1.6.0，共 19 个 GitHub Release、14 个 PyPI 版本。

---

## 0. 一句话结论

**项目工程完成度远超可信度验证完成度。v1.7 不该再加功能，应该把全部力气押在「三态判定的可度量化」上——把 30.7% 的 UNKNOWN 归因清楚、把 `48/54` 换成带 Ground Truth 的召回率/精确率。**

这条同时解决两个问题：产品上，它是所有效果数字的地基；毕设上，它是《基于三态判定的若依漏洞扫描器设计与实现》唯一能拿出手的实验章节。现在最危险的不是某个插件判错，而是**核心创新点从未被量化证明过**。

---

## 1. 关键数字总览

| 维度 | 数字 | 判定 |
|---|---|---|
| GitHub stars / forks | **55 / 10** | 关注度小，且增长已衰减 |
| 外部人类贡献者 | **0** | contributors 仅 `xiabai2008` + `dependabot[bot]` |
| 真实外部用户 issue | **2**（共 27 条 issue） | 1 条问用法、1 条桌面端白屏 bug |
| 真实第三方独立测评 | **0** | 命中文章全是同一篇自投稿通稿的转载 |
| 自有 Python 代码 | **85,806 行 / 350 文件** | 生产 49,052 + 测试 28,152 |
| 测试用例 / CI | **1,633 用例 / 8 workflow / 11 jobs** | 门禁体系相当完整 |
| 桌面端代码 | **17,688 行 / 21 个 `.tsx` / 0 单元测试** | 却是下载量最高的交付物 |
| PyPI 非镜像累计下载 | **1,980 次 / 69 天**（日均 28.7） | 含镜像 7,289，镜像占 73% |
| Release 累计下载 | **约 1,286 次** | `ruoyi-scan-desktop.exe` 单项 380 次 |
| 对外效果数字 | **48/54** | 插件覆盖率代理指标、v1.5.6 基线、不覆盖当前发布版 |
| UNKNOWN 占比 | **30.7%**（567 / 1,849） | 三态判定的核心软肋，未归因 |

---

## 2. GitHub 与分发数据

### 2.1 关注度：曝光驱动，且已衰减

仓库创建于 2026-07-23，最后 push 2026-11-14。55 stars / 10 forks / 0 watchers（subscribers_count=0）/ 0 discussions / 1 open issue（安全依赖告警）。

Star 月度新增（`stargazers` 带 `starred_at`）：

| 月份 | 新增 star |
|---|---:|
| 2026-07 | 1 |
| 2026-08 | 18 |
| 2026-09 | **21** |
| 2026-10 | 8 |
| 2026-11（半月） | 7 |

9 月见顶后回落。项目自己的增长记录也承认这一点：`.workbuddy/memory/topics/release.md:7` 写「star 由曝光事件驱动（非自然流量）；用量/star 倒挂」。

### 2.2 社区：0 外部人类贡献

| 项 | 构成 |
|---|---|
| contributors | `xiabai2008` 267 + `dependabot[bot]` 40 = **2 个，全部非外部人类** |
| PR 55 条 | dependabot 52 条 + 作者本人 3 条 |
| Issue 27 条 | `github-actions[bot]` 18 条（nightly 验收失败告警）+ 作者 7 条 + **外部账号 2 条** |
| discussions | 0 |
| forks | 10 个，最近 3 个集中在 2026-10，无后续提交迹象 |

两条外部 issue 值得逐字看：

- **#1**（`xslzlccc`，2026-08-25）：「请问【单目标漏洞扫描】和【综合扫描】有什么区别呢？」—— 用法咨询。
- **#66**（`yiasong644-hue`，2026-10-19）：Windows 桌面版 v1.5.0 「新建任务」白屏。用户给出了 WebView2 Runtime 155.0.4283.62、两种安装包都复现、清缓存/重建 EBWebView 无效、浏览器访问 `127.0.0.1:8123` 正常、怀疑 React 初始化或 CSP —— **排查质量很高，是真在用的用户**。

**这是全项目唯一一条真实使用证据，而且指向桌面端 UI 崩溃，不是检出效果。** 结合 §2.4 的下载分布，这个信号的分量比它看起来重得多。

### 2.3 流量：数字虚高，机器人占比明显

近 14 天（GitHub Traffic）：

| 指标 | 总数 | 独立数 |
|---|---:|---:|
| views | 358 | 149（≈10.6 独立访客/天） |
| clones | **1,750** | 209 |

clones 的异常很直白：2026-11-13 有 371 次克隆却只有 **10 个 unique**，11-14 有 271 次却只有 **17 个 unique** —— 典型的 CI / 镜像 / 爬虫批量拉取。把 1,750 当「1,750 个人在用」是错的。

Referrers：github.com 69 / Google 40 / Bing 16 / 文档站 5 / 知乎 3 / pypi.org 1。热门路径里 `releases/tag/v1.6.0` 有 51 views、39 uniques，仅次于仓库首页 —— **流量是冲下载来的，不是冲代码来的**。

### 2.4 Release 资产：桌面端 exe 才是主角

19 个 Release 累计约 1,286 次下载。按资产累计排序，第一名是桌面端单文件 exe：

| 资产 | 累计下载 |
|---|---:|
| `ruoyi-scan-desktop.exe` | **380** |
| `checksums.txt` | 98 |
| `ruoyi-scan.exe`（CLI 单文件） | 75 |
| 各版本 `*_x64-setup.exe` 合计 | ≈170 |
| 各版本 `.whl` 合计 | ≈200 |

v1.6.0 单版 164 次下载里：desktop.exe 62（38%）、CLI exe 37（23%）、setup 17、**whl 仅 10（6%）**、tar.gz 5。`checksums.txt` 被拉 98 次说明其中有自动化脚本在跑，不是纯人工下载。

结论：**用户接触到产品的第一入口是 Windows 桌面端 exe，不是 pip、不是 CLI。**

### 2.5 PyPI：73% 来自镜像，且没有 pip 元数据

| 指标 | 数值 |
|---|---:|
| 当前版本 / 版本数 | 1.6.0 / 14 |
| 含镜像累计下载（9/7–11/15，69 天） | 7,289 |
| **非镜像累计下载** | **1,980**（日均 28.7） |
| 镜像占比 | **73%** |
| 非镜像月度 | 9 月 777 / 10 月 535 / 11 月 668（半月） |
| recent | last_day 8 / last_week 124 / last_month 1,046 |

`python_minor` 与 `system` 两类维度的 `category` **全部为 `null`** —— 这些请求没有 pip 的 User-Agent 元数据特征，多数是镜像同步 / CI 自动拉取，**不能折算成「真实安装用户数」**。月度曲线是波动而非增长，与 §2.1 的 star 衰减一致。

另外，`pyproject.toml:18` 的 PyPI description 至今写「**54 检测插件**」，实际运行时是 **56** 个。这是对外分发元数据，外部复核最容易一眼看穿的漂移。

### 2.6 外部口碑：全是同一篇通稿

中英两轮检索结果：

- 中文命中 5 处：CSDN、微信公众号（SRC 培训号）、cn-sec.com、先知社区、zone.ci —— **全部是作者 XIABAI 同一篇投稿的转载/搬运**，正文还停在 v1.2.2（写「16 个若依 POC」、让读者 `pip install ruoyi_scan-1.2.2-...whl`）。
- 英文检索无任何独立测评、benchmark、对比文章、误报率实测。

即：外部可见信息既不是第三方验证，也已经和当前版本脱节两个大版本。**曝光 ≠ 使用 ≠ 效果验证。**

---

## 3. 实际使用效果

### 3.1 结论先行

**真实外部使用效果证据 = 0。** 全部量化结果来自自建靶场、自建 CI、mock 会话的项目自测。项目自己对此很诚实，`README.md:29-30` 明写：

> 验证环境是一套自建的仿真靶场……**尚未经过大规模实战项目检验**，因此**不对漏洞检出率（产出率）、漏报率与误报率做任何承诺**。

`lab/README.md:122` 也写明靶场「验证的是插件的匹配逻辑是否正确，而非真实漏洞的可利用性」。这份诚实值得肯定，但不能替代验证。

### 3.2 四轮盲测的口径真相

| 版本 | 报告 | 结果 | 口径 |
|---|---|---|---|
| v1.5.3 | `docs/blind_test_report_20261031.md` | 19 CONFIRMED / 91 SAFE / 167 UNKNOWN，17 漏报 / 1 误报，UNKNOWN 60.3% | 逐站 TP/FN/FP |
| v1.5.4 | `docs/blind_test_report_v2.md` | TP 10 / FN 1 / FP 2（27 座） | GT 三方对照 |
| v1.5.5 | `docs/blind_test_report_v3.md` | 29/54 → **46/54** | 插件覆盖率 |
| v1.5.6 | `docs/blind_test_report_v4.md` | 46/54 → **48/54**，零产出 8→6，B 类硬误报 0 | 插件覆盖率 |

`docs/blind_test_report_v4.md:20` 原文定义：

> 覆盖判定：同一插件在任一报告中有 CONFIRMED 即计为「有产出」。

所以 **`48/54` 的分母是 54 个插件，分子是「至少在某一处报出过一次 CONFIRMED」**。它不是检出率、不是召回率、不是实战准确率。项目全仓库检索「召回率 / 精确率 / recall / precision」，唯一命中是 `docs/_plan_盲测v2_20261101.md:455` 的**计划表头**，不是结果。`docs/blind_test_report_v2.md:35` 只给计数（TP 10 / FN 1 / FP 2），且仅在 GT 覆盖的 27 站内成立。

三个额外问题：

1. **过时**：48/54 是 v1.5.6 基线，v1.6.0 已 56 插件，新增 2 个 yudao 插件从未进任何一轮盲测，`artifacts/lab_manifest_v4.json` 里 Y1 为 DOWN。
2. **不可复现**：`artifacts/blind_v4/aggregate.py` 读的 `docs/promo/ruoyi-scan-plugins.txt` 现在已是 56 项，重跑会得到与 54 口径不一致的结果。
3. **泛化未证**：`docs/_plan_v1.6_labs.md:9-39` 记载 48 个有产出插件里 **31 个（65%）只在 1 个站点验证过**；spring 3 座 / jeecg 2 座 / cloud 1 座。盲测 v4 靶场快照 33 项中 **UP 5 / DEGRADED 10 / DOWN 18**。

6 个零产出项：2 个 recon 类（设计上不产 CONFIRMED）、Shiro 指纹（已收口为 recon）、2 个任意文件读取（靶场侧缺未授权读点）、Plus 定时任务（真实版本端点已不存在）。`docs/_plan_v1.6_labs.md:156-210` 明确放弃补造 R14，结论是「维持 48/54」。

### 3.3 三态判定的未攻之地：30.7% UNKNOWN

这是全项目最重要、也最被低估的数字。`docs/_plan_v1.6_facts.md:20,27-28`：

> 61 份报告共 **1849 条结果，其中 UNKNOWN 567 条（30.7%）**。
> **v1.6 的第一优先级因此是「让 UNKNOWN 说真话」**：567 条里有多少是「真测不了」、多少是「被自己降级掉的正确答案」。

规划文档把这条列为待查，v1.6.0 最终交付的是框架扩展（芋道插件、`path_scope=both`、注册门禁）、靶场和判定缺陷修复，**UNKNOWN 归因没有做**。

这个缺口直接动摇毕设命题：三态判定的价值主张是「不确定就如实标注，不凑数、不误报」。但如果近三分之一结果是 UNKNOWN，且不知道其中混了多少本该 CONFIRMED 的正确答案，那么：

- 无法证明三态比二态更优（可能只是把漏报换了个标签藏起来）；
- 无法给出召回率（UNKNOWN 里的假阴性算哪边？）；
- 答辩时被问「UNKNOWN 率 30%，你怎么论证它合理」会答不上来。

**这是唯一一个「技术上必须做、论文上必须写、外部可信度上也必须补」的三重交点。**

### 3.4 能力声称 vs 验证覆盖

| 声称能力 | 代码 | 验证状态 |
|---|---|---|
| 56 个插件（对外写 54 / 源码文件 59） | 有 | 三套口径并存，`pyproject.toml` / `docs/index.md` / `ROADMAP.md` 仍写 54 |
| WAF 绕过 11 策略 | `lib/waf_bypass.py` 865 行 | mock 会话自测；`docs/promo/ruoyi-scan-usage-guide.txt:47` 自认对抗传输层只覆盖 Cloudflare 一类 |
| 分布式 Redis Master-Worker | `lib/distributed.py` 1019 行 | **有「死开关」虚报前科**（宣传脚本自述「原来命令静默退出 0」）；盲测明确未测 |
| SIEM（ECS/CEF/LEEF/Syslog） | `lib/siem_export.py` 579 行 | 零靶场用例、零接入记录 |
| OAST 带外检测 | `lib/oast.py` | `:338` 自注「DNS check 仅用于测试模拟」；未测 |
| AI POC 生成 | `lib/ai_generator.py` | `:181-182` 规则模板输出 `# TODO: 实现检测逻辑`；四轮盲测「AI 未测」 |
| 利用链 DAG / 3 条内置链 | `core/chain.py` 693 行 | 盲测明确 `--chain 未测`，3 个链步骤类 2 个验证级别为 `none` |
| `--serve` / `--passive` / `--crawl` / `--async` / `--nuclei` | 有 | `docs/blind_test_report_20261031.md:23`、`_v2.md:17` 均记「未测」 |
| nuclei 模板兼容 | 3 个自建模板 | `contrib/nuclei-templates/README.md:53` 自认「未经实网批量验证」；v2 盲测只在 C1-1 命中且自身误报 1 条 |
| 组件 CVE 比对 | `data/cve_offline.json` | 更新于 2026-09-09、20 条、**aliases 全为空** |

验收基础设施自身也不稳：`nightly-acceptance.yml:111-121` 自记「验收连续失败 16 天（9/19–10/04）却没有任何红色信号」；`lab/run_acceptance.sh:10` 只起 2 个容器，与 workflow 的 3 个不一致；`data/acceptance_baseline.json:4` 自认 jeecgboot / yudao 尚无签名靶场。

### 3.5 已知未修缺陷（节选）

`plugins/common/shiro_rememberme.py` 明确写「本插件只做框架指纹识别……**它永远不会 CONFIRMED**」；`tests/test_d19_d27_template_config.py` 2 条测试顺序污染（全量跑红、单跑绿）**未修**（`.workbuddy/memory/MEMORY.md:185-186`）；离线 CVE 库陈旧；`CHANGELOG.md:10-17` 记录唯一一次外部输入驱动的修复是「配置合并误吸 `sys.argv` 参数」，属代码评审反馈，不是检出效果反馈。

---

## 4. 代码结构质量

### 4.1 规模与分层（AST 实测，排除 vendored）

全仓 6,847 个 `.py` 里 **6,497 个（95%）是构建 venv / node_modules / dist 产物**。自有代码 350 个文件 / 85,806 行：

| 类别 | 文件 | 总行 | 代码行 |
|---|---:|---:|---:|
| 生产代码 | 195 | 49,052 | 37,410 |
| 测试代码 | 111 | 28,152 | 20,876 |
| 靶场 Python | 15 | 4,841 | 3,776 |
| 研究/临时脚本 | 27 | 3,564 | 3,052 |
| 桌面端 Python | 2 | 197 | 145 |

测试/生产 = **0.57**。`lib/` 是最大生产目录（18,373 行 / 45 文件），`core/` 10,302 行，`plugins/` 11,256 行。

### 4.2 做得好的地方（不要动）

- **`core/engine.py` 是全项目最干净的解耦**：不 import 任何 plugins 模块，靠鸭子类型 + `ScanResult` DTO 与插件通信，`enrich()` 统一回填元信息，`getattr` 读能力标志。这套设计是对的。
- **门禁体系密度罕见**：1,633 个 pytest 用例、误报基线（`test_fp_baseline.py`）、日志规范（`test_logging_hygiene.py`）、会话隔离（`test_session_isolation_gate.py`）、框架注册（`check_framework_registration.py`）、版本/依赖/插件清单一致性、覆盖率棘轮、CodeQL、Scorecard、nightly、Actions 全部按 commit SHA 固定。
- **核心运行时依赖只有 1 个**（`requests`），extras 分组清晰，供应链面很窄。

### 4.3 结构问题（按对迭代速度的影响排序）

| # | 问题 | 硬证据 |
|---|---|---|
| 1 | **编排层 god-function + 13 模块循环依赖** | `core/orchestrator.py:474 _run()` **752 行 / cc≈100**；`cli/runner.py:448 run_mode()` 325 行 / cc≈65；`cli/dispatcher.py:43 dispatch()` cc≈53。三者与 `main`、`api/app`、`lib/scheduler`、`lib/config_loader`、`lib/scan_templates` 靠**函数内延迟导入**构成 13 模块 SCC。无运行时死锁，但改一个扫描参数无法静态界定影响面 |
| 2 | **分层倒置** | `plugins → core` **65 条 import / 57 文件**（其中 56 条只是 `from core.http import join_url`）；`lib/config_loader.py:342`、`lib/scan_templates.py:277` 反向 `import main`。改 `core/http.py` 签名要连带核对 56 个插件；`lib/` 脱离 CLI 无法独立复用 |
| 3 | **插件数 / 版本号硬编码散落约 30 处** | 实际 56；`pyproject.toml:18` 写 54、`README.md` 写 56、`docs/verification-matrix.md:6` 写 59（源码文件数）。`desktop/src/data/mock.ts:33/90/97` 把 `"54"`、`"23/54 plugins"` 写进 UI mock。`.github/workflows/desktop-release.yml:167` 注释是事故实证：「**写死 54 时，新增芋道 2 个插件后桌面端构建直接失败**」。现有门禁只覆盖 5 个版本文件 + 插件清单，UI mock / docs / release / PyPI 描述不在范围内 |
| 4 | **用 6 个一致性脚本固化重复，而非消除重复** | `check_framework_registration.py` 检查 5 处框架清单（起因：JeecgBoot 接入时 6 处全漏）；新增第 6 个框架仍要同步 6+ 处，只是失败提前。重复代码实测：`test_report_docx/pdf/xlsx` 两两共享 55 个 5 行窗口，`sql_inject_dept.py` ↔ `sql_inject_role.py` 共享 51 个，会话隔离 3 行样板在 15 个文件逐字复制 |
| 5 | **类型 / 覆盖门禁与规模错配** | `pyproject.toml:185-187` 把 `lib.*`、`api.*` 设 `ignore_errors = true`，而 `lib/` 恰是最大目录且完全类型化函数只 31.8%；CI 的 `mypy --strict` 实际只跑 `common/`、`core/` 和 2 个 lib 文件。覆盖率 6 个手工阈值（78/84/**72**/85/75/95）硬编码在 `ci.yml:126-131`，无 `.coveragerc` |
| 6 | **输出双轨制** | 891 个裸 print（`cli/` 288、`scripts/` 160、`tests/` 205）vs 结构化 `lib/reporter.emit()`；门禁只管库层（`core` 1 个、`lib` 4 个）。终端输出与报告/API/桌面端是两条管线，格式一致性无收敛点 |
| 7 | **桌面端 17,688 行零单元测试** | 21 个 `.tsx`、无任何 `*.test.ts(x)`、无 vitest/jest/playwright。只有 `eslint src`、`tsc --noEmit` 和 3 个手写 CDP 脚本（`smoke:ui` / `check:fonts` / `check:ui`），且 `ci.yml:409-410,447-452` 注释表明这几条是为逐个历史 bug（React #310 白屏、字体切换失效）累加的补丁 |
| 8 | **工作树被 15,073 个生成物淹没** | `lab/` 3,790 文件、`reports/` 5,971、`artifacts/` 5,312，另有多份 `desktop/dist-old-*`、`tools/cli_build/build-old-local/`。任何全仓 grep / 静态分析都要先手工排除，固定成本很高 |

函数规模：40 个文件 >500 行，55 个函数 >100 行，151 个函数圈复杂度 ≥15，平均 cc≈4.32。模块 docstring 覆盖率仅 19%，函数 docstring 86.4%，完全类型化函数 31.8%。

### 4.4 最刺眼的一处错配

把 §2.4、§2.2、§4.3#7 叠起来看：

> 下载量最高的交付物是 `ruoyi-scan-desktop.exe`（380 次），唯一一条真实用户 issue（#66）报的是桌面端白屏，而桌面端是 17,688 行代码、**零单元测试**、靠 3 个手写 CDP 脚本兜底的模块。

用户唯一真正摸到的地方，恰好是工程质量最薄的地方。这不是巧合——桌面端没有组件测试层，所以每个运行时 bug 只能等外部用户报出来，然后补一条脚本。

---

## 5. 核心矛盾：投入产出倒挂

| 月份 | 提交数 | 新增 star |
|---|---:|---:|
| 2026-07 | 48 | 1 |
| 2026-08 | 37 | 18 |
| 2026-09 | 79 | **21** |
| 2026-10 | **113** | 8 |
| 2026-11（半月） | **100** | 7 |

开发强度持续上升（377 commits，10 月峰值 113），外部关注度从 9 月峰值单调衰减，真实使用证据始终趋近于零。同时：56 个插件里 31 个只有单点验证、6 个零产出、8 类「企业级能力」从未盲测、30.7% UNKNOWN 未归因。

**结论：继续扩功能 / 扩框架 / 加插件数量，边际可信度是负的。** 每新增一个能力，都在扩大「有代码但没验证」的面积，同时抬高口径同步成本（§4.3#3 已经造成过真实构建失败）。这不是「还差一点就成功」，是方向本身该换。

---

## 6. v1.7 迭代方向（明确取舍）

### 6.1 主方向：从「能力扩张」转向「可信度闭环」

**只押一件事：把三态判定从「实现」升级为「可度量的方法论」。**

不要选：加框架、加插件、加扫描模式、UI 美化、性能优化、新卖点。这些在当前数据下都不产生新可信度。

### 6.2 优先级清单

#### P0-1　UNKNOWN 归因 + 三态对照实验（v1.7 主线，学术与产品双重收益）

- 给 UNKNOWN 建**子类枚举**：网络不可达 / 端点不存在 / 认证缺失 / 证据不足 / 主动降级 / 版本门跳过，每类可计数、可追溯。
- 对 567 条 UNKNOWN 逐类人工抽样归因，明确「其中多少是被自己降级掉的正确答案」——直接回答 `docs/_plan_v1.6_facts.md:27` 留下的待查项。
- **做三态 vs 二态对照实验**：同一套 GT 靶场，分别以二态（CONFIRMED/SAFE）和三态跑，量化三态在「不显著抬高漏报」的前提下把误报压低多少，给出 UNKNOWN 率与精确率/召回率的权衡曲线（可画 ROC/PR 式对比）。
- 产出**带 GT 的召回率、精确率、F1、UNKNOWN 转化率**，替换对外使用的 `48/54`；把口径明确写进 README（标注适用范围＝自建靶场，不外推生产）。
- 验收标准：能对答辩委员会说清「三态判定相对于二态判定的量化增益」，且数字可一键复跑。

#### P0-2　单一事实源（SSOT）与对外口径收敛

- 版本号、插件数、框架清单收敛到一处派生：扩展 `scripts/export_plugin_list.py --check` 的覆盖范围到 `pyproject.toml` description、`docs/*`、`ROADMAP.md`、`desktop/src/data/mock.ts`、release 脚本、promo 材料。
- 统一三套口径：运行时 56 / 宣传 54 / 源码文件 59，在 README 用一句话解释三者关系（或干脆只留一个对外数字）。
- 把 56 个插件（含 yudao 2 个）纳入盲测重跑基线，修掉 `aggregate.py` 的复现漂移。
- 对外材料补当前版本：外部通稿还停在 v1.2.2，PyPI 描述还写 54。
- 验收标准：新增一个插件 / 发一个新版本，全仓零手工搜数字，CI 自动覆盖所有声明点。

#### P1-1　把真实使用回路建起来

- 桌面端补组件测试层（引入 vitest + React Testing Library，先覆盖「新建任务」路由与 #66 白屏回归）——这是投入产出比最高的一处工程质量补齐。
- 提供**可选、脱敏**的匿名反馈/遥测（扫了多少目标、CONFIRMED/SAFE/UNKNOWN 分布、是否有人工复核结论），让「有没有人真的扫出东西」变成可观测量。
- 找 3–5 个**授权**的真实站或社区试用，产出可引用案例。毕设论文需要「实际应用验证」章节，现在这一章是空的。
- 验收标准：报告里第一次出现非自建靶场的数据，且注明授权范围与脱敏方式。

#### P1-2　架构收敛（为后续迭代降本，不是为好看）

- 拆 `orchestrator._run()`（752 行 / cc≈100）为可单测的阶段函数；把 `lib → main` 的两处反向 import 改为依赖注入或下沉到 `common/`。
- 把散落在 `getattr` 字符串里的插件能力契约（`path_scope` / `anonymous_probe` / `supports_waf_bypass` / `requires_auth`）显式化为一个 Capability 数据类 + 加载期校验，避免「插件声明了、引擎没支持」这类 v1.6 已踩过的回归。
- 输出单轨：CLI 的 288 个 print 逐步收敛到 reporter，让终端 / 报告 / API / 桌面端共用一套文案与字段。
- 验收标准：新增一个 `--mode` 不需要同时读 3 个超长函数；`lib/` 可脱离 CLI 独立单测。

#### P2　能力分级标注，停止堆料

把现有能力按「已验证 / 实验性 / 仅有代码」三级标进 README 和 `--help`：SIEM、分布式、OAST、AI、利用链、passive、crawl 目前都属后两级。`--distributed` 有过「死开关」虚报前科，尤其要标清楚。Shiro 插件要么实现默认密钥爆破 + 回显验证，要么永久保留 recon 定位，不要再挂在 vuln 类里制造「应该能 CONFIRMED」的错觉。

### 6.3 明确不做

| 不做 | 理由 |
|---|---|
| 新增第 6 个框架 / 继续扩插件数量 | 31/56 只有单点验证，扩规模只会稀释可信度；且每扩一次要同步 6+ 处清单 |
| 新增扫描模式 / 企业级集成 | 已有 8 类未验证能力，先补验证再谈新增 |
| 桌面端视觉改版 / 主题迭代 | 唯一真实用户 issue 是功能崩溃，不是外观；零单测是根因 |
| 对外宣传 48/54 或任何「检出率」 | 口径是插件覆盖率且属历史版本，评委/用户一复核就穿 |

### 6.4 毕设视角的特别提醒

《基于三态判定的若依漏洞扫描器设计与实现》这个题目，答辩时最容易被打穿的三个点，正好是本次调研的全部结论：

1. 「三态比二态好在哪？」→ **现在答不出**，因为没有对照实验，只有 30.7% 的 UNKNOWN 和一句「如实标注不凑数」。
2. 「效果怎么验证？」→ 现在只能答「自建靶场 48/54」，而这不是检出率、还不覆盖当前版本、且项目自己在 README 声明不做任何检出率承诺。
3. 「有实际应用吗？」→ 现在只能答「PyPI 有下载」，但 73% 是镜像、外部贡献者 0、真实使用反馈只有一条桌面端白屏 bug。

P0-1 把这三个洞一次补齐。这也是为什么它必须是 v1.7 的唯一主线，而不是「顺手做一下的实验」。

---

## 7. 数据来源与口径说明

| 数据 | 来源 | 注意 |
|---|---|---|
| stars / forks / issues / PR / traffic / releases / contributors | GitHub REST + GraphQL API，2026-11-16 拉取 | traffic 只保留近 14 天；clones 含大量自动化 |
| star 月度曲线 | `stargazers` + `Accept: application/vnd.github.star+json` | 反映首次 star 时间，非累计 |
| 提交节奏 | 本地 `git log`（377 commits，`main` @ `890b7f2`） | 作者别名合并后仍是单人项目 |
| PyPI 下载 | pypistats.org `overall?mirrors=true/false`、`recent`；PyPI JSON API | `python_minor`/`system` 全为 null，不能折算成用户数 |
| 外部口碑 | 中英两轮公开检索 | 命中均为同一篇自投稿转载，无独立测评 |
| 代码规模 / 复杂度 / 依赖图 | 本地 AST 统计，排除 `.venv*`、`node_modules`、`dist*`、`target`、`__pycache__` | 圈复杂度为近似 McCabe（含嵌套函数），偏大；重复代码用 5 行规范化滑窗 |
| 效果与能力证据 | `docs/blind_test_report_*.md`、`docs/_plan_v1.6_*.md`、`data/acceptance_baseline.json`、`.workbuddy/memory/MEMORY.md`、`lab/`、`README.md` | 全部为项目自测或自述 |

**已知限制**：无法获取「下载后是否真的运行过扫描」「扫描结果是否被人工复核」这类数据，因此本报告中的「真实使用」以「存在外部人类用户提交的可复现问题」为最低门槛。这个门槛目前只有 #66 一条。
