# 变更日志

本项目遵循 [语义化版本](https://semver.org/lang/zh-CN/) 规范。

格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)。

## [Unreleased]

### Added
- **桌面端质量门禁**：ESLint `react-hooks/rules-of-hooks` 静态检查（拦截条件 Hook；v1.5.0 白屏同类问题）+ 构建产物 CDP 冒烟（真实点击「新建扫描」并遍历全部导航页，捕获运行时异常）；两项均纳入 CI
- **依赖清单一致性门禁**：`scripts/check_deps.py` 校验 requirements.txt / requirements-dev.txt 与 pyproject.toml 的依赖声明一致（测试专用依赖不得混入必装清单），已接入 CI
- **`EXIT_PARTIAL = 4`**：批量扫描时有目标未扫到时返回，区别于「一个都没扫到」（`EXIT_UNREACHABLE = 3`）

### Fixed
- **批量 + `--ci` 假覆盖（假覆盖级别）**：`run_mode` 的 CI 分支会 `sys.exit()`，而批量对每个目标调 `run_mode` —— 第一个目标命中高危即整批中断，后续目标根本没扫，用户拿到的是「只覆盖 1/N 目标」的报告却以为整批都扫过。改为批量路径禁用单目标 CI 退出码、整批跑完后统一判定（同步与异步两条路径均修）
- **`--serve` 默认监听 0.0.0.0**：安全工具的 Web API 默认暴露整个网段。改为默认 127.0.0.1（与 lab/ 靶场 v1.2.0 的安全收口一致），可用 `RUOYI_SCAN_HOST` 环境变量覆盖（容器/反代场景），对外监听仍可显式 `--host 0.0.0.0`；桌面端本就显式传 127.0.0.1，不受影响
- **批量模式退出码语义缺失**：全部目标不可达时退出码为 0，CI/脚本会误判为「扫描完成」。现与单目标对齐（3 = 一个都没扫到，4 = 扫到但覆盖面不全）；`-f` 不带 `-u/-m/-p/-l` 时也从 0 改为 2（参数错误）
- **依赖清单漂移**：`requirements.txt` 把测试专用的 `requests-mock` 列进「核心依赖（必装）」段，与 pyproject 已注明它只属 `[dev]` 矛盾。改为 requirements.txt 只含核心依赖、其余指向 pip extras；requirements-dev.txt 补齐原先靠 requirements.txt 间接带入的 fastapi/uvicorn/flask

### Changed
- **README**：目录树 `models.py` 位置修正（实为 `common/models.py`）并补齐 `common/` 段；末尾个人宣言移至 `AUTHOR.md`；与 nuclei/xray 对比表补 3 行诚实短板（模板存量 / 跨框架广度 / 社区规模），与「互补而非竞争」定位对齐
- **退出码文档**：统一 0/1/2/3/4 五种语义，修正 `docs/usage.md` 中「3 = 配置错误」的错误表述（配置错误是 2，3 是目标不可达）

## [1.5.2] - 2026-10-28

### Fixed
- **三态纪律（真实生产形态）**：真实 RuoYi 4.7.8 未认证访问是 302→/login（跟随后 200 登录页）而非 401；7 个插件与统一兜底新增「登录墙」识别，SAFE 不再冒充"确认不存在"；真实 4.7.8 栈复测 16 条假 SAFE → 0
- **SAFE 必须带证据**：插件返回空 evidence 的 SAFE 统一降级 UNKNOWN（MinIO/RocketMQ 等中间件探测此前 SAFE 无证据）
- **批量扫描**：按文档承诺为每个目标输出独立报告（`<host_port>_<timestamp>.<ext>`），并跳过 targets.txt 中 `#` 注释；不再出现"多目标只剩一份 report.html"
- **CLI**：`--help` 与 `-h` 等价；无协议目标自动补 `http://`；登录依赖插件不再输出「SAFE + UNKNOWN」两条矛盾结论
- **真实栈靶场**：nginx 反代改用 `$http_host` + Spring forward-headers，修复 Shiro 302 丢端口导致真栈扫描全 UNKNOWN；smoke 验证码探针补 `?type=math`

### Changed
- **README/PyPI**：README 图片改为绝对地址，PyPI 项目页可正常渲染；新增终端与桌面端真实运行截图；文档口径（退出码 / 报告命名 / OCR 安装 / 靶场命令）按实际行为修正

## [1.5.1] - 2026-10-27

### Fixed
- **桌面端**：修复 v1.5.0 点击「新建扫描」必现白屏——`NewScanDialog` 中 `useRef` 位于提前 return 之后，打开弹窗时 Hook 数量变化触发 `React error #310` 并卸载整棵组件树；已将 Hook 移至提前 return 之前。新增顶层 `ErrorBoundary`：渲染异常降级为可读错误页 + 「重新加载」入口，不再整窗白屏
- **CLI**：首次使用体验修复——版本号显示、缺少目标时的报错、结论重复输出、插件显示名
- **CI/验收**：移除已改名插件（`job_invoke_target`）的过期验收基线项，`main` 与 Nightly 门禁恢复全绿（基线 1.0.4）

### Changed
- **依赖维护**：dependabot 升级 GitHub Actions 组、CodeQL Action、桌面 npm 组、Tauri Cargo 组、pip（requests / setuptools / aiohttp / redis / httpx2）

### Notes
- 桌面端白屏复现与回归：WebView2 远程调试实测 v1.5.0 报 `React #310`；修复后同一操作路径弹窗完整渲染、无异常
- 本版为补丁版本，无行为变更；建议所有 v1.5.0 桌面用户立即升级

## [1.5.0] - 2026-10-12

### Added
- **对抗型传输层（Scrapling）**：新增 `--adversarial-transport` 开关与 `[adversarial]` 可选依赖组（`pip install "ruoyi-scan[adversarial]"`）——隐身浏览器解 CF/JS 挑战 + 指纹伪装，作为 WAF 绕过的引擎级兜底；配套 `lib/scrapling_transport.py` 与 `lab/scrapling_poc/` 契约/端到端验证脚本。默认关闭；依赖需另装约 150MB 浏览器二进制，刻意不并入 `all` 组

### Changed
- **API 鉴权 fail-closed（行为变更）**：无效 scope（如 `key:raed`）由静默回退 `admin` 改为最小权限 `read`；非 ASCII `X-API-Key` 由 500 改为 401。使用无效 scope 的部署升级后权限会收紧，请核对密钥配置
- **口令字典扫描级隔离**：`--pass-level` 不再改写进程级 `settings.PASSWORD_DICT`，改为注入本次扫描的 `session.password_dict`（API/批量并发下多任务不再互相覆盖字典）
- **分布式队列可靠性**：出队改为 `BRPOPLPUSH` + 租约时间戳；Worker 崩溃后遗留任务自动重入队（载荷丢失标记 failed），`collect_results` 不再干等超时
- **插件判定系统性收紧**：以否定为判据的弱特征改为强特征与结构化校验；网络异常一律 `UNKNOWN`（三态铁律）
- **工具链**：dependabot 覆盖 `lab/` 与 pip/Actions 分组（codeql 同族防拆分）；Actions 升级 checkout v7 / setup-python v7 / codecov v7.1.1 / codeql v4；`httpx2` 开发依赖恢复；ruff / mypy 锁定版本升级

### Fixed
- **核心**：会话资源统一 `finally` 释放；验证码探测竞态、限速器令牌、软 404 与 favicon 弱命中误判、报告缓存失效、SARIF 指纹跨运行不稳定、PDF 转义、代理池实际生效、插件加载失败可观测、任务订阅原子化、链超时与 fallback 校验、跳过节点判 `UNKNOWN`
- **库**：ai_generator 覆盖保护与规则降级落盘、ci_runner 生成的 workflow 花括号与 GitLab junit 绑定、cve_sync 路径穿越、plugin_repo 全清单签名与私钥 0600、scheduler 恢复隔离与重复定时器、SIEM CEF 转义、waf_bypass 变换与共享会话、web_ui 模板花括号、js_extractor / crawler / matcher / tamper 判定修正
- **插件**：`file_read` / `file_read_download` 改用 `/etc/passwd` 行强判据；jeecgboot（默认口令/文件读取/SSTI/SQL 注入/JMReport）改结构化校验、不确定态返回 `UNKNOWN`；Spring Actuator 与 Spring Boot Admin 结构校验；CORS `*` 降级低危；MinIO / RocketMQ / Swagger / Source / TRACE / Shiro 等判定收紧；无鉴权探测改用独立会话（防认证状态泄漏）；Nacos 链按实际前缀解析；证据凭据打码；CVE 归属修正与硬编码 Cookie 清理
- **API/CLI**：报告下载 task_id 路径校验、WebSocket 订阅竞态与连接生命周期、批量扫描按目标出报告（不再只出第一个）、`--cache-clear-all` 生效、指纹探测阻塞 IO 移出事件循环
- **CI/供应链**：`github.ref_name` 注入点改用 env、nuclei 下载校验和、Pages 部署并发策略、pip 缓存、Dockerfile / .dockerignore 加固（非 root、固定 UID、密钥排除、保留 `lab/server.py`）
- **桌面端**：Tauri CSP 启用与 asset 作用域收窄（移除 `$HOME/**`）、引擎解压/清理与端口释放加固、状态竞态与主题/字体容错、无障碍与图表性能、自定义头像加载失败回退默认形象、版本号统一

### Notes
- 本版合并两条独立的全库评审修复线（10/5-10/6 与 10/11-10/12），合计处理 800+ 条发现（重叠项按更严格实现收敛）
- 验证：合并后全量测试 0 失败（含新增并发字典隔离、分布式租约恢复、验收基线等用例）；靶场回归与检出矩阵门禁通过
- `pypa/gh-action-pypi-publish@release/v1` 与 `skip-existing` 为刻意保留（文件内有注释说明）

## [1.4.3] - 2026-09-19

### Added
- **G4 RuoYi nuclei 模板包 v0.1.0**（`contrib/nuclei-templates/`）：3 个专项模板——默认管理员口令（admin/admin123）、定时任务端点未授权（/monitor/job/edit）、管理 API 未授权（/system/user/list）；全部结构化英文 matcher（状态码 + JSON 业务字段 + 否定式排除），不依赖中文文案；**签名靶场 vuln/safe 双模式实测**（vuln 4 命中 / safe 零误报，nuclei v3.11.1 官方二进制，证据见 `EVIDENCE.md`）；CI 新增 `nuclei-templates` 作业（语法校验 + 双模式功能门），Release 附 zip 发布包

- **G4 供应链信任建设**：新增 OpenSSF Scorecard workflow（每周评分 + SARIF 上传 Code Scanning + 公共徽章）；Release 增加 **SLSA 构建来源证明**（`actions/attest-build-provenance`，消费者可 `gh attestation verify` 独立验证）；RuoYi nuclei 模板包 zip 随 Release 分发（校验和一并覆盖）
- **G4 Awesome-POC 投稿材料（B 渠道，待确认投递）**：`contrib/awesome-poc/` 两篇（后台定时任务 RCE / params[dataScope] SQL 注入），POC 细节源自本项目签名靶场验证过的插件实现；同时记录：`thymeleaf_ssti.py` 的 CVE-2023-38286 归属经 NVD 核查有误（该 CVE 实为 spring-boot-admin MailNotifier 沙箱绕过），后续需修正插件元数据
- **G4 评分提升（首评 3.1 → 目标 5+）**：全部 workflow 补齐显式最小权限（Token-Permissions）；新增 CodeQL 静态分析（SAST，security-extended）；新增 Dependabot（pip + github-actions 周更）；SLSA 验签已 E2E 实证（`gh attestation verify` → SLSA v1 provenance，builder 为本仓库 release.yml）
- **插件误报基线门禁**（`tests/test_fp_baseline.py`）：把「确定不含漏洞」的良性响应喂给全部插件，断言零 CONFIRMED；另设陷阱语料，确需放宽判定的插件必须在 `KNOWN_FALSE_POSITIVES` 登记原因（技术债可见而非隐藏）。动因：实测 51 插件中 5 个（9.8%）对完全正常的 200 页面返回 CONFIRMED，而当时的测试套件对此零告警——仅约 100 处真正调用过 `verify()`
- **软 404 基线**（`lib/soft404.py`）：`Soft404Baseline` 先探测随机不存在路径建立站点基线，catch-all 路由不再把任意路径误判为「文件存在」；`backup_scan` / `source_leak` 已接入
- **检出能力矩阵**（`scripts/verification_matrix.py` → `docs/verification-matrix.md`）：按插件汇总验证级别（L3 真实软件双向验证 / L2 真实响应靶场 / L1 签名靶场 / none），证据自动提取自 lab 文档与测试源码；CI 增量门禁——none 级插件数量不得增加，矩阵文档与脚本输出强制一致
- **新增 CVE 插件**：CVE-2025-46174（重置密码页数据权限绕过，含越权场景判定与对照逻辑）、CVE-2025-70986（selectDeptTree 未授权越权读取组织架构）；均已纳入 `tests/regression_ruoyi.py`
- **目标可用性预检 + 超时熔断 + TLS 策略**：扫描前两级探测（TCP → HTTP），不可达/无响应目标秒级中止并给出可操作提示（exit=3，与 CI 模式 0/1/2 区分）；批量模式逐目标跳过并在汇总中列出；按主机共享的连续超时熔断（黑洞目标 `-p` 模式从 120 秒以上未完成降至 21 秒）；TLS 默认不校验证书（内网自签名为若依部署常态，此前该类目标所有请求降级 UNKNOWN 且无提示），`--verify-tls` 可开启严格校验；验证码 OCR 引擎改为进程级缓存（默认字典 1052 条口令，原先每个口令重建一次模型）
- **多版本矩阵工具**（`lab/version_matrix/`）：多 RuoYi 版本编译构建 + 逐插件检出对拍的本地靶场工具链

### Changed
- **插件输出通道重构**（58 文件）：插件与 core 模块的进度输出从直接 `print()` 改为 `lib.reporter.emit` 单一出口。CLI 模式观感与迁移前完全一致；API / 桌面端 / 测试模式自动静默（原先插件输出直接写进程 stdout 污染服务日志——实测误报基线测试向 stdout 倾倒约 2 MB 文本；静默模式下转 DEBUG 日志，`--debug` 或 `RUOYI_SCAN_DEBUG=1` 可见）。**对以 stdout 解析扫描结果的外部脚本是行为变更**：以库/API 方式调用时插件不再写 stdout
- **CI 门禁收紧**：`tests/` 与 `scripts/` 纳入 ruff lint（原先 1212 个测试完全不受 lint 约束，实测累积 16 处未用导入/顺序漂移）；覆盖率由全仓统一 70% 改为按目录棘轮（core 78 / common 84 / lib 72 / api 85 / plugins 75 / chains 95，取实测值下浮 3 点，防止低覆盖模块躲在平均值后）；`lib/reporter.py`、`lib/soft404.py` 纳入 mypy strict；全部 GitHub Actions 固定到 commit SHA（仅 `dtolnay/rust-toolchain@stable` 与 `pypa/gh-action-pypi-publish@release/v1` 保留浮动并注明理由）；main 分支启用保护（必过状态检查 + 禁强推/删除，管理员直推不受限）
- **目录扫描输出降噪**：目标不可用时同一失败原因只提示一次（原先 696 条路径刷出 541 行），失败原因与数量写入结果 evidence

### Notes
- **上游收录尝试存档（避免重复踩坑）**：nuclei-templates PR #17192 被以 *duplicate + unvalidated* 关闭——理由（原文要点）：① 若依指纹检测已存在于 fingerprinthub；② 定时任务未授权模板实网 0 命中（缺流行度证明）；③ 标 PR:H 但利用需 admin 会话（严重度虚高）；④ matcher 仅中文。**结论**：授权配置类模板不符合上游收录标准，策略转为「自建模板包 + Awesome-POC 等中文社区渠道」；仅当出现 CVE/CNVD 编号的若依漏洞时再考虑上游提交，且须遵守：英文结构 matcher、严重度如实、附实网证明

## [1.4.2] - 2026-09-15

### Fixed
- **指纹误判修复**: 软 404 站点（任意路径返回同页面）导致指纹误判——`core/fingerprint.py` 增加软 404 探测判定，`lab/fp_lab/server.py` 补软 404 签名，假阳测试判定补全
- **CLI 修复**: `-f` 批量模式校验分支补齐 RED/RESET 颜色导入（NameError）
- **CI**: PyPI 发布加 `skip-existing`——tag 重跑幂等，修复 v1.4.1 发布链两次因 `400 File already exists` 标红（产物无损，重复上传被 PyPI 拒绝）；忽略测试运行产物 data/acceptance_report*.json
- **文档版本号同步遗漏**: v1.4.1 发版只同步了 README.md——README_EN / docs/USAGE 停留在 1.4.0，本次全部对齐；CHANGELOG 补录 v1.4.1 段

## [1.4.1] - 2026-09-10

### Added
- **桌面端正式发布**: 桌面端全量入库 + exe 发布链路（PyInstaller 引擎 / Tauri NSIS / CI 单 exe 构建与冒烟）；单 exe 架构——引擎编译期嵌入壳内，免安装双击即用；GitHub Release 新增 desktop 产物（setup.exe + portable exe + desktop checksums）
- **G4 文档站落地**: mkdocs-material + GitHub Pages 自动部署（docs 站 URL 全量小写化重构 + 交叉引用修正）
- 社交预览图（GitHub Social Preview，1280x640）；README 新增桌面端章节 + 6 张界面截图 + 与通用扫描器的差异化对比表

### Fixed
- 桌面端：推送前全量测试修复（卸载残留引擎缓存 + 事件双推去重）；CI 单 exe 冒烟时序竞态（JobObject 挂接诊断 + 轮询等待回收）；三态统计补齐 SAFE / UNKNOWN 维度
- CI：引擎冒烟残留污染 portable 冒烟——双进程清理 + 阶段前置守卫
- 版本号同步（README 项目定位段 + whl 安装示例；README_EN / docs/USAGE 漏同步已在 1.4.2 补齐）

## [1.4.0] - 2026-09-09

### Added
- **G1 CNVD 源 + 离线 CVE 库**: `lib/cve_sync.py` 查询链扩展为 NVD → GHSA → **CNVD（无官方 API，网页抓取 best-effort，反爬静默降级）→ 离线库（内网兜底）**；新增 `data/cve_offline.json` 随包分发（20 条精选组件 CVE，scripts/build_offline_cve.py 从 component_cve_map 自动生成，--merge 保留手工 CNVD 别名）；新增 `--cve-offline <component>` 内网排查命令；**修复 package-data 只分发 *.txt 导致 component_cve_map.json 未随 wheel 发布的 bug**（安装版组件检测 CVE 比对此前空转）
- **G1 深扫爬虫增强**: `lib/auth_surface.py` 爬虫分支升级为 `crawl_with_js_urls` + `JSExtractor`——RuoYi-Vue/Plus 为 SPA，管理 API 路径多藏于 JS 包，纯 HTML 爬取覆盖不足，现从 JS 包提取 API 路径（来源标记 js）并入盘点
- **G5 合规报告模板引擎**: 新增 `lib/report_template.py`——安服公司用自己的 docx 报告模板（公司抬头/Logo/整改声明），扫描后一键出交付物；占位符 `{{target}}/{{scan_date}}/{{total}}/{{high}}` 等标量注入 + `{{vuln_table}}`（定点插入漏洞明细表，低层 XML）+ `{{vuln_details}}`（逐漏洞详述）；`--report-template <path>` 一键启用，`fail_on_unresolved` 模板校验模式
- **G3 AI 闭环 v2**:
  - **生成即验证（差异化核心）**: 新增 `lib/ai_validate.py`——AI 生成插件先在签名靶场跑三态：vuln 模式 CONFIRMED 且 safe 模式不误报才允许入库（pass）；safe 模式误报触发红线直接拒绝入库并删除（fail）；靶场未覆盖该签名的转入 `plugins/_quarantine/` 隔离目录待人工复核（unverified）。`--ai-validate`（无参=生成后自动验证；带路径=对已有插件独立验证）
  - **UNKNOWN 智能降噪**: 新增 `lib/ai_triage.py`——`--ai-triage` 对无法判定结果按插件聚类分流（suspected_waf / network_error / captcha_or_auth / needs_manual_review 固定标签），LLM 可选（无 Key 规则降级）；**三态纪律红线：AI 只能输出分流标签，输出三态判定一律拒绝并降级**，输出必带免责声明
  - **本地模型支持（Ollama）**: 自定义 `RUOYI_AI_BASE_URL`（如 http://127.0.0.1:11434/v1）时无 API Key 也走 LLM 主路径（OpenAI 兼容端点不校验 Key），内网离线场景可用
- **G5 整改复测工作流**: 新增 `lib/remediation.py`——`--remediation <baseline.json>` 复测后与基线对比出**整改验证报告**（CLOSED 已闭环 / OPEN 未整改 / NEW 复测新发现 + 整改完成率 + 结论），复用 D20 指纹对比；JSON + docx 双交付物
- **G5 等保映射报告级章节**: HTML 与 docx 报告新增「合规映射」章节（等保 2.0 条款命中表 + OWASP Top 10 类别命中表，条款以编号呈现便于对照 GB/T 22239-2019 核实）——从附表升级为报告级章节；数据源为 CONFIRMED 结果 compliance 字段的聚合（`ReportBuilder.compliance_summary()`）

## [1.3.0] - 2026-09-08

### Added
- 新增 `ROADMAP.md` 发展路线图（G1-G5 + v2.0 愿景）：检测深度 / 工程债清偿 / AI 闭环 v2 / 生态社区 / 合规交付五大方向，含三条底线、度量仪表盘与落地机制；README 文档表同步入口
- **G1 认证后深度扫描（`--auth-surface`）**: 新增 `lib/auth_surface.py`——登录态接口资产盘点（若依管理端点字典 + /prod-api 前缀变体 + 登录态页面提取 + 可选浅层爬虫）+ 越权矩阵（匿名重放判未授权访问 / 低权重放判垂直越权，三态纪律与全局一致）；`--surface-account` 提供低权账号对比、`--surface-output` 输出资产清单 JSON；双路自动登录（token 型 `/prod-api/auth/login` 优先，回退标准 `/login` 链路）
- **G1 lab 认证区签名靶场**: `lab/server.py` 新增 `/prod-api/auth/login`（按账号发 admin/user 权限 token）+ `/prod-api/system/user/list` + `/prod-api/system/role/list` 垂直越权签名（vuln 低权可读 / safe 403），配套 13 个测试（单测 + 进程内真实 HTTP 集成，vuln/safe 双模式对拍）
- **G1 组件检测扩展 5 → 20**：新增 druid / xxl-job / solr / rabbitmq / elasticsearch / kibana / tomcat / jetty / shenyu / jenkins / eureka / minio / grafana / sentinel / consul 数据驱动探测器（`_COMPONENT_SPECS` 规格表，存在性/版本提取/三态判定与手写探测器纪律一致）；`data/component_cve_map.json` 同步扩充（kibana CVE-2019-7600、grafana CVE-2021-43798、tomcat Ghostcat/PUT、jenkins CVE-2024-23897、shenyu CVE-2021-37580、jetty CVE-2021-34428 等）
- **G1 CVE 双源**：`lib/cve_sync.py` 增加 GHSA（GitHub Advisory Database）回退源——NVD 未收录/不可达时按 CVE 编号查询，`RUOYI_SCAN_GHSA_TOKEN` 环境变量可提速；`CVEInfo` 增加 `source` 字段
- **G1 变体矩阵补全**：`core/ruoyi_versions.py` 新增 `RUOYI_VARIANT_INFO` 变体元数据表（7 变体的鉴权方式 / API 前缀 / 版本指纹来源）与 `get_variant_info` / `get_variant_api_prefixes` 接口；`detect_version` 支持变体感知的指纹来源优先级（向后兼容）

### Fixed
- **G2 Windows 可移植性修复（CI matrix 首跑即暴露）**: `main.py` 未强制 stdout 编码，英文 Windows（cp1252 控制台）下 banner/帮助信息中的中文触发 `UnicodeEncodeError` 使 CLI 直接崩溃退出码 1（中文系统 GBK 碰巧能编所以此前未发现）——新增 `common/console.py` `force_utf8_stdio()`，main.py 与 regression 脚本统一接入（`errors=replace`，任何终端最多乱码显示绝不中断）；补 cp1252 环境回归测试
- **G2 Windows 兼容修复**: `tests/test_report_xlsx.py` 8 处 `load_workbook` 未释放 workbook 句柄（openpyxl 内部循环引用 + close() 非 read_only 模式为 no-op），Linux 上删除打开中的文件无感、Windows 上 TemporaryDirectory 清理必报 WinError 32——断言后统一 `del` + `gc.collect()` 强制释放（5 轮稳定性验证通过）
- **CI lint 转绿**: 修复 ruff format 漂移（10 个文件 docstring 后空行重排）；lint 工具版本固定（ruff==0.16.2 / mypy==2.1.0，CI 与 pyproject dev 依赖同步），杜绝格式化工具版本演进导致的漂移复发
- **Nightly 验收修复**: 靶场容器 `docker run` 补传 `LAB_HOST=0.0.0.0`——v1.2.0 安全收口后靶场默认绑定 127.0.0.1，容器内绑定回环导致 Docker 端口映射不可达，自 8/25 起每晚启动超时；失败自动建 issue 覆盖靶场启动失败场景（旧条件在该场景下永不触发），并显式声明 `issues: write` 权限
- mypy `python_version` 目标 3.8 → 3.10（mypy 2.x 最低支持 3.10，仅影响类型分析，运行时仍支持 3.8+）
- **版本号同步修复**: `config/settings.py` VERSION 停留在 1.2.2（v1.2.3/v1.2.4 发版漏改，banner 显示旧版本号）——本次起 VERSION/pyproject/README/USAGE 四处一并对齐

### Changed
- **G2 mypy 债务清偿四批完成（350 → 0）**: core/ 25 文件全部 strict 清零（函数签名、容器泛型、Optional 注解、`cast` 消除 Any 传播、dataclass 重复字段去重、`http_code` 变量改名消除类型冲突、lib ComponentDetector/OriginIPFinder 公共类补签名）；**CI 软门禁转硬——`mypy core/ --strict` 回归任何类型错误即失败**（棘轮步骤完成使命移除），common/ + core/ 全量 strict 硬门禁就位
- **G2 CI Windows matrix**: unit 作业矩阵增加 `windows-latest`（pytest-timeout Windows 侧自动切 thread 方法），防 GBK 编码 / 路径分隔符回归；Codecov 上传收敛至 ubuntu+py3.11 组合
- **Release 发布门禁**: tag 推送先等待同一提交的 CI 全绿再构建上传（ci.yml 增加 `tags: v*` 触发），防止带病发布
- **G2 mypy 债务清偿第三批（report 系列 3 模块）**: core/ 的 report_xlsx / report / report_docx 共 ~120 个 strict 错误清零（全部渲染函数签名、ReportBuilder/MultiTargetReport 方法注解、缓存字段 Optional、`aggregate` 鸭子类型边界 `cast`、python-docx 未注解方法定向 ignore）；棘轮门禁扩至 **19 个文件**，core/ 整体错误 229 → **106**（三批累计 350 → 106，已还债 70%）
- **G2 mypy 债务清偿第二批（7 模块）**: core/ 的 ruoyi_versions / captcha_solver / auth_chain / storage / chain / session / report_sarif 共 82 个 strict 错误清零（方法签名、Optional/容器注解、OCR 返回值 str 化、`http_code` 变量改名消除与验证码变量的类型冲突）；棘轮门禁列表同步扩列，core/ 整体错误 311 → **229**
- **G2 mypy 债务清偿第一批（9 模块）**: core/ 的 http / waf_features / fingerprint_features / cache / dedup / report_pdf / engine / router / portscan 共 27 个类型错误清零（补函数签名注解、容器泛型参数、`cast` 消除 Any 传播）；CI 新增 mypy 棘轮硬门禁（已清零模块列表回归任何类型错误即失败，只增不减）
- 文档数字对齐实际状态：插件 51 个（ruoyi 18 / spring 14 / common 11 / jeecgboot 8）、测试 51 文件 1000+ 用例、lib 33 模块；`.idea/` 加入 .gitignore；CHANGELOG 版本对比链接补全

## [1.2.4] - 2026-09-07

### Added
- Release 流水线接入 PyPI（OIDC 受信任发布，`pypa/gh-action-pypi-publish`），tag 推送自动双发 GitHub Release + PyPI
- README / README_EN 快速开始改为 `pip install ruoyi-scan` 优先（Release wheel 下载降级为离线方式）

## [1.2.3] - 2026-09-07

### Added
- 扫描结束输出仓库引导（降低点星摩擦）：终端提示 + HTML 报告页脚 Star 链接
- 新增 `--no-cta` 参数与 `RUOYI_SCAN_NO_CTA` 环境变量关闭引导；非终端（管道/CI）自动静默
- 新增 `lib/star_cta.py` 及配套单元测试与调用链集成测试

## [1.2.2] - 2026-08-25

### Fixed

- **字典未随包分发**: wheel 缺少 `data/*.txt`（`data/` 无 `__init__.py` + 未配置 `package-data`），安装版 Druid 爆破/口令字典全部降级为"无法判定"；已将其作为包随 wheel 分发（实测：安装版成功执行 `ruoyi:123456` 弱口令检测）
- **冒烟门禁增强**: 新增字典文件存在性检查（`PASSWORD_DICT` / `RUOYI_DICT`），杜绝该类问题再次发布

## [1.2.1] - 2026-08-25

### Fixed

- **Release 阻断修复（Critical）**: wheel 打包缺失 `common` / `cli` 包，安装后 CLI 无法启动（`ModuleNotFoundError: No module named 'common'`）— v1.1.0 / v1.2.0 安装包均受影响；本版补齐 `pyproject.toml` include 清单并重新发布
- **构建警告清理**: `project.license` 改用 SPDX 表达式（`license = "MIT"`），消除 setuptools 弃用警告

## [1.2.0] - 2026-08-25

### Added

- **P0 版本矩阵**: 新增若依版本兼容性矩阵文档 `docs/version-matrix.md`
- **P0 Cloud 路由**: `core/router.py` 添加 `ruoyi-cloud` → `plugins.ruoyi` 路由映射
- **P0 Cloud 里程碑**: `core/ruoyi_versions.py` 添加 RuoYi-Cloud 版本里程碑和特征路径

- 方向 1-5: README 文档同步 + 依赖规范化 + pyproject.toml 现代打包 + PyPI 发布工作流 + CI 代码质量门禁
- 方向 6: 社区治理文档（CONTRIBUTING / SECURITY / CHANGELOG + Issue/PR 模板）
- **E1-E9 生态与 AI 升级**: 若依 5 变体识别（Vue3 / App / Plus / Cloud-Plus）+ 组件版本检测（fastjson / SpringBoot / Shiro / Nacos / Log4j → CVE 映射）+ nuclei 模板兼容 + 模板仓库分发 + AI POC 生成 + 团队版 API
- **F2 模板仓库上线**: ruoyi-scan-templates 官方分发源 + GitHub API 回退
- **F3 贡献者 SOP**: issue / PR 模板 + README 贡献区块
- **F4 nightly 真实靶场验收**: 基线对拍 + 自动建 issue
- **F5 拓展框架实证**: JeecgBoot 插件包（首个非若依框架）
- **F6/F7 变体与中间件**: RuoYi-Plus 变体专项 + 中间件未授权包
- **文档**: README 演示动图 + 扫描模式速览（-p vs -u）+ 双语 SEO 优化

### Security

- **W1 插件供应链**: 远程安装强制 Ed25519 验签（fail-closed）+ manifest 路径穿越 / zip-slip 防护 + cryptography 硬性依赖
- **W1 签名发布**: manifest 由 CI 自动签名（私钥存 `$RUNNER_TEMP` 用后即删，禁止手工提交）
- **W2 鉴权**: API Key 改为 `hmac.compare_digest` 常量时间比较；禁止 `?api_key=` URL 传输，仅接受 `X-API-Key` 头
- **W2 WebSocket**: `/ws/scan/{task_id}` 增加与 REST 一致的鉴权（无 Key 仅本地；有 Key 走子协议头），修复 BaseHTTPMiddleware 不拦截 WS 的鉴权绕过
- **W2 暴露面**: 带洞靶场（lab / spring / real-spring）默认绑定 127.0.0.1，Docker 内以 `LAB_HOST` 覆盖；Grafana / Prometheus 宿主端口收口 127.0.0.1；靶场启动增加安全横幅提示
- **W2 权限**: 三级权限矩阵 read / scan / admin，权限不足返回 403
- **测试**: 新增 5 个安全回归用例（WS 鉴权 4 + URL 传密钥拒绝 1），完整套件 1185 全绿
- **文档**: 新增 `docs/security_report.md` 最终安全报告，并归档至模板仓库 ruoyi-scan-templates

### Changed

- **F8/F9 Release 规范化**: checksums.txt 供应链完整性 + mypy 债务起步
- **CI 全绿**: ruff lint/format 门禁（27 处修复）+ nightly 心跳超时修复

## [1.1.0] - 2026-08-07

### Added

- **P0 重构**: main.py 从 1426 行拆分为 389 行（CLI）+ cli/runner.py + 6 个子模块
- **CLI 模块化**: 新增 cli/chain_runner.py, passive_runner.py, plugin_runner.py, serve_runner.py, tool_runner.py, dispatcher.py
- **D10-D37**: 27 个深化方向全部完成，累计 887 测试通过
- **D16**: Docker Compose + Prometheus + Grafana 监控栈
- **D18**: 38 个 POC 新增详细修复信息（代码 diff / 升级命令）
- **D24**: 38 个 POC 新增漏洞复现命令（curl / Python PoC）
- **D19**: 4 个扫描模板（quick / deep / compliance / dengbao）
- **D27**: YAML 配置文件支持（CLI 参数覆盖优先级）
- **D23**: 国际化支持（中文/英文报告切换）
- **D25**: 插件 SDK（模板生成 + 验证）
- **D28**: CI/CD 集成（严重性阈值退出 + 流水线模板）
- **D29**: 离线漏洞知识库（HTML Wiki + JSON API）
- **D30**: OAST 带外检测（自建回调服务器 + 6 种 payload 模板）
- **D31**: 业务逻辑漏洞检测（IDOR / 越权 / 参数篡改 / 竞争条件）
- **D32**: CVE 同步（NVD REST API + 24h TTL 缓存 + CWE 合规映射）
- **D33**: SIEM 集成（ECS / CEF / LEEF / JSON 4 格式 + Syslog）
- **D34**: 异步扫描引擎（aiohttp）
- **D35**: Web UI 控制台（FastAPI + WebSocket）
- **D36**: 分布式任务队列（Redis Master-Worker）
- **D37**: 结果缓存（SQLite TTL + WAL 优化）
- **P1 entry_points 注册**: 第三方插件通过 pip install 自动注册
- **P1 --async 接线**: 批量扫描异步引擎（ThreadPoolExecutor + aiohttp）
- **P1 pytest-benchmark**: 性能基准测试框架
- **shiro_rememberme 插件完善**: CVE-2016-4437 完整检测逻辑 + 修复详情 + 复现命令
- **GitHub Release 自动构建**: tag 触发 wheel + sdist 发布
- **英文 README**: README_EN.md 完整翻译
- **API 文档**: docs/api.md + OpenAPI 3.0 规范
- **插件开发教程**: docs/plugin_dev.md
- **用户指南**: docs/usage.md 完整安装配置说明

### Changed

- CLI 参数从 21 个扩展到 80+ 个（15 个功能组）
- 报告格式从 4 种扩展到 7 种（新增 PDF / Word / Excel / SARIF）
- 插件数量从 20 扩展到 38（16 ruoyi + 14 spring + 8 common）
- 仓库迁移至 xiabai2008/ruoyi-scan
- ruff format 全量格式化（185 文件）

### Fixed

- 修复 CLI 子模块循环依赖（lazy import 解决 chain_runner / passive_runner / runner 互引）
- 修复 test_d8_cli.py 导入错误（_parse_report_formats 迁移至 cli/runner）
- 修复 D9 Web API CI 挂起（_DaemonThreadPoolExecutor + atexit os._exit）
- 修复 387 个 ruff lint 错误 + 42 个 ruff format 格式问题
- 修复 CI 中 pytest 缺失、httpx2 依赖、crt.sh 真实网络请求等问题
- 修复 Signature Labs E2E 靶场缺失 11 个插件签名
- 修复验证码接口在 CI 无 OCR 依赖时导致 UNKNOWN 判定
- 修复 shiro_rememberme 插件 TODO 占位符未填写导致测试失败

## [1.0.0] - 2026-07-16

### Added

- 首次发布
- 20 个 POC 插件（若依 + Spring 专项）
- 三态判定引擎（CONFIRMED / SAFE / UNKNOWN）
- WAF 绕过（11 种策略）
- 漏洞利用链（DAG 拓扑编排）
- 多格式报告（HTML / JSON / CSV）
- 批量扫描与汇总
- 签名靶场（Flask lab）
- 887 单元测试 + 回归测试

[Unreleased]: https://github.com/xiabai2008/Ruoyi-Scan/compare/v1.4.2...HEAD
[1.4.2]: https://github.com/xiabai2008/Ruoyi-Scan/compare/v1.4.1...v1.4.2
[1.4.1]: https://github.com/xiabai2008/Ruoyi-Scan/compare/v1.4.0...v1.4.1
[1.4.0]: https://github.com/xiabai2008/Ruoyi-Scan/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/xiabai2008/Ruoyi-Scan/compare/v1.2.4...v1.3.0
[1.2.4]: https://github.com/xiabai2008/Ruoyi-Scan/compare/v1.2.3...v1.2.4
[1.2.3]: https://github.com/xiabai2008/Ruoyi-Scan/compare/v1.2.2...v1.2.3
[1.2.2]: https://github.com/xiabai2008/Ruoyi-Scan/compare/v1.2.1...v1.2.2
[1.2.1]: https://github.com/xiabai2008/Ruoyi-Scan/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/xiabai2008/Ruoyi-Scan/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/xiabai2008/Ruoyi-Scan/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/xiabai2008/Ruoyi-Scan/releases/tag/v1.0.0
