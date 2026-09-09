# Ruoyi-Scan 发展路线图

> **定位**：守住「若依专项 + 三态判定」护城河，纵向做深检测能力，横向把方法论复制到
> 国产 Java 框架生态，以合规交付与 AI 闭环建立差异化——成为**国产 Java 管理框架专项扫描的事实标准**。
>
> 命名延续项目系列惯例（P → D → E → F → W → **G**）。本文档随版本演进滚动更新，
> 各阶段开工时拆解为带标签的 issue / milestone 跟踪。

---

## 总览

| 阶段 | 主题 | 目标版本 | 时间窗 | 状态 |
|------|------|---------|--------|------|
| G1 | 检测深度：存量生态深耕 | v1.3 | 2026 Q4 | 规划中 |
| G2 | 工程债清偿：为规模化铺路 | v1.3 - v1.4 | 2026 Q4 - 2027 Q1 | 规划中 |
| G3 | AI 闭环 v2：生成即验证 | v1.4 | 2027 Q1 | 规划中 |
| G4 | 生态与社区：26 → 500 star | 持续 | — | 进行中 |
| G5 | 合规交付市场：安服差异化 | v1.5 | 2027 H1 | 规划中 |
| 愿景 | 国产 Java 框架专项扫描标准 | v2.0 | 2027 H2+ | 远期 |

---

## 三条底线（任何版本不破）

1. **三态判定纪律** — UNKNOWN 永不冒充 SAFE，网络异常绝不判 SAFE。这是区别于
   「结果全红」扫描器的信任根基，也是报告可信度的来源。
2. **存在性验证** — 只做漏洞存在性确认，不做破坏性利用；工具仅用于授权目标。
3. **不做通用扫描器** — 不与 nuclei / xray 正面竞争；深耕细分专项，并反哺 nuclei 生态。

---

## G1 · 检测深度（v1.3）

核心价值层，优先级最高。每个新检测面配套 lab 模式并纳入 nightly acceptance 基线。

| 方向 | 现状 | 目标 |
|------|------|------|
| 认证后深度扫描 | ~~插件以未授权检测为主~~ **已落地（`lib/auth_surface.py`，`--auth-surface`）**：登录态资产盘点 + 越权矩阵 + lab 认证区签名靶场；**爬虫/JS 端点提取已接入（`crawl_with_js_urls` + JSExtractor）** | 深化：水平越权（IDOR）与盘点联动、微服务 API 资产图谱 |
| 组件版本检测 | ~~5 个组件~~ **20 个组件（G1 已落地，`lib/component_detect.py`）** | 扩展至 30+ 并补 SnakeYAML 等库级组件；从报错页 / actuator / favicon 提取版本特征 |
| CVE 数据源 | ~~仅 NVD~~ **NVD + GHSA + CNVD（best-effort）+ 离线库四源（已落地，`lib/cve_sync.py`）** | CNNVD 源评估；离线库 CNVD 别名人工扩充 |
| 若依变体矩阵 | `core/ruoyi_versions.py` 覆盖 4.2 / 4.7 / v5 / 3.9 / Cloud 里程碑 | 补全 RuoYi-Vue-Plus、RuoYi-App、小程序端点的路由差异与 POC 过滤 |
| nuclei 兼容升级 | http 协议子集 + 安全白名单（`lib/nuclei_loader.py`） | 扩展协议子集覆盖；向 nuclei-templates 上游贡献若依专项模板（借生态流量） |

**验收标准**：新增检测面均有签名靶场覆盖；nightly acceptance 基线文件更新；
版本矩阵文档 `docs/version-matrix.md` 同步。

---

## G2 · 工程债清偿（v1.3 - v1.4）

为规模化铺路，与 G1 并行不阻塞：

- **mypy 债务**：`core/` 350 错误（当前软门禁 `|| true`）按模块分批清零后转硬门禁；
  `lib/`、`api/` 结束 `ignore_errors`，逐步收紧
- ~~**CI Windows matrix**~~ **已落地（G2）**：unit 作业矩阵已含 `windows-latest`（pytest-timeout Windows 侧切 thread 方法）
- **Python 基线评估提升至 3.10**：3.8 已 EOL 两年，mypy 2.x 已弃支持；以 PyPI
  安装量数据决策，`pyproject.toml` classifiers 同步
- **引擎统一**：ThreadPool + aiohttp 双轨收敛为统一异步内核，保留同步插件 API
  兼容层，插件作者无感迁移
- **大规模批量基线**：基于现有 pytest-benchmark 建立 10k 目标吞吐 / 内存基线；
  批量报告聚合分页

---

## G3 · AI 闭环 v2（v1.4）

`lib/ai_generator.py`（生成）与 `lib/ai_report.py`（解读）是起点，下一步是**闭环与纪律**：

- **生成即验证**：AI 生成的 POC 必须先在签名靶场跑出预期三态才允许入库——
  lab 体系天然是验证器，这是多数「AI 生成 POC」项目不具备的差异化
- **LLM 降噪 UNKNOWN**：UNKNOWN 案例证据聚类 + LLM 辅助归类；AI 结论仅标记
  「建议复核」，**不得改写三态**——纪律优先
- **本地模型支持**：Ollama / OpenAI 兼容 endpoint——内网渗透测试是离线场景，需求真实
- **攻击面优先级排序**：报告修复优先级升级为资产上下文感知（组件暴露面 × 业务入口）

---

## G4 · 生态与社区（持续）

目标：26 → 500 star，从「个人项目」到「有外部贡献者的社区项目」。

- **文档站**：mkdocs-material + GitHub Pages——现有 `docs/*.md` 分散无导航，
  这是贡献者体验的第一道门槛
- **借力上游生态**：向 nuclei-templates 提若依专项模板 PR、向 Wappalyzer / EHole
  提若依指纹——`lib/nuclei_loader.py` 兼容层已证明技术同源
- **POC 征集 + good first issue**：Ed25519 签名分发闭环（`--plugin-update`）已建好，
  缺的是让第一批外部贡献者进来的钩子；参与 Hacktoberfest 等活动
- **信任建设**：OpenSSF Scorecard、可复现构建 + SLSA provenance
  （已有 checksums + Ed25519，补齐供应链最后一环）
- **集成触点**：Burp 被动扫描联动（`core/proxy_server.py` 已有被动代理）、
  DefectDojo 导入、钉钉 / 企微 / 飞书通知（`lib/notifier.py` 已有骨架）

---

## G5 · 合规交付市场（v1.5）

商业价值最高、竞争最少的差异化方向——现有 7 种报告格式 + 等保模板（`dengbao`）+
baseline diff 离真实痛点只差一步：

- ~~**安服报告模板引擎**~~ **已落地（`lib/report_template.py`，`--report-template`）**：docx 模板占位符注入
  （标量 + `{{vuln_table}}` 定点插表 + `{{vuln_details}}` 详述），安服公司套用自己的模板一键出交付物
- **整改复测工作流**：`--diff` 升级为「整改验证报告」——复测是安服第二高频交付物
- **等保 2.0 / 关基映射深化**：CWE → OWASP / 等保映射从附表升级为报告级章节
- **整改复测工作流**：`--diff` 升级为「整改验证报告」——复测是安服第二高频交付物
- **等保 2.0 / 关基映射深化**：CWE → OWASP / 等保映射从附表升级为报告级章节

---

## v2.0 愿景（2027 H2+）

定位从「若依专项」升级为「**国产 Java 管理框架专项扫描标准**」：

- 框架矩阵：若依系 + JeecgBoot（F5 已实证基建通用性）+ 芋道 yudao +
  SpringBlade + Pig / Guns
- 插件市场 2.0：评分 / 订阅 / 更新策略（Ed25519 签名分发之上）
- Open Core 边界设计：明确团队版功能哪些闭源，保持核心检测能力开源

---

## 明确不做的事

- ❌ 通用 Web 漏洞扫描器——打不过 nuclei，也没必要
- ❌ 破坏性利用、未授权目标的自动化攻击
- ❌ 自建大而全指纹库——借力 Wappalyzer / nuclei 生态，只维护若依系纵深指纹

---

## 度量仪表盘

| 指标 | 基线（2026-09） | 目标 |
|------|----------------|------|
| 检测插件数 | 51（ruoyi 18 / spring 14 / common 11 / jeecgboot 8） | 100+ |
| 组件 CVE 覆盖 | 20 组件 / NVD+GHSA 双源 | 30+ 组件 / CNVD 源 |
| nightly 误报 / 漏报率 | acceptance 基线对拍 | 持续 ≤ 0（回归即阻断） |
| 外部贡献者数 | 0 | 5+ |
| GitHub star | 26 | 500 |
| 测试用例 | 1023 | 随功能同步增长，覆盖率 ≥ 70% 红线 |

---

## 落地机制

- 每阶段开工时拆解为 GitHub issue，打标签：`g1` … `g5` / `roadmap` /
  `good first issue`，按版本挂 milestone
- 单项完成的定义（DoD）：代码 + 测试 + 签名靶场覆盖（涉及检测面时）+ 文档 +
  CHANGELOG 记录
- 路线图本身接受社区提案：开 issue 讨论后修订本文档
