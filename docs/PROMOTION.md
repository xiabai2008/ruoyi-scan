# Ruoyi-Scan 多平台推广文案

> 目的：触发 star 增长，冲击 GitHub Trending。
> 核心素材：README 演示动图（`assets/demo-scan.gif`）、GitHub 仓库（https://github.com/xiabai2008/ruoyi-scan）。

---

## 0. 通用素材（所有平台复用）

### 一句话定位

> 若依（RuoYi）专项漏洞扫描器：53 个检测插件、5 变体识别、三态判定、WAF 绕过、AI 生成 POC、nuclei 模板兼容，并提供**单文件桌面端**（双击即用，无需 Python / Docker）。专为国内使用最广的开源 Java 后台框架打造的扫描工具。

### 核心卖点数据

- **垂直定位**：若依是国内应用最广的开源 Java 后台框架（政企系统 / 外包项目 / 毕业设计大量二次开发），但此前没有专项扫描器
- **53 个检测插件**：若依 20（含 2 个 Plus 变体专属）/ Spring Boot 14 / 通用 11 / JeecgBoot 8（首个非若依框架拓展实证）
- **5 变体识别**（Vue3 / App / Plus / Cloud-Plus），变体感知路由，避免跨变体误报
- **三态判定** CONFIRMED / SAFE / UNKNOWN，显著降低误报
- **桌面端单 exe**：引擎 + 53 个 POC + Web 控制台**编译期嵌入同一文件**，双击即用（Tauri），对没有开发环境的机器最省事
- **AI 生成 POC**：自然语言生成插件，LLM 自验证回灌后才入库
- **nuclei 模板兼容**：直接运行 nuclei-templates YAML（http 协议子集 + 安全白名单）
- **WAF 绕过** 11 种策略 + **漏洞利用链**（DAG 编排，3 条内置链）
- **Web API** + WebSocket 实时推送 + Web 控制台 + 权限分级（read/scan/admin）+ 定时扫描
- **多格式报告**：HTML / JSON / CSV / PDF / Word / Excel / SARIF
- **检出能力矩阵**：每个插件的验证级别（L1 签名靶场 / L2 真实响应 / L3 真实软件双向验证）对外公开可查
- **供应链加固**：SLSA 构建来源证明 + 插件 Ed25519 强制验签 + OpenSSF Scorecard
- **三种用法**：`pip install ruoyi-scan`（PyPI）/ 单文件 exe / Docker 一键部署，均内置签名靶场（仅本地绑定）
- **在线文档站**：https://xiabai2008.github.io/ruoyi-scan/（mkdocs-material 全量文档）
- MIT 开源，v1.4.3

### 通用 CTA（结尾模板）

> 项目地址：https://github.com/xiabai2008/ruoyi-scan
> 演示动图见 README。觉得有用的话点个 ⭐，欢迎提交 POC 与改进。

### 发布纪律

1. **合规红线**：所有文案强调"仅限授权测试"，内置靶场用于验证，杜绝未授权使用
2. **避免绝对化**：不用"最强大 / 第一 / 唯一"等表述（FreeBuf / 先知审核尤其敏感）
3. **统一口径**：仓库名 `ruoyi-scan`，地址 https://github.com/xiabai2008/ruoyi-scan
4. **动图先行**：每条文案都带 README 演示动图或截图，视觉是转化关键
5. **节奏**：中文社区同日或隔日发（FreeBuf / 先知 / 掘金 / V2EX）；HN 单独挑好时段；国际平台隔 1–2 天

---

## 一、FreeBuf（投稿 / 专栏）

**平台特点**：国内安全媒体，偏专业向，审核严格，重视技术深度与合规性。走投稿流程，禁止硬广。

### 标题（三选一）

1. 《若依框架的"隐形风险"：为什么通用扫描器扫不出你的若依系统？》
2. 《专项化扫描实践：面向若依（RuoYi）的漏洞检测工具设计与实现》
3. 《当通用扫描器失效时：若依专项漏洞扫描器的插件化与三态判定》

### 正文（约 900 字）

**开头·痛点**

若依是国内应用最广的开源 Java 后台框架之一，大量政企系统、外包项目乃至毕业设计都基于它二次开发。然而通用扫描器对若依的覆盖往往停留在"能扫到 Shiro / Spring"的层面，缺少对若依专有攻击面的深入检测：特定路径的信息泄露、各版本的差异化漏洞、二次开发引入的未授权接口等。若依及其变体（Vue3 / App / Plus / Cloud-Plus）指纹差异大，通用工具误报率偏高，安全测试人员需要大量人工复核。

**方案·设计**

Ruoyi-Scan 采用插件化架构与三态判定（CONFIRMED / SAFE / UNKNOWN），专为若依生态设计：

- **插件系统**：`PluginBase` 抽象基类 + `entry_points` 注册，新增 POC 即插即用
- **指纹识别**：favicon hash + 特征路径 + 关键字，多数据驱动并对若依变体细分
- **三态判定**：确认存在 / 确认不存在 / 无法判定，从机制上降低误报
- **53 个检测插件**：若依 20（含 2 个 Plus 变体专属）+ Spring Boot 14 + 通用 11 + JeecgBoot 8
- **WAF 绕过**（11 种策略）与 **漏洞利用链**（DAG 拓扑编排）
- **AI 生成 POC**：用自然语言描述漏洞，LLM 生成插件并自验证回灌，降低 POC 编写门槛
- **nuclei 模板兼容**：直接复用 nuclei-templates 生态（http 协议子集 + 安全白名单）
- **Web API**：REST + WebSocket 实时推送 + Web 控制台 + 权限分级 + 定时扫描
- **交付形态完整**：单文件桌面端（双击即用，无需 Python/Docker）+ PyPI + Docker 三种用法

**合规与安全边界**

工具仅用于授权范围内的安全测试与学习研究。内置签名靶场默认仅绑定 127.0.0.1，启动时展示安全警告横幅，杜绝被部署到公网或未授权网络。涉及利用的插件默认仅做存在性验证，不做实际破坏。

**结尾**

项目开源（MIT），已在 GitHub 发布并附带完整演示动图。欢迎安全从业者试用、提交 POC 与改进建议。

### 发布注意

- FreeBuf 投稿需注册账号走投稿流程，署名：XIABAI
- 文中所有漏洞检测需附"仅在授权环境/内置靶场验证"说明
- 可配 1–2 张报告截图（风险分布、漏洞列表）

---

## 二、先知社区（阿里云先知）

**平台特点**：偏实战漏洞研究，受众为渗透测试工程师与白帽，重视技术干货与可复现性。

### 标题（三选一）

1. 《若依专项扫描：从指纹识别到 AI 生成 POC 的完整实现》
2. 《Ruoyi-Scan：面向若依生态的插件化扫描器》
3. 《如何系统性地检测若依框架的已知与未知漏洞》

### 正文要点（技术向）

- **背景**：若依生态的共性攻击面梳理（路径泄露、SQL 注入、RCE、SSTI、未授权等 16 类）
- **指纹识别**：favicon hash + 特征路径 + 若依变体细分，如何做到"扫得准"
- **插件架构**：`PluginBase` / 三态判定 / `--plugin-init` / `--plugin-check`，附最小插件代码示例
- **三态判定实现**：CONFIRMED / SAFE / UNKNOWN 的判定逻辑，如何控制误报
- **AI 生成 POC**：自然语言 → 插件模板 → LLM 自验证回灌流程，附一条实际命令
- **nuclei 兼容**：http 协议子集 + 安全白名单的实现取舍
- **靶场复现**：内置签名靶场（lab-ruoyi / lab-spring）一键启动，附验证命令与报告

### 结尾 CTA

> 仓库：https://github.com/xiabai2008/ruoyi-scan（MIT）。欢迎测试、反馈与 POC 贡献。

### 发布注意

- 代码示例要能直接复制运行，注明依赖（Python 3.8+ / pip install -r requirements.txt）
- 强调所有 POC 均在自建靶场验证，附靶场安全提示

---

## 三、Hacker News（Show HN）

**平台特点**：英文、极客向、反感营销，重视真实性与技术细节。标题格式 `Show HN: 工具名 — 一句话亮点`。

### 标题（二选一）

1. `Show HN: Ruoyi-Scan – a specialized vulnerability scanner for the RuoYi Java admin framework`
2. `Show HN: I built a niche scanner for China's most popular Java admin framework (RuoYi)`

### 正文（英文，直接、克制）

```
Show HN: Ruoyi-Scan – specialized vulnerability scanner for RuoYi

RuoYi is one of the most widely used open-source Java admin frameworks in
China — tons of enterprise, outsourcing, and even student projects are built
on it. It had no dedicated scanning tool, so I built one.

Highlights:
- Plugin architecture with a three-state verdict (CONFIRMED / SAFE / UNKNOWN)
  to keep false positives down
- 53 detection plugins: 20 RuoYi (incl. 2 Plus-only) + 14 Spring Boot
  + 11 generic + 8 JeecgBoot, with fingerprint detection for 5 RuoYi variants
  (Vue3 / App / Plus / Cloud-Plus)
- A single-file desktop app (Tauri) — engine + all plugins + web console are
  embedded at compile time, so it runs with no Python/Docker install
- WAF bypass (11 strategies) and exploit chains (DAG orchestration)
- Generate POCs from plain-language descriptions; LLM-generated plugins are
  self-verified before being saved
- Runs nuclei-templates YAML directly (http protocol subset, safety allowlist)
- Web API + WebSocket live push + web console (read/scan/admin roles),
  scheduled scans, SARIF/PDF/Word/Excel reports
- A published verification matrix showing, per plugin, how it was validated
  (signature lab / real-response lab / real software with patch rollback)
- SLSA build provenance + Ed25519-signed plugin distribution
- Ships with a signed vulnerable lab bound to localhost for safe verification

Demo GIF and quick start in the README:
https://github.com/xiabai2008/ruoyi-scan

MIT licensed. Feedback and POC contributions are welcome.
```

### HN 注意事项（重要）

- 只能提交一次，不要在标题/正文求 star（HN 反感）
- 发布后 1–2 小时是黄金窗口，需持续在线回复评论
- 避免营销词（best / first / awesome）
- 建议先确认英文 README（README_EN.md）完整，外链体验流畅
- 挑美东工作日早 9 点（≈ 北京晚 9 点）发布

---

## 四、V2EX（分享创造）

**平台特点**：中文程序员社区，实用主义，反感硬广，喜欢真实体验与快速上手。

### 标题（二选一）

1. 《分享创造：我给若依框架写了个专项漏洞扫描器，支持 AI 生成 POC》
2. 《若依后台系统太多人用了，我做了个专项扫描器开源了》

### 正文（口语化、真实）

```
若依（RuoYi）应该是国内用得最多的开源 Java 后台框架之一，政企、外包、毕设到处都是。
但一直没有一个专门给它做的扫描器，通用工具扫出来误报一堆，人工复核很痛苦。
所以我自己写了一个，开源了。

几个我觉得值得说的点：
- 三态判定（确认存在 / 确认不存在 / 无法判定），误报率低很多
- 53 个插件：若依 20 + Spring 14 + 通用 11 + JeecgBoot 8，5 变体识别（Vue3/App/Plus/Cloud-Plus）
- 有单文件 exe 桌面端，双击就能用，不用装 Python 和 Docker
- 用自然语言描述漏洞，AI 直接生成 POC（会自验证再入库）
- 能直接跑 nuclei 模板，社区生态白嫖
- 自带 Web 控制台 + API + 定时扫描，还能出 PDF/Word/Excel 报告
- 每个插件的验证级别（靶场/真实响应/真实软件回退验证）都公开可查，不是嘴说
- Docker 一键部署，内置签名靶场本地验证，安全边界做足了

快速上手（三选一）：
  pip install ruoyi-scan && ruoyi-scan -u http://target:8080/   # PyPI
  下载 Releases 里的单文件 exe，双击                          # 桌面端
  docker compose up -d                                        # Docker

演示动图在 README 里：https://github.com/xiabai2008/ruoyi-scan
觉得有用给个 star，有问题评论区聊。只做授权测试用，别拿去乱扫哈。
```

### 发布注意

- V2EX 可在正文附图（动图/截图），标题加「分享创造」前缀符合惯例
- 避免贴太多参数表，突出"我能直接上手用"

---

## 五、掘金（中文技术博客）

**平台特点**：中文开发者社区，教程向，中等技术深度，注重排版与可读性。

### 标题（二选一）

1. 《若依专项漏洞扫描器：从插件化架构到 AI 生成 POC》
2. 《手把手：用 Ruoyi-Scan 检测你的若依系统》

### 正文结构（教程式）

1. 引言：若依的普及度与安全检测痛点
2. 快速开始：安装（whl / 源码 / Docker 三种方式）+ 三条常用命令
3. 核心特性逐条讲：三态判定、指纹识别、WAF 绕过、利用链、AI POC、nuclei 兼容
4. 架构图解：入口 `main.py` → 编排器 → 插件系统 → 报告输出
5. 实战演示：内置靶场一键扫描，贴报告截图
6. 合规说明 + 结尾 CTA

### 发布注意

- 掘金适合放较多代码块与截图，排版用 Markdown 规范
- 可标注"参与征文/专题"提高曝光（视平台当期活动而定）

---

## 六、X / Twitter（国际）

**平台特点**：短文案 + 视觉，2–3 条推文组成发布序列。

### 推文 1（发布当天）

```
RuoYi is everywhere in China — enterprise, outsourcing, even student projects
— but it had no dedicated scanner. So I built one:
53 plugins, 3-state verdict (no more false-positive floods), WAF bypass,
exploit chains, AI-generated POCs, nuclei-template compatibility — and a
single-file desktop app so you don't need Python or Docker.
https://github.com/xiabai2008/ruoyi-scan
```

### 推文 2（间隔 2–4 小时，配动图）

```
It runs nuclei YAML templates directly, and you can describe a vulnerability
in plain language to generate a POC (self-verified before saving).
Full demo: → GIF 附件/README
#RuoYi #infosec #opensource #python #AI #pentest
```

### 推文 3（次日，互动向）

```
What should a framework-specific scanner do differently from a general one?
I built Ruoyi-Scan around three-state verdicts and variant-aware fingerprinting.
Feedback & POC contributions welcome — MIT licensed.
https://github.com/xiabai2008/ruoyi-scan
```

### 发布注意

- 推文 2 可把演示 GIF 转成短视频或直接挂动图
- 用话题标签扩大曝光，但不堆砌（3–5 个足够）

---

## 七、Reddit（r/netsec / r/selfhosted）

**平台特点**：英文，r/netsec 对工具帖要求实质技术内容，禁止纯推广；先阅读版规。

### 标题（二选一）

1. `I built a specialized vulnerability scanner for RuoYi, the most popular Chinese Java admin framework`
2. `[Tool] Ruoyi-Scan – dedicated scanner for a framework behind thousands of Chinese enterprise systems`

### 正文（英文，强调技术实质）

```
I built a niche scanner for RuoYi, an open-source Java admin framework that
powers a huge share of Chinese enterprise/outsourcing systems but had no
dedicated security tool.

What makes it different from a generic scanner:
- Three-state verdict (CONFIRMED / SAFE / UNKNOWN) instead of binary hit/miss,
  which keeps false positives manageable at scale
- 53 detection plugins (20 RuoYi, 14 Spring Boot, 11 generic, 8 JeecgBoot)
- Variant-aware fingerprinting (Vue3 / App / Plus / Cloud-Plus) so plugins
  only run against matching targets
- AI-assisted POC authoring: describe the vuln in natural language, get a
  plugin, and it's self-verified before it's saved
- Runs nuclei-templates YAML directly (http subset + safety allowlist)
- Web API + WebSocket live push + console with read/scan/admin roles
- A single-file desktop build (engine embedded at compile time), plus a
  published per-plugin verification matrix instead of a bare plugin count
- SLSA build provenance and Ed25519-signed plugin distribution

It ships with a signed vulnerable lab (localhost-only) so everything can be
verified safely before any real engagement.

Repo (MIT): https://github.com/xiabai2008/ruoyi-scan
Demo GIF in the README. Happy to discuss the architecture.
```

### 发布注意

- r/netsec 可发但必须配合实质性讨论，发布后及时回复技术问题
- 部分子版块要求 10 天等待期（先有账号活跃度再发），提前规划

---

## 八、仓库侧配合动作（引流配套）

| 动作 | 说明 | 状态 |
|------|------|------|
| Topics 标签 | 已配置 20 个（ai / nuclei / ruoyi / cve / cnvd / waf-bypass 等） | ✅ 完成 |
| README 演示动图 | `assets/demo-scan.gif` + 命令行真实运行截图 | ✅ 完成 |
| 英文 README | `README_EN.md` 已存在（HN/Reddit 访客入口） | ✅ 完成 |
| Release 发布 | 已发布至 v1.4.3，含 whl 资产、校验和与更新日志 | ✅ 完成 |
| PyPI 发布 | `pip install ruoyi-scan`（OIDC 受信任发布，无需手动上传） | ✅ 完成 |
| 桌面端单 exe | Releases 附单文件 exe，双击即用（无需 Python/Docker） | ✅ 完成 |
| 在线文档站 | https://xiabai2008.github.io/ruoyi-scan/（mkdocs-material） | ✅ 完成 |
| 检出能力矩阵 | `docs/verification-matrix.md` 逐插件公开验证级别 | ✅ 完成 |
| 供应链证明 | SLSA 构建来源证明 + OpenSSF Scorecard + Ed25519 插件验签 | ✅ 完成 |
| 徽章完备 | CI / Python / License / Coverage / PyPI 已有 | ✅ 完成 |
| 仓库描述 | 已含关键词（插件化 / 三态判定 / AI POC / nuclei / 53 插件） | ✅ 完成 |
| 投稿材料 | `contrib/awesome-poc`（Awesome-POC 投稿） | ✅ 完成 |

### 建议发布节奏（示例）

1. **Day 1 上午**：FreeBuf 投稿 + 掘金教程（国内技术圈）
2. **Day 1 晚间**：V2EX 分享创造（程序员圈扩散）
3. **Day 2**：先知社区（实战圈） + X 推文序列
4. **Day 3**：HN（Show HN）+ Reddit（挑工作日晚间时段）
5. **持续**：回复所有评论，收集反馈迭代；star 增长集中在发布后 48–72 小时
