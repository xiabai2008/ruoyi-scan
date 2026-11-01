# v1.5.5 计划：从「少误报」到「真检出」（盲测 v3 能力建设）

- 制定：2026-11-02（承接 2026-11-01 会话的最终目标：以下一版发布为终点，自主决策）
- 前置：v1.5.4 已发布（盲测 v2 的 2 个 P0 误报/漏扫缺陷修复）
- 本版目标：**提升「该报的能报」**——盲测 v2 已证明误报控制变强，但检出插件数 23/54 未变

---

## 一、量化现状（盲测 v2，62 份扫描报告聚合）

54 个插件里，**25 个在整个盲测 v2 中一次 CONFIRMED 都没有**：

| 分类 | 插件 | 说明 |
|---|---|---|
| **JeecgBoot（8/8）** | 默认口令、字典越权、任意文件读取、jmreport 文件上传、报表 SSTI、报表未授权、jmreport SQL 注入、queryUserByDepId SQL 注入 | R10 是负样本站，8 个插件全部无靶可打 |
| **Spring（5/14）** | actuator env RCE、CVE-2022-22963 SCF、CVE-2022-22947 Gateway、Spring4Shell、/trace 泄露 | C2 矩阵未覆盖这些端点；Spring4Shell 无 --exploit 诚实 UNKNOWN |
| **RuoYi（7/20）** | 任意文件读取 ×2、定时任务 RCE（未授权）、RuoYi-Plus 定时任务、RuoYi-Cloud Nacos 配置泄露、Nacos 未授权、代码生成 SSTI | 部分需鉴权/需 R8 独占；R1 的 /docs 属设计边界不算 |
| **通用（5/12）** | Redis 未授权（R8 未跑）、Shiro 指纹（设计上不 CONFIRMED）、备份文件泄露（仅命中 R1 设计边界）、HTTP 方法探测/目录扫描（recon 类） | 排除设计上不产 CONFIRMED 的项 |

> 注：recon 类（目录扫描/HTTP 方法探测）与 Shiro 指纹不计入「检出能力」KPI。

## 二、工作包（按 ROI 排序，可并行）

> **执行状态（2026-11-02 第 1 轮）**：WP1 ✅ 完成（真实 R10，8/8 CONFIRMED，lab commit de58a37）；
> WP2 ✅ 完成（R6/R7/R9 登录 exit 0，ruoyi-scan 3c27e31）；
> WP3 ✅ 完成（scanner fee7580；C2-1b 真实 Gateway 3.1.0 + SBA client 上 env RCE / Gateway RCE / trace 全部 CONFIRMED，
> C2-3 降到 3.2.2 后 SCF 时序差分 CONFIRMED，C2-2 --exploit Spring4Shell CONFIRMED；三站 safe 模式 0 CONFIRMED）；
> WP4 🔶 部分（R2 任意文件上传已通：runtime profile 改绝对路径，待收口进 launch.py；
> dataScope 注入在 R2(4.6.2) 已修复、判 SAFE 正确；文件读取受 Windows 靶场限制）；
> WP5/WP6 未开始。

**本轮新增扫描器能力（均已 push，CI 绿）**
- `3c27e31` 分离版登录入口识别（base path → /prod-api/login | /auth/login | /sys/login）
- `95f27be` Jeecg context-path 不重复追加 + jmreport result 包装识别
- `fee7580` Spring 三插件按真实响应形态判定（env 属性回显/204、gateway 201+Location+清理、SCF 时序差分）

### WP1 · JeecgBoot 8 个插件（ROI 最高，一座靶场解锁 8 个）
- **做法**：改造真实 R10（JeecgBoot 3.6.3）为**漏洞版**：jmreport 未授权/注入/上传、dict 越权、
  queryUserByDepId 注入、任意文件读取、代码生成 SSTI、默认口令；保留一个「修复版」负样本。
  真实源码在 lab repo 的 src/（Java），改动后 Maven 重建；**禁止用 Flask mock 冒充**（mock 只用于 CI 签名对拍）。
- **验收**：8 个插件在 R10-vuln 上各至少 1 次 CONFIRMED；R10-safe 上 0 B 类误报。

### WP2 · 鉴权后能力（解锁 ~10 个 ruoyi 插件）
- **问题**：R6/R7/R9 的 auth 扫描退出码 4（登录失败），鉴权后插件整类未测。
- **做法**：先用 scripts/diag_login.py 类工具诊断三站登录链（验证码/JWT/Sa-Token），
  修扫描器认证链或靶场登录参数；为三站准备低权账号（--surface-account 用）。
- **验收**：三站 --auth-login 退出码 0（A2 双因子为 4 属预期）；sql_inject_role/dept、
  file_upload、file_read、job_invoke_target、resetPwd/dept_tree 至少 4 项在真实靶场 CONFIRMED。

### WP3 · Spring 缺口 5 插件
- **做法**：给 C2 系列补 actuator env RCE / trace / SCF / Gateway 端点（或新建 C2-4/C2-5）；
  Spring4Shell 用 C2-2 真实 Tomcat + --exploit 验证（已具备）。
- **验收**：5 项各至少 1 次 CONFIRMED（Spring4Shell 允许 --exploit 下 CONFIRMED）。

### WP4 · RuoYi 遗留项
- 任意文件读取 ×2 / 定时任务 RCE（未授权）→ R2/R4 加可控读点与未授权 job 端点；
- Nacos 未授权 / Cloud 配置泄露 → R8 独占模式跑一轮（盲测 v2 未跑）；
- 备份文件泄露 → 补 R3 子目录真实备份（目录可列场景）；/docs 不可列场景维持设计边界。

### WP5 · 盲测 v3 + 修复
- 新靶场冻结 tag（lab repo）+ manifest；跑 62+ 目标扫描（anon/auth/低权三路）；
  三方对照（扫描器/nuclei/手工 GT）；产出 docs/blind_test_report_v3.md。
- 暴露的真缺陷按 P0/P1 修复，每个修复带回归测试 + FP 基线。

### WP6 · 发布 v1.5.5
- 版本位 6 处 + CHANGELOG + release-notes/v1.5.5.md；全量 pytest/ruff/mypy/签名靶场 E2E 全绿；
  push → CI 绿 → tag v1.5.5 → Release/PyPI/桌面端核验。

## 三、约束（沿用盲测 v2 纪律）
1. **先修尺子再测**：靶场先自验（GT 独立探测），再拿扫描器扫。
2. **新判定必须过 tests/test_fp_baseline.py**；新增 CONFIRMED 同步 data/acceptance_baseline.json。
3. **禁止对着插件源码写 mock 当真实靶场**；签名靶场（lab/server.py 等）只用于 CI 回归。
4. 时间盒：单个工作包超过 1 天无进展 → 降级/换 ROI 更高项，不无限投入。

## 四、验收标准（v1.5.5 可发布条件）
- 25 个零产出插件中，**>= 15 个**在盲测 v3 至少 1 次 CONFIRMED（排除 recon/Shiro 等设计上不产出的项后）；
- 盲测 v3 的 **FP = 0**（B 类硬误报），FN 有清单且逐条给出「修/不修」结论；
- 全量 pytest、ruff、format、mypy --strict、签名靶场 E2E、CI 全绿；
- 干净 venv 安装 wheel + 冒烟通过；GitHub Release / PyPI / 桌面端产物齐全。
