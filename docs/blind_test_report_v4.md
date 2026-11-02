# ruoyi-scan v1.5.6 盲测 v4 报告（口径正确性验证）

- 盲测日期：2026-11-02
- 被测代码：main `994e7d7`（含 WP1 context-path、WP2 win.ini、WP3 plus job、WP4 备份、WP5 Shiro、WP6 归属）
- 靶场版本：lab repo `24382f0`（tag `lab-blindtest-v4`；manifest `artifacts/lab_manifest_v4.json`）
- 原始数据：`artifacts/blind_v4/`（61 份报告：29 anon + 10 auth + 5 surface + 4 专项 + 2 R8 独占 + 3 子模式 + 8 C 系列）
- 驱动脚本：`artifacts/blind_v4/{run_blind_v4.ps1,aggregate.py}`

## 0. 本轮目标与判定口径

v1.5.5（盲测 v3）解决的是「该报的能报」——54 插件中 46 个有 CONFIRMED 产出。
本轮（v1.5.6）的目标不是再涨数字，而是**把口径做对**：

1. 自定义 context-path 能不能识别（否则路径类插件整类探错基准）；
2. Windows 目标能不能判（否则「任意文件读取」在 Windows 上系统性漏报）；
3. 「端点不存在」会不会被冒充成「确认安全」；
4. 宿主级发现会不会被当成站点漏洞重复计入；
5. 永远无法 CONFIRMED 的插件会不会继续虚报 high 级 RCE。

覆盖判定：同一插件在任一报告中有 CONFIRMED 即计为「有产出」；
安全/负样本模式出现 CONFIRMED 计为误报（B 类硬误报）。

## 1. 结论摘要

| 指标 | 盲测 v3（v1.5.5） | 盲测 v4（v1.5.6） | 变化 |
|---|---|---|---|
| 有 CONFIRMED 产出的插件 | 46/54 | **48/54** | **+2** |
| 零产出插件 | 8 | **6** | **-2** |
| v3 已有产出在 v4 丢失 | — | **0** | 无回归 |
| 安全模式新增 CONFIRMED（B 类误报） | 0 | **0** | 保持 |

**新增 2 项**：Redis 未授权访问（WP2 端口可配）、备份文件泄露（WP4 靶场）。

> 剩余 6 个零产出全部是**已识别边界**，无一为「未知漏报」：
> - 目录扫描 / HTTP 方法探测（2）：recon 类，设计上不产 CONFIRMED；
> - Shiro 框架指纹（1）：WP5 已收口为 `category=recon`，只到 SAFE/UNKNOWN；
> - 任意文件读取 ×2：需**未授权可读**的下载接口，R1/D1 的 `/common/download/resource`
>   都要登录（302 登录墙）。WP2 的 win.ini 判据已就绪，缺的是靶场侧的未授权读点；
> - RuoYi-Plus 定时任务（1）：Plus 5.6.2 已改用 SnailJob，**该端点不存在**（见 §4）。

## 2. v1.5.6 工作包验证点（6/6 PASS）

| 工作包 | 验证点 | 结果 |
|---|---|---|
| WP1 | D1 的 `/portal` 自动识别 | **PASS**（无需 nginx 兼容映射，job RCE CONFIRMED） |
| WP1 | `--base-path /portal` 显式指定 | **PASS**（探测基准推进到 `/portal/`） |
| WP2 | R1/D1 任意文件读取（登录墙） | **PASS**（判 UNKNOWN，不冒充 SAFE） |
| WP3 | R9 端点不存在 | **PASS**（判 UNKNOWN，证据写明 SnailJob） |
| WP4 | R7 备份文件泄露 | **PASS**（CONFIRMED，paths=`/index.bak, /config.old`） |
| WP6 | 宿主级归属标注 | **PASS**（44 个站点正确标注 Redis 为 host 级） |

## 3. 宿主级归属（WP6）

盲测 v3 及之前，宿主 Redis 会在**每一份站点报告**里各报一次，读者会以为是各站点都有该漏洞。
v1.5.6 引入归属判定后：

- **44 个站点**的 Redis 发现被标注为 `host`（探测地址是 `127.0.0.1:16379`，站点在 19xxx）；
- 单目标报告：`risk_distribution.host_level` + HTML 归属列/横幅 + CSV 归属列 + JSON `host_level_count`；
- 批量报告：概览表单列「其中宿主级」+ 归属说明；
- 终端输出同步标注，与报告口径一致。

**这解释了为什么「Redis 未授权」这一条插件名出现在 44 份报告里却只该算 1 个主机暴露**——
报告读者据此能把「站点漏洞」和「主机暴露」分开统计。

## 4. WP3 的重要发现：Plus 5.6.2 没有 /monitor/job

计划原方案是「给 R9 加 vuln 模式（`security.excludes` 追加 `/monitor/**`）让插件 CONFIRMED」。
实测**推翻了原方案**：

- RuoYi-Vue-Plus **5.6.2 的定时任务已迁到 SnailJob**（`snailjob.version=1.10.0`，
  依赖 `snail-job-client-*`），`controller/monitor/` 下只有 Cache/Logininfor/Operlog/UserOnline，
  **没有 SysJobController**；
- `/monitor/job/**` 返回 `HTTP 200 + {"code":404,"msg":"请求地址不存在"}`。

**这不是误配能造出来的**——任何配置都变不出一个不存在的端点。
真正的问题是插件把「端点不存在」和「鉴权生效」都判 SAFE，
等于用「地址错了」冒充「系统是安全的」。已改为按若依 AjaxResult 业务码判 UNKNOWN。

注：`affected_versions` 补了 `>=5.0,<5.6`，但**版本过滤靠不住**——
R9 的 api-docs 需认证（401）、根路径是纯 SPA，版本识别不出，过滤不生效。
这就是必须在插件判定层修的根本原因。

## 5. WP1 暴露并修复的认证链缺陷

WP1 补上 context-path 识别后，D1 的 `--auth-login` **从 exit 0 回退成 exit 4**，
连带丢失「RuoYi 代码生成模块 SSTI」的 CONFIRMED（该插件需会话）。

根因：`_detect_separated_login` 的兜底分支**无条件假设**登录入口是 `{base}/login`，
而 D1 是二开改名的 `/portal/auth/signin`。POST 打到 404 → 登录失败。

修法（`994e7d7`）：从登录页的 form action 读真实入口，不猜路径。只认同源、
method=post、含 password 输入框的表单（否则搜索框/筛选器都会被当成登录入口）。
修复后 D1 恢复 `admin: ok`，代码生成 SSTI 恢复 CONFIRMED。

**这是本轮最有价值的一条**：它说明「能力增强」和「既有能力不回归」必须同时验证——
WP1 让前缀识别变强了，却暴露了认证链的硬编码假设。

## 6. 安全模式 / 负样本验证（误报检查）

| 目标 | CONFIRMED | 结论 |
|---|---|---|
| C3 蜜罐站 | 5（.env/.git/Redis/Swagger/批量未授权） | 诱饵真实存在，A 类可接受 |
| R11 内部接口负样本 | 1（仅宿主 Redis，已标注 host） | 站点自身 0 误报 |
| R13 WAF hold-out | 2（Redis + 后台默认口令） | 与 v3 设计一致 |

**B 类硬误报 0**。R11 从 v3 的「1 条」变成「1 条但已标注宿主级」——
数字没变，但读者现在能看出它不是站点漏洞。

## 7. 已知限制（如实记录）

1. **任意文件读取 ×2 仍零产出**：判据（含 win.ini）已就绪，缺的是**未授权可读**的靶场读点。
   R1/D1 的 `/common/download/resource` 都要登录。需另建一个匿名可读的文件读取靶场，
   或给现有站点开一个未授权读点（列为 v1.6 候选）。
2. **Plus 定时任务**：5.6.2 无该端点，需另建 Plus 5.5 及更早的误配站才能验证 CONFIRMED。
3. **R8 站点扫描的归因**：gateway 组件暴露挂在若依插件名下，报告需按「gateway 组件」阅读（v3 已记录）。
4. **C4-1（16379）不能当 HTTP 目标扫**：它是 Redis socket 服务，`-u http://...:16379` 会被预检判不可达
   （exit 3）。Redis 插件的验证走「扫描任意 HTTP 站点 + `--redis-port 16379`」这条路。
5. **D1 的 nginx 兼容映射已收敛到 context-path 之内**：lab `a2a69f5`。

## 8. 交付物

- 扫描器 commit：`226423b`（归属）、`1fd4ff4`（Redis 端口）、`969a6c9`（Shiro 收口）、
  `5a7f6ea`（context-path）、`3e331a1`（win.ini）、`4c71878`（plus job）、`994e7d7`（认证链）
- 靶场 commit：`a2a69f5`（D1 映射）、`24382f0`（R9 误配模式 + R7 备份资产），tag `lab-blindtest-v4`
- 原始数据：`artifacts/blind_v4/`（`coverage_summary.json`、`results.tsv`、各站点 report.json 与日志）
