# 变更日志

本项目遵循 [语义化版本](https://semver.org/lang/zh-CN/) 规范。

格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)。

## [Unreleased]

### Added
- 新增 `ROADMAP.md` 发展路线图（G1-G5 + v2.0 愿景）：检测深度 / 工程债清偿 / AI 闭环 v2 / 生态社区 / 合规交付五大方向，含三条底线、度量仪表盘与落地机制；README 文档表同步入口
- **G1 组件检测扩展 5 → 20**：新增 druid / xxl-job / solr / rabbitmq / elasticsearch / kibana / tomcat / jetty / shenyu / jenkins / eureka / minio / grafana / sentinel / consul 数据驱动探测器（`_COMPONENT_SPECS` 规格表，存在性/版本提取/三态判定与手写探测器纪律一致）；`data/component_cve_map.json` 同步扩充（kibana CVE-2019-7600、grafana CVE-2021-43798、tomcat Ghostcat/PUT、jenkins CVE-2024-23897、shenyu CVE-2021-37580、jetty CVE-2021-34428 等）
- **G1 CVE 双源**：`lib/cve_sync.py` 增加 GHSA（GitHub Advisory Database）回退源——NVD 未收录/不可达时按 CVE 编号查询，`RUOYI_SCAN_GHSA_TOKEN` 环境变量可提速；`CVEInfo` 增加 `source` 字段
- **G1 变体矩阵补全**：`core/ruoyi_versions.py` 新增 `RUOYI_VARIANT_INFO` 变体元数据表（7 变体的鉴权方式 / API 前缀 / 版本指纹来源）与 `get_variant_info` / `get_variant_api_prefixes` 接口；`detect_version` 支持变体感知的指纹来源优先级（向后兼容）

### Fixed
- **G2 Windows 兼容修复**: `tests/test_report_xlsx.py` 8 处 `load_workbook` 未释放 workbook 句柄（openpyxl 内部循环引用 + close() 非 read_only 模式为 no-op），Linux 上删除打开中的文件无感、Windows 上 TemporaryDirectory 清理必报 WinError 32——断言后统一 `del` + `gc.collect()` 强制释放（5 轮稳定性验证通过）
- **CI lint 转绿**: 修复 ruff format 漂移（10 个文件 docstring 后空行重排）；lint 工具版本固定（ruff==0.16.2 / mypy==2.1.0，CI 与 pyproject dev 依赖同步），杜绝格式化工具版本演进导致的漂移复发
- **Nightly 验收修复**: 靶场容器 `docker run` 补传 `LAB_HOST=0.0.0.0`——v1.2.0 安全收口后靶场默认绑定 127.0.0.1，容器内绑定回环导致 Docker 端口映射不可达，自 8/25 起每晚启动超时；失败自动建 issue 覆盖靶场启动失败场景（旧条件在该场景下永不触发），并显式声明 `issues: write` 权限
- mypy `python_version` 目标 3.8 → 3.10（mypy 2.x 最低支持 3.10，仅影响类型分析，运行时仍支持 3.8+）

### Changed
- **Release 发布门禁**: tag 推送先等待同一提交的 CI 全绿再构建上传（ci.yml 增加 `tags: v*` 触发），防止带病发布
- **G2 CI Windows matrix**: unit 作业矩阵增加 `windows-latest`（pytest-timeout Windows 侧自动切 thread 方法），防 GBK 编码 / 路径分隔符回归；Codecov 上传收敛至 ubuntu+py3.11 组合
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
- **文档**: 新增 `docs/SECURITY_REPORT.md` 最终安全报告，并归档至模板仓库 ruoyi-scan-templates

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
- **API 文档**: docs/API.md + OpenAPI 3.0 规范
- **插件开发教程**: docs/PLUGIN_DEV.md
- **用户指南**: docs/USAGE.md 完整安装配置说明

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

[Unreleased]: https://github.com/xiabai2008/Ruoyi-Scan/compare/v1.2.4...HEAD
[1.2.4]: https://github.com/xiabai2008/Ruoyi-Scan/compare/v1.2.3...v1.2.4
[1.2.3]: https://github.com/xiabai2008/Ruoyi-Scan/compare/v1.2.2...v1.2.3
[1.2.2]: https://github.com/xiabai2008/Ruoyi-Scan/compare/v1.2.1...v1.2.2
[1.2.1]: https://github.com/xiabai2008/Ruoyi-Scan/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/xiabai2008/Ruoyi-Scan/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/xiabai2008/Ruoyi-Scan/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/xiabai2008/Ruoyi-Scan/releases/tag/v1.0.0
