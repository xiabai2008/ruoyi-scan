# 变更日志

本项目遵循 [语义化版本](https://semver.org/lang/zh-CN/) 规范。

格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)。

## [Unreleased]

### Added

- **P0 版本矩阵**: 新增若依版本兼容性矩阵文档 `docs/version-matrix.md`
- **P0 Cloud 路由**: `core/router.py` 添加 `ruoyi-cloud` → `plugins.ruoyi` 路由映射
- **P0 Cloud 里程碑**: `core/ruoyi_versions.py` 添加 RuoYi-Cloud 版本里程碑和特征路径

- 方向 1-5: README 文档同步 + 依赖规范化 + pyproject.toml 现代打包 + PyPI 发布工作流 + CI 代码质量门禁
- 方向 6: 社区治理文档（CONTRIBUTING / SECURITY / CHANGELOG + Issue/PR 模板）

## [1.1.0] - 2026-07-19

### Added

- **P0 重构**: main.py 从 1426 行拆分为 389 行（CLI）+ core/runner.py 798 行（业务逻辑）
- **D10-D37**: 27 个深化方向全部完成，累计 871 测试通过
- **D16**: Docker Compose + Prometheus + Grafana 监控栈
- **D18**: 38 个 POC 新增详细修复信息（代码 diff / 升级命令）
- **D24**: 38 个 POC 新增漏洞复现命令（curl / Python PoC）
- **D19**: 4 个扫描模板（quick / deep / compliance / dengbao）
- **D27**: YAML 配置文件支持（CLI 参数覆盖优先级）
- **D23**: 国际化支持（中文/英文报告切换）
- **D25**: 插件 SDK（模板生成 + 验证）
- **D28**: CI/CD 集成（严重性阈值退出 + 流水线模板）
- **D29**: 离线漏洞知识库（HTML Wiki + JSON API）
- **D34**: 异步扫描引擎（aiohttp）
- **D35**: Web UI 控制台（FastAPI + WebSocket）
- **D36**: 分布式任务队列（Redis Master-Worker）
- **D37**: 结果缓存（SQLite TTL）

### Changed

- CLI 参数从 21 个扩展到 80+ 个（15 个功能组）
- 报告格式从 4 种扩展到 7 种（新增 PDF / Word / Excel / SARIF）
- 插件数量从 20 扩展到 38（16 ruoyi + 14 spring + 8 common）

### Fixed

- 修复 test_d8_cli.py 导入错误（_parse_report_formats 迁移至 core/runner）
- 修复 387 个 ruff lint 错误
- 修复 CI 中 pytest 缺失、httpx2 依赖、crt.sh 真实网络请求等问题
- 修复 Signature Labs E2E 靶场缺失 11 个插件签名
- 修复验证码接口在 CI 无 OCR 依赖时导致 UNKNOWN 判定

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

[Unreleased]: https://github.com/xiabai2008/Ruoyi-Scan/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/xiabai2008/Ruoyi-Scan/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/xiabai2008/Ruoyi-Scan/releases/tag/v1.0.0
