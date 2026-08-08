## 变更描述

<!-- 简要说明变更内容 -->

## 变更类型

- [ ] 新 POC（漏洞检测插件）
- [ ] 新功能
- [ ] Bug 修复
- [ ] 文档 / CI / 重构
- [ ] 其他

## POC 贡献检查清单（新增插件时必填）

- [ ] 继承 `PluginBase`，实现 `verify(target, session) -> ScanResult`
- [ ] 元信息完整：`name`（中文）/ `cve` / `severity` / `category` / `description` / `fix`
- [ ] 建议字段已填：`fix_detail` / `reproduce` / `cvss_vector` / `compliance` / `affected_versions`
- [ ] **三态判定**：CONFIRMED / SAFE / UNKNOWN；网络异常绝不判 SAFE
- [ ] 降误报：多条件联合（状态码 + 正向关键字 + 负向排除）
- [ ] 仅存在性验证，无破坏性 payload（不写 webshell / 不执行恶意命令）
- [ ] 中文注释，符合项目代码风格（ruff format 通过）
- [ ] 已添加对应测试（`tests/test_*.py`）
- [ ] 本地验证：`python -m pytest tests/ -q` 全量通过

## 测试

- 本地运行：`python -m pytest tests/ --ignore=tests/test_report_xlsx.py`
- 结果：`<通过数> passed`

## 相关 issue

<!-- 关联 issue 编号（如有） -->

## 检查清单

- [ ] 代码风格：`ruff check common/ core/ lib/ api/ plugins/ chains/ cli/ main.py` 通过
- [ ] 已用真实/签名靶场验证判定逻辑（`lab/`）
- [ ] 变更不破坏既有行为（向后兼容）
