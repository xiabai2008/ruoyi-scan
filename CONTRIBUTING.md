# 贡献指南

感谢你对 Ruoyi-Scan 的关注！本文档介绍如何参与项目开发。

## 快速开始

```bash
# 1. Fork & Clone
git clone https://github.com/<你的用户名>/Ruoyi-Scan.git
cd Ruoyi-Scan

# 2. 安装开发依赖
pip install -r requirements-dev.txt

# 3. 运行测试
python -m pytest -q

# 4. 代码检查
ruff check core/ lib/ api/ plugins/ chains/ main.py
ruff format --check core/ lib/ api/ plugins/ chains/ main.py
```

## 开发流程

1. **创建分支**：`git checkout -b feature/your-feature` 或 `fix/your-fix`
2. **编写代码**：遵循下方代码规范
3. **编写测试**：新功能必须配套测试，确保 `pytest` 通过
4. **代码检查**：`ruff check` 零错误、`ruff format --check` 通过
5. **提交代码**：使用约定式提交信息（见下方）
6. **提交 PR**：描述清楚改动内容与动机

## 约定式提交

使用 [Conventional Commits](https://www.conventionalcommits.org/) 格式：

```
<type>(<scope>): <description>

[optional body]
```

| type | 说明 |
|------|------|
| `feat` | 新功能 |
| `fix` | Bug 修复 |
| `docs` | 文档变更 |
| `style` | 代码格式（不影响逻辑） |
| `refactor` | 重构（非新功能、非修复） |
| `test` | 测试相关 |
| `ci` | CI/CD 配置 |
| `chore` | 构建/工具变更 |

示例：`feat(plugin): 新增若依 SQL 注入 POC`、`fix(ci): 修复 pytest 超时`

## 代码规范

### Python 风格

- **行宽**：120 字符（ruff `line-length = 120`）
- **目标版本**：Python 3.8+（`target-version = "py38"`）
- **规则集**：E / F / W / I / N（错误、pyflakes、警告、导入排序、命名）
- **格式化**：`ruff format`（非 black）

### 插件开发

每个漏洞检测插件继承 `PluginBase`，遵循「一漏洞一插件」原则：

```python
from plugins.base import PluginBase, cvss_score, parse_compliance
from core.models import ScanResult, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN


class YourPlugin(PluginBase):
    name = "漏洞名称"
    cve = "CVE-2026-XXXX"
    severity = "high"  # high / medium / low
    category = "ruoyi"  # ruoyi / spring / common
    description = "漏洞描述"
    fix = "一句话修复建议"
    fix_detail = "多行修复详情（代码 diff / 升级命令 / 配置加固）"
    reproduce = "复现命令（curl / Python PoC）"
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    compliance = "等保2.0:8.1.3;OWASP:A03:2021"

    def verify(self, target, session):
        # 1. 发送探测请求
        resp = session.get(f"{target}/vulnerable-path")
        # 2. 三态判定
        if resp.status_code == 200 and "vuln_keyword" in resp.text:
            return self._build_result(STATUS_CONFIRMED, url=resp.url, evidence="...")
        elif resp.status_code == 404:
            return self._build_result(STATUS_SAFE, url=resp.url)
        else:
            return self._build_result(STATUS_UNKNOWN, url=resp.url)
```

### 测试规范

- 测试文件放在 `tests/test_*.py`
- 使用 `unittest.TestCase` 或 `pytest` 风格
- 网络请求必须用 `requests_mock` mock，不得发出真实网络请求
- 测试命名：`test_<被测功能>_<场景>`

```python
import requests_mock
import unittest
from plugins.ruoyi.your_plugin import YourPlugin


class TestYourPlugin(unittest.TestCase):
    def test_vuln_confirmed(self):
        plugin = YourPlugin()
        with requests_mock.Mocker() as m:
            m.get("http://test/vulnerable-path", text="vuln_keyword", status_code=200)
            result = plugin.verify("http://test", mock_session)
            self.assertEqual(result.status, STATUS_CONFIRMED)
```

## 项目结构

```
Ruoyi-Scan/
├── main.py              # CLI 入口（参数解析）
├── core/                # 核心引擎（runner / session / report / models）
├── lib/                 # 功能库（WAF 绕过 / 认证 / 逻辑扫描 / 异步引擎...）
├── plugins/             # POC 插件
│   ├── base.py          # 插件基类
│   ├── ruoyi/           # 若依专项 16 个 POC
│   ├── spring/          # Spring Boot 14 个 POC
│   └── common/          # 通用漏洞 8 个 POC
├── chains/              # 漏洞利用链
├── api/                 # FastAPI Web API + Prometheus 指标
├── config/              # 指纹库 / 字典 / 模板
├── tests/               # 测试套件（887+ 测试）
├── lab/                 # 签名靶场（Flask）
├── scripts/             # 辅助脚本
└── monitoring/          # Prometheus + Grafana 配置
```

## 报告安全漏洞

请勿通过 GitHub Issue 报告安全漏洞。请参考 [SECURITY.md](SECURITY.md) 中的流程私下报告。

## 行为准则

参与本项目即代表你同意保持尊重和包容的交流态度。人身攻击、骚扰或恶意行为将不被容忍。
