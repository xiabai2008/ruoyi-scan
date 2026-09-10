# 社区

Ruoyi-Scan 从「个人项目」走向「有外部贡献者的社区项目」。核心文档入口：

| 文档 | 位置 |
|------|------|
| [贡献指南](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/CONTRIBUTING.md) | 仓库根 · 开发环境 / 代码规范 / PR 流程 |
| [变更日志](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/CHANGELOG.md) | 仓库根 · 每个版本的变更记录 |
| [发展路线图](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/ROADMAP.md) | 仓库根 · G 系列阶段规划与度量指标 |

## 参与方式

- **报告问题**：[Issues](https://github.com/xiabai2008/Ruoyi-Scan/issues) —— 检测误报 /
  漏报请附脱敏扫描 JSON（UNKNOWN 结果尤其欢迎，帮助扩展三态判定覆盖）
- **贡献 POC**：按[插件开发教程](PLUGIN_DEV.md)实现 PluginBase，通过 PR 提交；
  涉及检测面的改动需附带[签名靶场](https://github.com/xiabai2008/Ruoyi-Scan/tree/main/lab)覆盖
- **good first issue**：在 issue 列表筛选 `good first issue` 标签入手
- **安全漏洞反馈**：详见[安全政策](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/docs/DEVSECOPS.md)
  ——请勿通过公开 issue 提交安全漏洞

## 检测插件矩阵

| 插件包 | 数量 | 说明 |
|--------|------|------|
| `plugins/ruoyi/` | 18 | 若依专项（文件读取 / SQL 注入 / RCE / SSTI / 未授权等） |
| `plugins/spring/` | 14 | Spring Boot 生态（Actuator / Gateway / Jolokia / Spring4Shell 等） |
| `plugins/common/` | 11 | 通用泄露与配置（.git / .env / 备份 / CORS / Swagger 等） |
| `plugins/jeecgboot/` | 8 | JeecgBoot 拓展（首个非若依框架实证，方法论可复制性验证） |

第三方插件通过 `ruoyi_scan.plugins` entry_points 注册，pip 安装即被自动发现——
分发与验签流程见[插件模板仓库](TEMPLATE_REPO.md)。

## 上游生态回馈

- [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)：计划提交若依专项
  模板 PR（`lib/nuclei_loader.py` 兼容层已证明技术同源）
- Wappalyzer / EHole：若依系指纹回馈

## 星标历史

[![Star History Chart](https://api.star-history.com/svg?repos=xiabai2008/ruoyi-scan&type=Date)](https://star-history.com/#xiabai2008/ruoyi-scan&Date)
