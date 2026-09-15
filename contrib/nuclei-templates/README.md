# RuoYi Nuclei 模板包

面向 [nuclei](https://github.com/projectdiscovery/nuclei) 用户的若依（RuoYi）专项模板包，
由 [ruoyi-scan](https://github.com/xiabai2008/ruoyi-scan) 团队维护。

## 为什么单独成包

官方 nuclei-templates 的定位是「有实网命中量证明的产品级漏洞」：若依的检测指纹（fingerprinthub）、
任意文件读取（CNVD-2021-01931）、DOM XSS（CVE-2025-7901）均已收录。但若依的
**授权配置类暴露面**（未授权可达的管理接口、默认口令）属于"部署配置问题"，不符合上游收录标准——
而恰恰是渗透测试中实际会遇到、需要检查的点。本包就是这部分的补充。

## 获取方式

- 本仓库：`contrib/nuclei-templates/`（规范源，CI 有语法校验 + 靶场功能门）
- 发布包：`ruoyi-nuclei-templates-<version>.zip`（随 ruoyi-scan Release 附出，见 Releases 页）

## 使用方法

```bash
# 直接指向本目录扫描
nuclei -u https://target.example.com -t ./nuclei/

# 按标签筛选（只跑若依模板）
nuclei -u https://target.example.com -t ./nuclei/ -tags ruoyi

# JSONL 输出（供流水线消费）
nuclei -u https://target.example.com -t ./nuclei/ -jsonl -o ruoyi-findings.jsonl
```

## 模板清单（v0.1.0）

| 模板 | 严重度 | 检查内容 | CWE |
|------|--------|---------|-----|
| `ruoyi-default-password.yaml` | high | 默认管理员口令（admin/admin123）——文档记载的若依初始凭据，成功获取 token 才判定 | CWE-1392 |
| `ruoyi-job-unauth.yaml` | medium | 定时任务端点（/monitor/job/edit）未授权可达业务层 | CWE-306 |
| `ruoyi-unauth-api.yaml` | medium | 管理列表 API（/system/user/list）未授权返回业务数据 | CWE-306 |

**严重度取值说明**（吸取上游审查反馈）：未授权可达类如实标 medium——漏洞本体是"授权配置失效"，
进一步的破坏需要结合弱口令等条件；不虚标 high/critical。

**matcher 设计**：全部基于结构化特征（HTTP 状态码 + JSON 业务字段 + 否定式排除登录/鉴权错误），
不依赖中文文案匹配，避免响应本地化导致的漏报。

## 验证状态

每个模板均在本项目的**签名靶场**（vuln / safe 双模式）实测：

- vuln 模式必须命中（3/3 模板命中）
- safe 模式必须零误报（0 命中）

原始证据见 [EVIDENCE.md](EVIDENCE.md)。模板 metadata 中 `ruoyi-scan-lab-verified: true` 表示
已通过双模式验证；**未经实网批量验证**（与上游 `verified: true` 的语义不同，如实标注）。

> 注意：签名靶场验证的是 matcher 逻辑与响应特征的正确性。目标环境若做过定制化改造，
> 可能存在差异——遇到误报/漏报欢迎提 issue。

## 与官方模板集的关系

本包与官方 [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) 互补，不重复收录：

- 指纹识别：使用官方 `fingerprinthub-web-fingerprints.yaml`（-tags fingerprinthub）
- 任意文件读取：官方 `CNVD-2021-01931.yaml`
- DOM XSS：官方 `CVE-2025-7901.yaml`
- 定时任务/管理 API 未授权、默认口令：本包

两套模板可同时加载（ID 无冲突）。

## 贡献

模板遵循 nuclei 官方语法规范，提交前请：

1. `nuclei -validate -t <template>`
2. 在本项目签名靶场或真实授权目标上验证（附运行输出）

模板 ID 使用 `ruoyi-` 前缀，避免与上游冲突。
