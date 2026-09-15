# Awesome-POC 投稿材料（B 渠道）

本目录是面向 [Threekiii/Awesome-POC](https://github.com/Threekiii/Awesome-POC) 的投稿**预备材料**，
尚未提交（对外 PR 需作者确认后执行）。

## 为什么投这里

上游 nuclei-templates 的收录标准（CVE/流行度证明）不适合若依的后台功能滥用类漏洞；
Awesome-POC 是中文安全社区最主流的 POC 汇编仓库，收录大量后台/需认证类 POC，
与若依这类国产框架的漏洞形态匹配。

## 待投文档（2 篇）

| 文档 | 漏洞 | 影响版本 | POC 来源（已实证） |
|------|------|---------|------------------|
| `若依管理系统 后台定时任务 RCE.md` | invokeTarget 调用目标注入 → RCE（4.7.0 前白名单缺失） | >=4.0, <4.7 | `plugins/ruoyi/job_rce.py`（签名靶场验证） |
| `若依管理系统 SQL注入（params dataScope）.md` | /system/role/list 与 /system/dept/list 的 dataScope 报错注入 | >=4.0, <4.6 | `plugins/ruoyi/sql_inject_role.py`（签名靶场验证） |

已存在不重复投：`Web应用漏洞/若依管理系统 后台任意文件读取 CNVD-2021-01931.md`（上游已有）。

## 投稿步骤（待确认执行）

```bash
# 1. Fork + 克隆
gh repo fork Threekiii/Awesome-POC --clone=false
git clone https://github.com/xiabai2008/Awesome-POC.git
# 2. 新分支 + 拷贝文档到 Web应用漏洞/（与既有若依文档同目录）
# 3. 提交 PR：
gh pr create --repo Threekiii/Awesome-POC \
  --title "Add 若依管理系统 后台定时任务 RCE / SQL注入 POC" \
  --body "<见下>"
```

PR 描述要点：
- 两个 POC 均来自 [ruoyi-scan](https://github.com/xiabai2008/ruoyi-scan) 插件的实测实现（含三态判定与修复建议）
- 请求/响应为文本形态（靶场实测）；如需界面截图，可在 review 时补充
- 参考链接指向官方仓库与 PeiQi 文库

## 准确性备忘

- 两篇文档的影响版本、修复版本均与本项目插件 `affected_versions` 及官方修复记录一致
- 未引用不确定的 CNVD 编号（若依多个漏洞的 CNVD 归属在社区资料中存在混用）
- 定时任务 POC 为**非破坏性探测**（jobId=99999 不存在，不修改任何任务），符合「仅授权测试」定位
