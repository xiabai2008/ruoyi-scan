# 快速上手

> 5 分钟从安装到出第一份报告。完整参数见 [用户手册](USAGE.md)。

## 1. 安装

=== "pip（推荐）"

    ```bash
    pip install ruoyi-scan
    ```

=== "源码"

    ```bash
    git clone https://github.com/xiabai2008/Ruoyi-Scan.git
    cd Ruoyi-Scan
    pip install -r requirements.txt
    python main.py -h
    ```

=== "Docker"

    ```bash
    docker build -t ruoyi-scan .
    docker run --rm ruoyi-scan -u http://target:8080
    ```

=== "桌面端（免 Python）"

    从 [GitHub Releases](https://github.com/xiabai2008/Ruoyi-Scan/releases) 下载
    `ruoyi-scan-desktop.exe`，双击即用（引擎内嵌，详见[桌面端文档](DESKTOP.md)）。

依赖：Python 3.8+；报告增强（PDF/Word/Excel）与 Web API 为可选依赖，缺失时自动降级
（详见[用户手册 · 依赖要求](USAGE.md#依赖要求)）。

## 2. 四种扫描模式

| 模式 | 命令 | 说明 |
|------|------|------|
| 综合扫描 | `ruoyi-scan -u http://target:8080` | 指纹 → WAF → 路由 → POC → 报告，全流程 |
| 漏洞检测 | `ruoyi-scan -p http://target:8080` | 跳过指纹，直接 POC 验证 |
| 目录扫描 | `ruoyi-scan -m http://target:8080` | 敏感路径 / 后台 / actuator 探测 |
| 登录爆破 | `ruoyi-scan -l http://target:8080` | 弱口令字典爆破（可 `--pass-level top100`） |

常用增强：

```bash
# 批量目标
ruoyi-scan -f targets.txt

# 组件版本检测（fastjson/Shiro/Nacos/Log4j 等 20 组件）
ruoyi-scan -u http://target:8080 --components

# 认证后深度扫描（登录态资产盘点 + 越权矩阵）
ruoyi-scan -u http://target:8080 --auth login=ruoyi:admin123

# WAF 环境强制绕过策略
ruoyi-scan -u http://target:8080 --bypass-waf on

# 指定报告目录与格式
ruoyi-scan -u http://target:8080 --report ./out --report-format html,pdf,docx
```

## 3. 读懂三态结果

<div class="rs-tri" markdown>
<span class="confirmed">CONFIRMED 确认存在</span>
<span class="safe">SAFE 确认不存在</span>
<span class="unknown">UNKNOWN 无法判定</span>
</div>

- **CONFIRMED**：拿到了漏洞存在的直接证据（如回显文件内容、注入成功标记）
- **SAFE**：在目标当前版本/配置下**已验证不存在**——不是"没测出来"，而是"测过了，排除"
- **UNKNOWN**：网络异常 / WAF 拦截 / 验证码阻断等原因导致无法判定，**永不冒充 SAFE**，
  建议人工复核

> 这条纪律是 Ruoyi-Scan 与「结果全红」扫描器的核心差异：报告里的每一行结论都可信。
> 判定细节与误报防护矩阵见[安全报告说明](SECURITY_REPORT.md)。

## 4. 报告在哪

默认输出到 `reports/`（可用 `--report` 覆盖），一次扫描同时产出：

```
reports/
├── report_<host>_20260910_153045.html    # 交互式报告（SVG 图表）
├── report_<host>_20260910_153045.json    # 机器可读（CI 集成 / baseline diff）
├── report_<host>_20260910_153045.pdf     # 交付物（可选依赖）
├── report_<host>_20260910_153045.docx    # Word 交付物（可选依赖）
└── ...
```

## 5. Web 控制台（可选）

```bash
ruoyi-scan --serve --host 127.0.0.1 --port 8123
# 浏览器打开 http://127.0.0.1:8123 —— 实时任务流 / WebSocket 推送 / 报告下载
```

完整 REST 端点与 WebSocket 事件协议见 [API 文档](API.md)。

## 下一步

- [用户手册](USAGE.md)：全部 CLI 参数、扫描模板、分布式、CI/CD 集成
- [插件开发教程](PLUGIN_DEV.md)：写你的第一个 POC（PluginBase 三态契约）
- [桌面端](DESKTOP.md)：单 exe 免安装形态
- [社区总览](COMMUNITY.md)：贡献指南 / 变更日志 / 发展路线图（仓库根文件）
