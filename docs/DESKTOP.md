# 桌面端（单 exe）

> **一个 exe 双击即用**：无需安装 Python、无需命令行。引擎（FastAPI + 51 POC + 字典 +
> Web 控制台）经 PyInstaller 冻结后在编译期整块嵌入壳程序，首次运行自动释放并拉起。

## 下载

从 [GitHub Releases](https://github.com/xiabai2008/Ruoyi-Scan/releases) 获取：

| 文件 | 适用场景 |
|------|---------|
| `ruoyi-scan-desktop.exe`（~48 MB） | **推荐**：单文件版，放到任意目录双击即可 |
| `Ruoyi-Scan_<version>_x64-setup.exe` | 可选：NSIS 安装包（开始菜单 / 桌面快捷方式，currentUser 免管理员） |
| `checksums-desktop.txt` | SHA256 校验（供应链完整性） |

```powershell
# 校验（可选）
Get-FileHash .\ruoyi-scan-desktop.exe -Algorithm SHA256
```

## 使用

1. 双击 `Ruoyi-Scan.exe`（单文件版文件名以下载页为准）
2. 首次启动约 3~5 秒：引擎自释放到 `%LOCALAPPDATA%\Ruoyi-Scan\engine\` 并在
   `127.0.0.1:8123` 就绪
3. 窗口内操作：新建扫描 → 实时事件流 → 报告下载

!!! tip "引擎已内嵌，无需联网"
    所有检测能力（POC / 字典 / Web 控制台）都在 exe 内，仅扫描目标需要网络。

## 进程与端口说明

桌面端 = **Tauri 壳（界面）+ 内嵌引擎（后端）**，单 exe 启动后表现为两个进程：

```
Ruoyi-Scan.exe                 ← WebView 壳（界面）
└─ ruoyi-scan-engine.exe       ← 自释放的 PyInstaller 引擎（127.0.0.1:8123）
```

- 引擎**仅监听 127.0.0.1**（本机回环），不对局域网开放；未设置 API Key 时仅允许
  本机访问
- 关闭窗口：壳正常退出并回收引擎
- 壳被任务管理器强杀：引擎通过 Windows JobObject（KILL_ON_JOB_CLOSE）**整树自动回收**，
  不会残留孤儿进程占用 8123

## 数据落盘位置

| 数据 | 路径 | 说明 |
|------|------|------|
| 引擎释放目录 | `%LOCALAPPDATA%\Ruoyi-Scan\engine\` | 版本戳控制，升级自动覆盖 |
| 扫描报告 | `%USERPROFILE%\Ruoyi-Scan\reports\` | 冻结环境自动重定向（安装目录可能只读） |
| 任务数据库 | `%USERPROFILE%\Ruoyi-Scan\tasks.db` | SQLite 任务持久化 |
| 界面偏好 | localStorage | 主题 / 人格 / 视觉签名 / Widgets |

卸载（安装包版）或删除单文件版 exe 即完成卸载；`%USERPROFILE%\Ruoyi-Scan\` 下的
报告数据按需手动清理。

## 桌面端特性

- **人格系统**：11 预设操作员 + 自定义头像（`~/Ruoyi-Scan` 界面内选择）
- **主题**：4 套预设 + 自定义色板（6 色派生 30 token）
- **视觉签名**：CRT 扫描线 / 复古字体 / 像素字体（retro / pixel 模式）
- **桌面 Widgets**：CONFIRMED 计数 / 引擎状态 / 任务进度浮卡，可拖拽

## Web API 依旧可用

引擎在本地 8123 端口提供完整 REST + WebSocket（与 CLI `--serve` 模式同一套 API），
桌面端界面就是它的第一个消费者。外部脚本可直接对接：

```python
import requests
r = requests.get("http://127.0.0.1:8123/api/plugins")
print(len(r.json()))  # 51
```

端点全表见 [API 文档](API.md)。

## 从源码构建桌面端

```bash
# 一键：引擎冻结 → 前端构建 → cargo 打包（引擎随编译嵌入）
cd desktop/engine && build-engine.cmd

# 产物
#   desktop/src-tauri/target/release/ruoyi-scan-desktop.exe      单文件版
#   desktop/src-tauri/target/release/bundle/nsis/*-setup.exe     安装包
```

构建链路：`PyInstaller (ruoyi-scan-engine.spec)` → `build.rs 复制到 OUT_DIR` →
`include_bytes! 嵌入` → `tauri build`。CI 由 `.github/workflows/desktop-release.yml`
在 push tag 时自动执行（含便携版 / 装机双冒烟）。

## 故障排查

| 现象 | 处理 |
|------|------|
| 双击无窗口 | 检查 `%LOCALAPPDATA%\Ruoyi-Scan\engine\` 是否有释放失败残留；删除该目录重试 |
| 8123 被占用 | 壳会提示"后端已在本机运行，跳过拉起"——正在跑的 CLI `--serve` 可直接复用 |
| WebView2 缺失 | Win10 早期版本需安装 [WebView2 Runtime](https://developer.microsoft.com/microsoft-edge/webview2/)（Win10 21H2+/Win11 系统自带） |
| 杀软报毒 | PyInstaller onefile 的常见误报，可提交白名单或改用 NSIS 安装包 + checksums 校验 |
