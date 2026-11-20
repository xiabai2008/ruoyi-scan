# 在线更新

> 从 v2.0 起，桌面端与 CLI 均支持检查新版本；桌面端可一键下载安装并重启，CLI 可通过 pip 或单文件 exe 自升级。

## 一、桌面端

- 启动后约 2 秒自动检查一次 GitHub Release 的 `latest.json`；
- 「设置 → 在线更新 / UPDATE」可手动检查、查看更新说明、下载并安装；
- 更新包由 Tauri 使用**编译期内置的 Ed25519 公钥**验签，签名不匹配/被篡改会在下载阶段拒绝；
- 安装完成后应用自动重启，引擎随新版壳重新解压。

### 发布端要求

1. 仓库 Secret 配置：
   - `TAURI_SIGNING_PRIVATE_KEY`：minisign 私钥内容（或私钥文件路径，CI 建议用内容）；
   - `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`：无密码 key 可留空。
2. `desktop/src-tauri/tauri.conf.json` 的 `plugins.updater.pubkey` 必须与私钥配对；
   本地开发可把私钥放 `.secrets/`（已 gitignore），**绝不要提交**。
3. `desktop-release.yml` 构建时会生成 `*.exe.sig`，并由
   `scripts/build_update_manifest.py` 生成：
   - `latest.json`：Tauri updater 清单；
   - `version.json`：CLI 更新清单；
   - `checksums-desktop.txt` 覆盖全部发布资产。

## 二、CLI

```bash
# 只检查，不修改当前安装
ruoyi-scan --check-update

# 检查并升级
ruoyi-scan --self-update

# 指定镜像/内网清单（HTTPS；localhost 允许 HTTP 便于测试）
ruoyi-scan --check-update --update-url https://mirror.example.com/version.json
```

升级策略：

| 安装形态 | 行为 |
|---|---|
| `pip install ruoyi-scan` | 调用当前解释器的 `pip install --upgrade ruoyi-scan==<版本>`；预发布版本自动加 `--pre` |
| PyInstaller 单文件 exe（Windows） | 下载对应 `ruoyi-scan.exe` → 校验 sha256 → 写入同目录 `.new` → 进程退出后延迟替换并重启 |
| 其他平台单文件 | 暂不自动替换，提示重新下载对应平台包 |

安全边界：

- 清单只接受 HTTPS；仅 `localhost/127.0.0.1` 允许 HTTP（供本地测试）；
- 单文件升级必须带合法 `sha256`，校验失败不会落盘；
- 网络/清单失败显式报错，不会静默当成「已是最新」。

### 环境变量

- `RUOYI_SCAN_UPDATE_URL`：覆盖默认清单地址（等价于 `--update-url`）；
- 默认清单：
  `https://github.com/xiabai2008/RuoYi-Scan/releases/latest/download/version.json`

## 三、发布流程

1. 打 tag（如 `v2.1.0`）；
2. CI 的 `desktop-release.yml` 在配置签名 secret 后构建；
3. 发布资产自动包含：
   - `latest.json` / `version.json`
   - `Ruoyi-Scan_<tag>_x64-setup.exe` + `.sig`
   - `ruoyi-scan.exe` / `ruoyi-scan-desktop.exe`
4. 桌面端只读取 `releases/latest/download/latest.json`，因此 **RC/预发布不会自动推送**；
   测试 RC 时可用 `RUOYI_SCAN_UPDATE_URL`（CLI）或临时修改桌面配置指向该 tag。

## 四、测试建议

```bash
# CLI 清单/版本比较（不联网）
pytest tests/test_updater.py -q

# 本地清单联调（示例）
python -m http.server 8765 --directory /tmp/update-manifest
ruoyi-scan --check-update --update-url http://127.0.0.1:8765/version.json
```

桌面端更新需要**签名产物**：本地构建时设置
`TAURI_SIGNING_PRIVATE_KEY`，否则 `createUpdaterArtifacts` 会失败或生成不可用清单。
