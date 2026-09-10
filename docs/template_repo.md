# 插件模板仓库规范（E5）

Ruoyi-Scan 的插件分发遵循「模板仓库」模式（参照 nuclei-templates），
支持 `--plugin-export` / `--plugin-manifest` / `--plugin-update` 三件套。

## 仓库目录结构

```
ruoyi-scan-templates/          # 仓库根（建议独立 GitHub repo）
├── manifest.json              # 文件摘要 + Ed25519 签名（必须）
├── plugins_meta.json          # 插件元信息（导出自动生成）
├── plugins/
│   ├── ruoyi/
│   │   └── my_rce_plugin.py   # 单文件插件（PluginBase 子类）
│   ├── spring/
│   └── common/
└── examples/                  # nuclei 模板（可选）
```

## 发布流程

```bash
# 1. 导出插件源码 + 元信息
python main.py --plugin-export ./ruoyi-scan-templates

# 2. 生成 manifest.json（自动 Ed25519 签名）
#    首次执行自动生成签名密钥：~/.ruoyi-scan/signing.key（私钥）+ signing.pub（公钥）
#    私钥严禁入库！只发布 .pub 公钥给使用者校验
python main.py --plugin-manifest ./ruoyi-scan-templates

# 3. 校验（模拟消费者视角）
python main.py --plugin-manifest ./ruoyi-scan-templates   # 重复执行即校验模式

# 4. 提交仓库（manifest.json + plugins/ + 公钥 signing.pub）
git add . && git commit -m "feat: 发布插件仓库 v1.0.0"
```

## 消费者流程

```bash
# 安装/更新（默认官方仓库 URL 见 config/settings.py PLUGIN_REPO_URL）
python main.py --plugin-update https://github.com/owner/repo/archive/refs/heads/main.zip

# 校验公钥（供应链防护）：把发布者的 signing.pub 放到 ~/.ruoyi-scan/signing.pub
# 有公钥 → 强制验签，失败拒绝安装
# 无公钥 → 仅 SHA256 摘要校验（防篡改，黄色提示未验签）
```

## 安全模型

| 层级 | 校验 | 失败行为 |
|------|------|----------|
| 摘要 | manifest.json 内 SHA256 逐文件比对 | 拒绝安装 |
| 签名 | Ed25519（cryptography 可选） | 有公钥时拒绝安装 |
| 代码 | 安装目录插件经 loader 白名单加载（仅 PluginBase 子类） | 自动跳过 |

## 安全注意事项

- 私钥 `signing.key` 是发布身份的根凭据，**绝不可提交到仓库**
- 建议发布者用独立机器/CI secret 管理私钥
- 消费者只信任自己放置的 `~/.ruoyi-scan/signing.pub`
- 插件仍是可执行 Python 代码：安装前请人工审查（`--plugin-list` 可枚举已加载插件）
