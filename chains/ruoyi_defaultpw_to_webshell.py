# 链 2：默认口令 → 登录链 → 任意文件上传 → webshell
#
# 攻击链路：
#   1. 默认口令登录（admin/admin123 等）获取登录凭证
#   2. 任意文件上传验证（/common/upload 接口可上传 JSP 文件）
#
# 失败策略：
#   - 步骤 1 失败 → abort（无法登录则文件上传接口不可达）
#   - 步骤 2 失败 → continue（仅验证，不影响登录成功的结论）
#
# 安全约束：本链仅验证可利用性，不实际上传真实 webshell。
from core.chain import ChainDef, ChainStep
from plugins.chain.defaultpw_to_webshell_steps import DefaultPasswordLoginPlugin, FileUploadVerifyPlugin

# 变量名 CHAIN 是 registry 的注册契约（链定义模块须导出同名变量），改名会破坏惰性加载
CHAIN = ChainDef(
    name="ruoyi_defaultpw_to_webshell",
    display_name="默认口令 → 登录链 → 任意文件上传 → webshell",
    description="利用默认口令登录，上传 JSP 探针文件验证可执行性（非真实 webshell）",
    severity="high",
    affected_versions="全版本（默认口令未修改时）",
    meta={
        "chain_type": "defaultpw_to_webshell",
        "references": [
            "默认口令 admin/admin123 或 ry/admin123",
            "文件上传 /common/upload 接口",
        ],
        "safety_note": "仅验证可利用性，不实际上传真实 webshell",
    },
    steps=[
        # 步骤 1：默认口令登录（链路起点，失败则 abort）
        ChainStep(
            id="default_login",
            plugin_cls=DefaultPasswordLoginPlugin,
            on_fail="abort",
            description="尝试 Ruoyi 常见默认口令登录",
            # 输出约定：secret: 前缀 → 凭证类（上下文 secrets 脱敏存储）；extra: 前缀 → 附加事实
            outputs={
                "login_token": "secret:login_token",
                "username": "extra:username",
            },
        ),
        # 步骤 2：文件上传验证（需登录后访问，失败 continue）
        ChainStep(
            id="file_upload",
            plugin_cls=FileUploadVerifyPlugin,
            depends_on=["default_login"],
            on_fail="continue",
            description="验证文件上传接口可上传 JSP 文件",
            outputs={
                "upload_endpoint": "extra:upload_endpoint",
                "jsp_allowed": "extra:jsp_allowed",
            },
        ),
    ],
)
