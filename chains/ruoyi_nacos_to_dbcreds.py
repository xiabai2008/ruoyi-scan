# 链 3：Nacos 未授权 → 配置泄露 → 数据库凭证
#
# 攻击链路：
#   1. Nacos 未授权访问验证（/nacos/v1/auth/users 接口无认证）
#   2. 拉取配置并提取数据库凭证（/nacos/v1/cs/configs）
#
# 失败策略：
#   - 步骤 1 失败 → abort（Nacos 不可访问则配置泄露无意义）
#   - 步骤 2 失败 → continue（即使未提取到凭证，未授权访问本身就是漏洞）
from core.chain import ChainDef, ChainStep
from plugins.chain.nacos_to_dbcreds_steps import NacosConfigExtractPlugin, NacosUnauthPlugin

# 变量名 CHAIN 是 registry 的注册契约（链定义模块须导出同名变量），改名会破坏惰性加载
CHAIN = ChainDef(
    name="ruoyi_nacos_to_dbcreds",
    display_name="Nacos 未授权 → 配置泄露 → 数据库凭证",
    description="利用 Nacos 未授权访问拉取配置，正则提取数据库凭证",
    severity="high",
    affected_versions="全版本（Nacos 未开启认证时）",
    meta={
        "chain_type": "nacos_to_dbcreds",
        "references": [
            "Nacos 认证绕过 CVE-2021-29441（User-Agent 白名单绕过）",
            "配置接口 /nacos/v1/cs/configs",
        ],
    },
    steps=[
        # 步骤 1：Nacos 未授权访问（链路起点，失败则 abort）
        ChainStep(
            id="nacos_unauth",
            plugin_cls=NacosUnauthPlugin,
            on_fail="abort",
            description="检测 Nacos 未授权访问",
            # 输出约定：secret: 前缀 → 凭证类（脱敏存储）；extra: 前缀 → 附加事实
            outputs={
                "nacos_url": "extra:nacos_url",
            },
        ),
        # 步骤 2：配置提取（失败 continue，未授权访问本身已是漏洞）
        ChainStep(
            id="config_extract",
            plugin_cls=NacosConfigExtractPlugin,
            depends_on=["nacos_unauth"],
            on_fail="continue",
            description="拉取 Nacos 配置并提取数据库凭证",
            outputs={
                # 数据库地址与用户名同属凭证类：chains 的 facts 不做脱敏且会被 CLI/报告原样输出，
                # 而 db_url 可能内嵌 ?user=x&password=y，故一并走 secret: 前缀（与 db_password 一致）
                "db_url": "secret:db_url",
                "db_username": "secret:db_username",
                "db_password": "secret:db_password",
            },
        ),
    ],
)
