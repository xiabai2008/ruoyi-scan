# 链 3：Nacos 未授权 → 配置泄露 → 数据库凭证
#
# 攻击链路：
#   1. Nacos 未授权访问验证（/nacos/v1/auth/users 接口无认证）
#   2. 拉取配置并提取数据库凭证（/nacos/v1/cs/configs）
#
# 失败策略：
#   - 步骤 1 失败 → abort（Nacos 不可访问则配置泄露无意义）
#   - 步骤 2 失败 → continue（即使未提取到凭证，未授权访问本身就是漏洞）
from core.chain import ChainStep, ChainDef
from plugins.chain.nacos_to_dbcreds_steps import (NacosUnauthPlugin,
                                                    NacosConfigExtractPlugin)

CHAIN = ChainDef(
    name='ruoyi_nacos_to_dbcreds',
    display_name='Nacos 未授权 → 配置泄露 → 数据库凭证',
    description='利用 Nacos 未授权访问拉取配置，正则提取数据库凭证',
    severity='high',
    affected_versions='全版本（Nacos 未开启认证时）',
    meta={
        'chain_type': 'nacos_to_dbcreds',
        'references': [
            'Nacos 未授权访问 CVE-2021-29441',
            '配置接口 /nacos/v1/cs/configs',
        ],
    },
    steps=[
        # 步骤 1：Nacos 未授权访问（链路起点，失败则 abort）
        ChainStep(
            id='nacos_unauth',
            plugin_cls=NacosUnauthPlugin,
            on_fail='abort',
            description='检测 Nacos 未授权访问',
            outputs={
                'nacos_url': 'extra:nacos_url',
            },
        ),
        # 步骤 2：配置提取（失败 continue，未授权访问本身已是漏洞）
        ChainStep(
            id='config_extract',
            plugin_cls=NacosConfigExtractPlugin,
            depends_on=['nacos_unauth'],
            on_fail='continue',
            description='拉取 Nacos 配置并提取数据库凭证',
            outputs={
                'db_url': 'extra:db_url',
                'db_username': 'extra:db_username',
                'db_password': 'secret:db_password',
            },
        ),
    ],
)
