# 链 1：SQL注入 → 文件读取配置 → 定时任务 RCE
#
# 攻击链路：
#   1. SQL 注入（/system/role/list dataScope 参数）提取数据库名
#   2. 任意文件读取（/common/download/resource）获取 application.yml 配置凭证
#   3. 定时任务 RCE（/monitor/job）验证接口未授权访问
#
# 失败策略：
#   - 步骤 1 失败 → abort（SQL 注入是链路起点，失败则整链无意义）
#   - 步骤 2 失败 → continue（配置读取失败不影响 RCE 验证）
#   - 步骤 3 失败 → continue（RCE 验证失败不影响前两步的已得信息）
from core.chain import ChainDef, ChainStep
from plugins.chain.sql_to_rce_steps import ConfigReadPlugin, JobRCEVerifyPlugin, SQLInjectExtractPlugin

CHAIN = ChainDef(
    name="ruoyi_sql_to_rce",
    display_name="SQL注入 → 文件读取配置 → 定时任务 RCE",
    description="通过 SQL 注入提取数据库名，任意文件读取获取配置凭证，验证定时任务 RCE 接口未授权",
    severity="high",
    affected_versions=">=4.0,<4.7",
    meta={
        "chain_type": "sql_to_rce",
        "references": [
            "SQL注入 /system/role/list dataScope 参数",
            "任意文件读取 /common/download/resource resource 参数",
            "定时任务 RCE /monitor/job invokeTarget 字段",
        ],
    },
    steps=[
        # 步骤 1：SQL 注入提取数据库名（链路起点，失败则 abort）
        ChainStep(
            id="sql_inject",
            plugin_cls=SQLInjectExtractPlugin,
            on_fail="abort",
            description="SQL 注入提取数据库名",
            outputs={
                "db_name": "extra:db_name",
            },
        ),
        # 步骤 2：配置文件读取（失败 continue，不影响 RCE 验证）
        ChainStep(
            id="config_read",
            plugin_cls=ConfigReadPlugin,
            depends_on=["sql_inject"],
            on_fail="continue",
            description="读取 application.yml 提取数据库和 Redis 密码",
            outputs={
                "db_password": "secret:db_password",
                "redis_password": "secret:redis_password",
            },
        ),
        # 步骤 3：定时任务 RCE 验证（失败 continue，不影响前两步已得信息）
        ChainStep(
            id="job_rce",
            plugin_cls=JobRCEVerifyPlugin,
            depends_on=["sql_inject"],
            on_fail="continue",
            description="验证定时任务接口未授权访问和 RCE 风险",
            outputs={
                "job_endpoint": "extra:job_endpoint",
            },
        ),
    ],
)
