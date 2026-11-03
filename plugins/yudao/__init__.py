# 芋道 yudao（ruoyi-vue-pro）插件包
#
# 为什么独立成包而不是塞进 plugins/ruoyi：
# 芋道虽然自称「RuoYi-Vue 全新 Pro 版本」，但它与若依是**不同的框架**——
#   - 认证：Spring Security + OAuth2（若依是 Shiro / Sa-Token）
#   - 前缀：/admin-api（若依分离版是 /prod-api）
#   - 业务码：code=0 表示成功（若依是 code=200）
#   - 多租户：内置 tenant-id 机制（若依单机版没有）
# 混在 ruoyi 包里的后果是：插件会按若依的形态去判定芋道，全线误判。
#
# 新增插件必须在此显式登记（core/loader.py 读 plugin_list，不是目录扫描）。
from plugins.yudao.druid_monitor_unauth import YudaoDruidMonitorUnauthPlugin
from plugins.yudao.tenant_unauth import YudaoTenantUnauthPlugin

plugin_list = [
    # 未授权类
    YudaoTenantUnauthPlugin,  # 租户列表匿名可读
    YudaoDruidMonitorUnauthPlugin,  # Druid 监控数据匿名可读
]
