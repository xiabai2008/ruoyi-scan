# 通用 Web 漏洞检测插件包
# 不依赖 CMS 指纹识别，对任意 Web 站点生效，始终参与扫描
# 与 CMS 插件包并行执行，不受路由过滤
from plugins.common.backup_scan import BackupScanPlugin
from plugins.common.cors_misconfig import CorsMisconfigPlugin
from plugins.common.dir_listing import DirListingPlugin
from plugins.common.env_leak import EnvLeakPlugin
from plugins.common.git_leak import GitLeakPlugin
from plugins.common.source_leak import SourceLeakPlugin
from plugins.common.swagger_leak import SwaggerLeakPlugin
from plugins.common.trace_method import TraceMethodPlugin

plugin_list = [
    # vuln：高危通用漏洞
    GitLeakPlugin,  # .git 源码泄露探测
    EnvLeakPlugin,  # .env 配置文件泄露
    BackupScanPlugin,  # 备份文件扫描
    # vuln：中危通用漏洞
    CorsMisconfigPlugin,  # CORS 跨域配置检测
    SwaggerLeakPlugin,  # Swagger/OpenAPI 文档泄露
    SourceLeakPlugin,  # IDE/SCM 残留文件泄露
    # recon：信息收集
    DirListingPlugin,  # 目录遍历探测
    TraceMethodPlugin,  # HTTP 方法探测（OPTIONS/TRACE）
]
