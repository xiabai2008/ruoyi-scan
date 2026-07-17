# ThinkPHP 插件包：plugin_list 声明本包插件类（保持执行顺序：按危险度从高到低）
from plugins.thinkphp.invoke_rce import ThinkphpInvokeRcePlugin
from plugins.thinkphp.method_construct_rce import ThinkphpMethodConstructRcePlugin
from plugins.thinkphp.lang_rce import ThinkphpLangRcePlugin
from plugins.thinkphp.rce_51 import Thinkphp51RcePlugin
from plugins.thinkphp.cache_write import ThinkphpCacheWritePlugin
from plugins.thinkphp.deserialize import ThinkphpDeserializePlugin
from plugins.thinkphp.debug_info import ThinkphpDebugInfoPlugin
from plugins.thinkphp.log_disclosure import ThinkphpLogDisclosurePlugin
from plugins.thinkphp.file_read import ThinkphpFileReadPlugin
from plugins.thinkphp.where_inject import ThinkphpWhereInjectPlugin
from plugins.thinkphp.request_rce_v2 import ThinkphpRequestRceV2Plugin
from plugins.thinkphp.dispatch_rce import ThinkphpDispatchRcePlugin

plugin_list = [
    # vuln：RCE 类（high）
    ThinkphpInvokeRcePlugin,          # invokefunction RCE（5.0/5.1）
    ThinkphpMethodConstructRcePlugin,  # 5.0.23 method 覆盖 RCE
    ThinkphpLangRcePlugin,            # 5.0.x 多语言 RCE（CVE-2022-25481）
    Thinkphp51RcePlugin,              # 5.1.x 路由 RCE
    ThinkphpCacheWritePlugin,         # 缓存文件包含 getshell
    ThinkphpDeserializePlugin,        # 反序列化 POP 链 RCE
    ThinkphpRequestRceV2Plugin,       # 5.0.x Request 输入 RCE 变体
    ThinkphpDispatchRcePlugin,        # 5.1.x 路由调度 invokefunction RCE
    # vuln：信息泄露类（medium）
    ThinkphpDebugInfoPlugin,           # APP_DEBUG 信息泄露
    ThinkphpLogDisclosurePlugin,       # runtime 日志文件暴露
    ThinkphpFileReadPlugin,           # 模板驱动文件读取
    ThinkphpWhereInjectPlugin,        # where 子句 SQL 注入
]
