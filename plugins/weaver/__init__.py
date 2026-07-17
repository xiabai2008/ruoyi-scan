# Weaver e-cology 插件包：plugin_list 声明本包插件类（按危险度排序）
from plugins.weaver.file_upload import WeaverFileUploadPlugin
from plugins.weaver.file_download import WeaverFileDownloadPlugin
from plugins.weaver.xml_rce import WeaverXmlRcePlugin
from plugins.weaver.bsh_rce import WeaverBshRcePlugin
from plugins.weaver.sqli import WeaverSqliPlugin
from plugins.weaver.unauth import WeaverUnauthPlugin
from plugins.weaver.info_leak import WeaverInfoLeakPlugin
from plugins.weaver.xss import WeaverXssPlugin

plugin_list = [
    # vuln：高危漏洞（high）
    WeaverFileUploadPlugin,      # CNVD-2021-49104 任意文件上传 getshell
    WeaverFileDownloadPlugin,    # 任意文件下载路径穿越（与 file_upload 同路径，GET 下载）
    WeaverXmlRcePlugin,          # XMLDecoder 反序列化 RCE
    WeaverBshRcePlugin,          # Beanshell 脚本执行 RCE
    WeaverSqliPlugin,            # CNVD-2022-43245 SQL 注入
    # vuln：中危漏洞（medium）
    WeaverUnauthPlugin,          # /weaver/ 未授权访问
    WeaverInfoLeakPlugin,        # ecology.properties 配置文件泄露
    WeaverXssPlugin,             # 反射型 XSS
]
