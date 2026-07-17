# 若依插件包：plugin_list 声明本包插件类（保持执行顺序，对齐原脚本 -u 综合扫描的调用次序）
# 原脚本顺序：path_scan → poc_scan(file_read / file_read_time / sql_inject_role / sql_inject_dept) → web_login
from plugins.ruoyi.directory_scan import DirectoryScanPlugin
from plugins.ruoyi.file_read import FileReadPlugin
from plugins.ruoyi.file_read_time import FileReadTimePlugin
from plugins.ruoyi.sql_inject_role import SqlInjectRolePlugin
from plugins.ruoyi.sql_inject_dept import SqlInjectDeptPlugin
from plugins.ruoyi.druid_brute import DruidBrutePlugin

plugin_list = [
    DirectoryScanPlugin,     # recon 目录扫描
    FileReadPlugin,          # vuln 任意文件读取
    FileReadTimePlugin,      # vuln 定时任务任意文件读取
    SqlInjectRolePlugin,     # vuln SQL 报错注入（role）
    SqlInjectDeptPlugin,     # vuln SQL 报错注入（dept）
    DruidBrutePlugin,        # brute Druid 弱口令爆破
]
