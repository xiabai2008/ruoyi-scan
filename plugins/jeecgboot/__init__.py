# JeecgBoot 插件包（F5：第一个拓展框架）
# 定位：证明基建通用性——指纹/路由/三态/报告零改动接入新框架
# 覆盖：未授权（jmreport 报表/sys/dict）、SQL 注入（queryUserByDepId/jmreport）、
#       任意文件读取（/common/download）、任意文件上传（/jmreport/upload）、
#       Freemarker SSTI（/jmreport/testConnection）、默认口令
from plugins.jeecgboot.default_password import JeecgDefaultPasswordPlugin
from plugins.jeecgboot.dict_unauth import JeecgDictUnauthPlugin
from plugins.jeecgboot.file_read_download import JeecgFileReadDownloadPlugin
from plugins.jeecgboot.file_upload_jmreport import JeecgFileUploadJmreportPlugin
from plugins.jeecgboot.freemarker_ssti import JeecgFreemarkerSstiPlugin
from plugins.jeecgboot.jmreport_list_unauth import JeecgJmreportListUnauthPlugin
from plugins.jeecgboot.sql_inject_jmreport import JeecgSqlInjectJmreportPlugin
from plugins.jeecgboot.sql_inject_query_user import JeecgSqlInjectQueryUserPlugin

plugin_list = [
    # 高危优先
    JeecgFreemarkerSstiPlugin,  # Freemarker SSTI RCE（high）
    JeecgSqlInjectQueryUserPlugin,  # queryUserByDepId SQL 注入（high）
    JeecgSqlInjectJmreportPlugin,  # jmreport SQL 注入（high）
    JeecgFileUploadJmreportPlugin,  # jmreport 任意文件上传（high）
    JeecgFileReadDownloadPlugin,  # 任意文件读取（high）
    JeecgJmreportListUnauthPlugin,  # 报表未授权（medium）
    JeecgDictUnauthPlugin,  # 字典越权（medium）
    JeecgDefaultPasswordPlugin,  # 默认口令（brute）
]
