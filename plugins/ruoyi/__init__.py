# 若依插件包：plugin_list 声明本包插件类（保持执行顺序）
# Step 2（无损迁移）：path_scan → poc_scan(file_read / file_read_time[后改名 job_invoke_target] / sql_inject_role / sql_inject_dept) → web_login
# Step 5（专项补齐）：vuln 类追加 file_upload / job_rce / thymeleaf_ssti / unauth_batch；brute 类追加 default_password
# Step 8（阶段八扩充）：vuln 类追加 file_read_path（high）/ nacos_unauth（medium）
# plugin_list：插件注册表，扫描器按声明顺序逐条执行——新增插件须在此登记，排序即执行优先级
from plugins.ruoyi.cve_2025_46174_resetpwd_scope import Cve202546174ResetPwdScopePlugin
from plugins.ruoyi.cve_2025_70986_select_dept_tree import Cve202570986SelectDeptTreePlugin
from plugins.ruoyi.default_password import DefaultPasswordPlugin
from plugins.ruoyi.directory_scan import DirectoryScanPlugin
from plugins.ruoyi.druid_brute import DruidBrutePlugin
from plugins.ruoyi.file_read import FileReadPlugin
from plugins.ruoyi.file_read_path import RuoyiFileReadPathPlugin
from plugins.ruoyi.file_upload import FileUploadPlugin
from plugins.ruoyi.job_invoke_target import JobInvokeTargetPlugin
from plugins.ruoyi.job_rce import JobRcePlugin
from plugins.ruoyi.nacos_unauth import RuoyiNacosUnauthPlugin
from plugins.ruoyi.plus_auth_login import PlusAuthLoginProbePlugin
from plugins.ruoyi.plus_job_unauth import PlusJobUnauthPlugin
from plugins.ruoyi.ruoyi_cloud_nacos import RuoyiCloudNacosPlugin
from plugins.ruoyi.ruoyi_gen_rce import RuoyiGenRcePlugin
from plugins.ruoyi.ruoyi_swagger_unauth import RuoyiSwaggerUnauthPlugin
from plugins.ruoyi.sql_inject_dept import SqlInjectDeptPlugin
from plugins.ruoyi.sql_inject_role import SqlInjectRolePlugin
from plugins.ruoyi.thymeleaf_ssti import ThymeleafSstiPlugin
from plugins.ruoyi.unauth_batch import UnauthBatchPlugin

plugin_list = [
    # recon：目录扫描（保持原 -u 综合扫描第一步）
    DirectoryScanPlugin,
    # vuln：原有 4 POC（保持原 -p 漏洞检测顺序）
    FileReadPlugin,  # 任意文件读取
    JobInvokeTargetPlugin,  # 定时任务 invokeTarget 白名单缺失（high，<4.7）
    SqlInjectRolePlugin,  # POST 型报错注入（role）
    SqlInjectDeptPlugin,  # POST 型报错注入（dept）
    # vuln：Step 5 新增专项 POC（按危险度从高到低排序）
    FileUploadPlugin,  # 任意文件上传
    JobRcePlugin,  # 定时任务 RCE 未授权访问
    ThymeleafSstiPlugin,  # Thymeleaf/SpEL 模板注入
    # vuln：Step 8 新增 POC（按危险度从高到低排序，high 在前）
    RuoyiFileReadPathPlugin,  # 文件下载路径穿越（high）
    UnauthBatchPlugin,  # 未授权访问批量检测（medium）
    RuoyiNacosUnauthPlugin,  # Nacos 未授权访问（medium）
    # brute：原有 Druid 爆破 + Step 5 新增默认口令
    DruidBrutePlugin,  # Druid 弱口令爆破
    DefaultPasswordPlugin,  # 后台默认口令 admin/admin123
    # P1-F 新增（阶段扩充 +3）
    RuoyiCloudNacosPlugin,  # RuoYi-Cloud Nacos 配置泄露（high）
    RuoyiSwaggerUnauthPlugin,  # Swagger 未授权 API 文档（medium）
    RuoyiGenRcePlugin,  # 代码生成模块 SSTI（high）
    # 多版本矩阵实测新增（2026-09-17）：认证后越权类，需「持功能权限但数据范围受限」的低权账号
    Cve202546174ResetPwdScopePlugin,  # CVE-2025-46174 重置密码页数据权限绕过（high，影响 <=4.8.0）
    Cve202570986SelectDeptTreePlugin,  # CVE-2025-70986 部门树越权访问（medium，影响 <=4.8.0）
    # F6：RuoYi-Plus 变体专项（variant='ruoyi-plus'，仅 Plus 变体目标执行）
    PlusAuthLoginProbePlugin,  # 认证服务探测（low）
    PlusJobUnauthPlugin,  # 定时任务未授权（high）
]
