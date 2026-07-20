# 若依插件包：plugin_list 声明本包插件类（保持执行顺序）
# Step 2（无损迁移）：path_scan → poc_scan(file_read / file_read_time / sql_inject_role / sql_inject_dept) → web_login
# Step 5（专项补齐）：vuln 类追加 file_upload / job_rce / thymeleaf_ssti / unauth_batch；brute 类追加 default_password
# Step 8（阶段八扩充）：vuln 类追加 file_read_path（high）/ nacos_unauth（medium）
from plugins.ruoyi.default_password import DefaultPasswordPlugin
from plugins.ruoyi.directory_scan import DirectoryScanPlugin
from plugins.ruoyi.druid_brute import DruidBrutePlugin
from plugins.ruoyi.file_read import FileReadPlugin
from plugins.ruoyi.file_read_path import RuoyiFileReadPathPlugin
from plugins.ruoyi.file_read_time import FileReadTimePlugin
from plugins.ruoyi.file_upload import FileUploadPlugin
from plugins.ruoyi.job_rce import JobRcePlugin
from plugins.ruoyi.nacos_unauth import RuoyiNacosUnauthPlugin
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
    FileReadTimePlugin,  # 定时任务任意文件读取
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
]
