# 插件检出能力矩阵

> 由 `scripts/verification_matrix.py` 自动生成（证据来自 lab 文档与测试源码，非人工填写）。
> 级别定义：L3 真实软件双向验证 / L2 真实响应靶场（无 marker）/ L1 签名靶场 / none 无自动化验证。

**总计 57 个插件**：L3 10 个，L2 11 个，L1 23 个，none 13 个

| 级别 | 插件 | CVE | 严重度 | 测试引用 | 已知误报 | 文件 |
|------|------|-----|--------|---------|---------|------|
| none | 默认口令登录 | N/A | high | **否** | — | `plugins/chain/defaultpw_to_webshell_steps.py` |
| none | SQL注入提取数据库名 | N/A | high | **否** | — | `plugins/chain/sql_to_rce_steps.py` |
| none | CORS 跨域配置不当 | N/A | medium | **否** | — | `plugins/common/cors_misconfig.py` |
| none | 目录遍历探测 | N/A | low | **否** | — | `plugins/common/dir_listing.py` |
| none | .env 配置文件泄露 | N/A | high | **否** | — | `plugins/common/env_leak.py` |
| none | shiro_rememberme | CVE-2016-4437 | high | **否** | — | `plugins/common/shiro_rememberme.py` |
| none | IDE/SCM 残留文件泄露 | N/A | medium | **否** | — | `plugins/common/source_leak.py` |
| none | Swagger API 文档泄露 | N/A | medium | **否** | — | `plugins/common/swagger_leak.py` |
| none | HTTP 方法探测 | N/A | low | **否** | — | `plugins/common/trace_method.py` |
| none | JeecgBoot 字典越权 | CVE-2023-1454 | medium | **否** | — | `plugins/jeecgboot/dict_unauth.py` |
| none | JeecgBoot jmreport 文件上传 | CNVD-2021-27656 | high | **否** | — | `plugins/jeecgboot/file_upload_jmreport.py` |
| none | JeecgBoot 报表未授权 | CVE-2023-1454 | medium | **否** | — | `plugins/jeecgboot/jmreport_list_unauth.py` |
| none | JeecgBoot jmreport SQL注入 | CNVD-2022-30348 | high | **否** | — | `plugins/jeecgboot/sql_inject_jmreport.py` |
| L1 | Nacos未授权访问 | N/A | high | 是 | — | `plugins/chain/nacos_to_dbcreds_steps.py` |
| L1 | 备份文件泄露 | N/A | medium | 是 | — | `plugins/common/backup_scan.py` |
| L1 | .git 源码泄露 | N/A | high | 是 | — | `plugins/common/git_leak.py` |
| L1 | MinIO 未授权访问 | CVE-2023-28432 | medium | 是 | — | `plugins/common/minio_unauth.py` |
| L1 | Redis 未授权访问 | CVE-2021-32761 | high | 是 | — | `plugins/common/redis_unauth.py` |
| L1 | RocketMQ Dashboard 未授权 | CVE-2023-33246 | medium | 是 | — | `plugins/common/rocketmq_unauth.py` |
| L1 | JeecgBoot 默认口令 | N/A | medium | 是 | — | `plugins/jeecgboot/default_password.py` |
| L1 | JeecgBoot 任意文件读取 | CNVD-2022-39817 | high | 是 | — | `plugins/jeecgboot/file_read_download.py` |
| L1 | JeecgBoot 报表 SSTI | CVE-2022-26809 | high | 是 | — | `plugins/jeecgboot/freemarker_ssti.py` |
| L1 | JeecgBoot queryUserByDepId SQL注入 | CVE-2022-44153 | high | 是 | — | `plugins/jeecgboot/sql_inject_query_user.py` |
| L1 | 重置密码页数据权限绕过 | CVE-2025-46174 | high | 是 | — | `plugins/ruoyi/cve_2025_46174_resetpwd_scope.py` |
| L1 | 部门树越权访问 | CVE-2025-70986 | medium | 是 | — | `plugins/ruoyi/cve_2025_70986_select_dept_tree.py` |
| L1 | 后台默认口令（admin/admin123） | N/A | high | 是 | — | `plugins/ruoyi/default_password.py` |
| L1 | 目录扫描 | N/A | low | 是 | — | `plugins/ruoyi/directory_scan.py` |
| L1 | Druid 弱口令爆破 | N/A | high | 是 | — | `plugins/ruoyi/druid_brute.py` |
| L1 | RuoYi-Plus 认证接口探测 | N/A | low | 是 | — | `plugins/ruoyi/plus_auth_login.py` |
| L1 | RuoYi-Plus 定时任务未授权 | N/A | high | 是 | — | `plugins/ruoyi/plus_job_unauth.py` |
| L1 | RuoYi-Cloud Nacos 配置泄露 | CVE-2021-29441 | high | 是 | — | `plugins/ruoyi/ruoyi_cloud_nacos.py` |
| L1 | RuoYi 代码生成模块 SSTI | N/A | high | 是 | — | `plugins/ruoyi/ruoyi_gen_rce.py` |
| L1 | RuoYi Swagger 未授权访问 | N/A | medium | 是 | — | `plugins/ruoyi/ruoyi_swagger_unauth.py` |
| L1 | Spring Boot Admin 未授权访问 | N/A | medium | 是 | — | `plugins/spring/spring_boot_admin.py` |
| L1 | Spring Cloud Config 路径穿越 | CVE-2020-5410 | high | 是 | — | `plugins/spring/spring_cloud_config.py` |
| L1 | Spring Data REST 信息泄露 | N/A | low | 是 | — | `plugins/spring/spring_data_rest.py` |
| L2 | Spring Boot Actuator env 配置覆盖 RCE | N/A | high | 是 | — | `plugins/spring/actuator_env_rce.py` |
| L2 | Spring Boot Actuator 未授权访问 | N/A | medium | 是 | — | `plugins/spring/actuator_unauth.py` |
| L2 | CVE-2022-22963 Spring Cloud Function 远程代码执行 | CVE-2022-22963 | high | 是 | — | `plugins/spring/cloud_function_rce.py` |
| L2 | CVE-2022-22947 Spring Cloud Gateway 远程代码执行 | CVE-2022-22947 | high | 是 | — | `plugins/spring/gateway_rce.py` |
| L2 | Spring Boot Actuator H2 Console 未授权 JNDI RCE | N/A | high | 是 | — | `plugins/spring/h2_console_rce.py` |
| L2 | Spring Boot Actuator heapdump 敏感信息泄露 | N/A | medium | 是 | — | `plugins/spring/heapdump_leak.py` |
| L2 | Spring Boot Actuator Jolokia MLet 链远程代码执行 | N/A | high | 是 | — | `plugins/spring/jolokia_mlet_rce.py` |
| L2 | Spring Boot Actuator Jolokia 远程代码执行 | N/A | high | 是 | — | `plugins/spring/jolokia_rce.py` |
| L2 | Spring Boot Actuator /mappings 路由映射泄露 | N/A | medium | 是 | — | `plugins/spring/mappings_leak.py` |
| L2 | CVE-2022-22965 Spring4Shell 远程代码执行 | CVE-2022-22965 | high | 是 | — | `plugins/spring/spring4shell.py` |
| L2 | Spring Boot Actuator /trace 请求历史泄露 | N/A | medium | 是 | — | `plugins/spring/trace_leak.py` |
| L3 | 任意文件读取 | CNVD-2021-01931 | high | 是 | — | `plugins/ruoyi/file_read.py` |
| L3 | 任意文件读取（路径穿越） | CNVD-2021-01931 | high | 是 | — | `plugins/ruoyi/file_read_path.py` |
| L3 | 任意文件上传 | N/A | high | 是 | — | `plugins/ruoyi/file_upload.py` |
| L3 | 定时任务调用目标未校验 | N/A | high | 是 | — | `plugins/ruoyi/job_invoke_target.py` |
| L3 | 定时任务 RCE（未授权访问） | N/A | high | 是 | — | `plugins/ruoyi/job_rce.py` |
| L3 | Nacos 未授权访问 | CVE-2021-29441 | medium | 是 | — | `plugins/ruoyi/nacos_unauth.py` |
| L3 | POST型报错注入（dept） | CNVD-2021-01931 | high | 是 | — | `plugins/ruoyi/sql_inject_dept.py` |
| L3 | POST型报错注入（role） | CNVD-2021-01931 | high | 是 | — | `plugins/ruoyi/sql_inject_role.py` |
| L3 | Thymeleaf/SpEL 模板注入 | CVE-2023-38286 | high | 是 | — | `plugins/ruoyi/thymeleaf_ssti.py` |
| L3 | 未授权访问（批量） | N/A | medium | 是 | — | `plugins/ruoyi/unauth_batch.py` |

