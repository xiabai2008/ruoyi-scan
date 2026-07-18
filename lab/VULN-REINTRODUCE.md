# RuoYi 4.7.8 漏洞重引入指南（Tier B 真实靶场）

> 用途：在本地真实 RuoYi 4.7.8 环境（`lab/real-ruoyi`）中，按漏洞类别回退官方修复，制造对应的「漏洞态（VULN）」，从而对扫描器做**真实利用级验证**。
> 前提：已完成 SAFE baseline 构建与运行（官方原版，扫描器对拍应**全 SAFE / 零误报**）。
> 红线：所有修改仅限本地靶场，禁止对外网络使用；回退后需重新 `mvn clean package` 并重启。

---

## 0. 回退后的标准操作流

```bash
# 1) 按第 1~5 节修改源码
# 2) 重新构建
cd lab/real-ruoyi
"/d/maven388/bin/mvn.cmd" clean package -DskipTests -Dmaven.test.skip=true
# 3) 停掉旧 jar，启动新 jar（端口 8080）
# 4) 用扫描器对拍：python main.py -u http://127.0.0.1:8080
#    对应插件应 CONFIRMED；改回官方后再构建则 SAFE
```

---

## 1. 后台任意文件上传（/common/upload）

### 安全实现位置
- 入口：`ruoyi-admin/.../web/controller/common/CommonController.java:76` `@PostMapping("/upload")`
- 白名单：`ruoyi-common/.../utils/file/MimeTypeUtils.java:29-39` `DEFAULT_ALLOWED_EXTENSION`
- 校验：`ruoyi-common/.../utils/file/FileUploadUtils.java:205-215` `isAllowedExtension(...)`

### 回退方法（二选一）
**A. 白名单追加脚本后缀**（MimeTypeUtils.java:29-39）：
```java
"mp4", "avi", "rmvb", "pdf",
"jsp", "jspx" };   // ← 新增，允许脚本后缀
```
**B. 取消校验**（FileUploadUtils.java:205）：
```java
public static final boolean isAllowedExtension(String extension, String[] allowedExtension)
{
    return true;   // ← 任意后缀可上传
}
```

### 对拍说明
扫描器 `file_upload` 插件判定基于上传响应中的 `url` / `fileName` 字段（CommonController:88-91 返回）。回退后上传 `.jsp` 成功即返回 `url`，插件判 **CONFIRMED**。
> 真实 Webshell 执行需 Spring Boot 将 `D:/ruoyi/uploadPath` 映射为 JSP 可解析路径（默认内嵌 Tomcat 不解析 upload 目录），属利用环节，不影响扫描器命中判定。

---

## 2. 定时任务 RCE（/monitor/job 编辑 invokeTarget）

### 安全实现位置
- 控制器校验：`ruoyi-quartz/.../controller/SysJobController.java:156-159`（addSave）、`:204-207`（editSave）白名单分支
- JNDI/危险调用拦截：同上 `:140-155`（addSave）、`:188-203`（editSave）
- 白名单逻辑：`ruoyi-quartz/.../util/ScheduleUtils.java:128-140` `whiteList(...)`
- 白名单常量：`ruoyi-common/.../constant/Constants.java:108` `JOB_WHITELIST_STR = {"com.ruoyi"}`
- 反射执行点：`ruoyi-quartz/.../util/JobInvokeUtil.java:23-63` `invokeMethod(...)`

### 回退方法（推荐 A）
**A. 注释白名单分支**：删除 `SysJobController.java` 的 `:156-159` 与 `:204-207` 整段（或改 `if(false)`）。
**B. 放开 JNDI 利用链**：同时注释 `:140-155`、`:188-203` 的 `LOOKUP_RMI/LDAP/LDAPS/HTTP/HTTPS/JOB_ERROR_STR` 拦截，可提交 `com.sun.rowset.JdbcRowSetImpl` 之类利用链。
**C. 扩大白名单**：`Constants.java:108` 改为 `JOB_WHITELIST_STR = {"com","java","javax"}`。

### 对拍说明
扫描器 `job_rce` 插件打 `/monitor/job/edit`（未授权），回退后该接口不再校验 `invokeTarget`，业务层进入 `code:200`，插件判 **CONFIRMED**。真实利用：`invokeTarget=com.ruoyi.xxx.Bean.method()` 或 RMI/LDAP 链。

---

## 3. SQL 注入（/system/role/list、/system/dept/list）

### 安全实现位置
- `ruoyi-system/.../resources/mapper/system/SysRoleMapper.xml:43` `#{}` 参数化（唯一 `${}` 在 `:61` 的 `${params.dataScope}`，由切面注入非用户输入）
- `ruoyi-system/.../resources/mapper/system/SysDeptMapper.xml:48` `#{}` 参数化
- `dataScope` 防护：`ruoyi-framework/.../aspectj/DataScopeAspect.java:163-171` `clearDataScope` 每次清空外部传入
- 排序注入防护：`ruoyi-common/.../utils/sql/SqlUtil.java:21` `SQL_PATTERN` 正则校验；`BaseController.java:68-71` 包裹 `escapeOrderBySql`

### 回退方法
**A. 改 #{} 为 ${}**（最直接）：
- `SysRoleMapper.xml:43` → `AND r.role_name like '%${roleName}%'`
- `SysDeptMapper.xml:48` → `AND dept_name like '%${deptName}%'`
**B. 放开 orderBy 注入**：`SqlUtil.java:21` `SQL_PATTERN` 改为 `".*"`；或 `BaseController.java:70` 直接 `PageHelper.orderBy(pageDomain.getOrderBy())`。
**C. 放开 dataScope**：删除 `DataScopeAspect.java:163-171` 的清空逻辑，允许前端传入 `params[dataScope]`。

### 对拍说明
扫描器 `sql_inject_role` / `sql_inject_dept` 插件发送 `extractvalue` 报错注入 Payload，回退 `${}` 后触发 SQL 异常含 `extractvalue` 特征，插件判 **CONFIRMED**。

---

## 4. Thymeleaf / SpEL 模板注入

### 安全实现位置
- 4.7.8 默认：所有 `@Controller` 返回**视图名字符串**，没有任何控制器把 HTTP 请求参数直接作为视图名，故默认不存在 SpEL 注入。
- 典型视图渲染：`ruoyi-admin/.../resources/templates/` 下模板；`SysJobController.java:48` `return "monitor/job"`。

### 回退方法
新增一个控制器，使请求参数直接作为视图名返回：
```java
@GetMapping("/preview")
public String preview(@RequestParam("page") String page) {
    return page;   // ← 用户输入直接作为 Thymeleaf 视图名
}
```
访问 `/preview?page=__${T(java.lang.Runtime).getRuntime().exec("calc")}__::.x` 即触发表达式预处理 → SpEL RCE。

### 对拍说明
扫描器 `thymeleaf_ssti` 插件发送 `${...}` / `__${...}__::.x` 候选路径，回退后视图名解析执行 SpEL 返回求值结果（如 `43` 或命令输出），插件判 **CONFIRMED**。

---

## 5. 未授权访问（Druid / Swagger / 后台接口）

### 安全实现位置
- `ruoyi-framework/.../config/ShiroConfig.java:267-314` 过滤链；`:310` 兜底 `/** -> user`（未登录跳登录）。
- 4.7.8 中 `/druid/**`、`/swagger-ui/**`、`/monitor/**`、`/system/**` **均不在 anon 列表**，受 `/** -> user` 拦截。
- Druid 监控：`application-druid.yml:44-51` `statViewServlet` 登录 `ruoyi/123456`（即使绕过 Shiro 仍需该口令）。
- 数据接口还带 `@RequiresPermissions(...)`，即便设 anon 仍会被权限注解拒绝。

### 回退方法
在 `ShiroConfig.java:296` 之后、`:310` 兜底之前插入：
```java
filterChainDefinitionMap.put("/druid/**", "anon");
filterChainDefinitionMap.put("/swagger-ui/**", "anon");
filterChainDefinitionMap.put("/monitor/**", "anon");
filterChainDefinitionMap.put("/system/**", "anon");
```
或直接将 `:310` 改为 `filterChainDefinitionMap.put("/**", "anon");` 全站匿名。
> 让 `/system/*`、`/monitor/*` 真正未授权可访问，需同时注释对应 Controller 的 `@RequiresPermissions` 注解（如 `SysJobController`、`SysRoleController`）。

### 对拍说明
扫描器 `unauth_batch` 插件对 Druid/Swagger/后台路径发未授权请求，回退 anon 后这些端点直接返回 200 + 特征关键字，插件判 **CONFIRMED**。Druid 监控后台（`ruoyi/123456`）由 `default_password` 插件命中。

---

## 6. 快速回退对照表

| 漏洞 | 回退关键文件:行 | 回退动作 | 扫描器命中插件 |
|---|---|---|---|
| 任意文件上传 | `MimeTypeUtils.java:29-39` | 白名单加 `jsp/jspx` 或 `isAllowedExtension` 恒 true | `file_upload` |
| 定时任务 RCE | `SysJobController.java:156,204` | 删除/注释白名单分支 | `job_rce` |
| SQL 注入 | `SysRoleMapper.xml:43`、`SysDeptMapper.xml:48` | `#{}`→`${}` | `sql_inject_role/dept` |
| Thymeleaf/SpEL | 任意 `@Controller` 视图名返回 | 让请求参数作视图名 | `thymeleaf_ssti` |
| 未授权访问 | `ShiroConfig.java:296→310` | 插入 `xxx/** -> anon` | `unauth_batch` / `default_password` |

> 所有修改定位均来自实际源码读取。回退后务必重新构建并重启，再用 `python main.py -u http://127.0.0.1:8080` 对拍。
