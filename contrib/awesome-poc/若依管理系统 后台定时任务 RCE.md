# 若依管理系统 后台定时任务 RCE

## 漏洞描述

若依管理系统（RuoYi）基于 Quartz 实现定时任务管理，后台「系统监控 → 定时任务」编辑接口
`/monitor/job/edit` 支持自定义 `invokeTarget`（调用目标）。在 4.7.0 版本对调用目标引入
白名单校验之前，`invokeTarget` 可被用于调用非预期的敏感方法，结合任务触发形成远程代码执行（RCE）。

此外，部分部署实例的 `/monitor/job/**` 路径鉴权配置缺失（拦截器未覆盖），使该接口可未授权直接访问，
风险面进一步扩大。

> 说明：本漏洞属于「后台功能滥用」类，利用前提是已获得后台权限；或在鉴权缺失的实例上未授权可达。

## 漏洞影响

```
RuoYi >= 4.0, < 4.7
```

## 网络测绘

```
app="若依-管理系统"
```

## 漏洞复现

### 1. 探测编辑接口可达性（非破坏性）

使用不存在的 `jobId`（99999）探测：若接口未鉴权，服务端会进入业务校验并返回「任务不存在」类业务响应；
若鉴权正常，则在拦截器层返回登录重定向或 401，不会进入业务逻辑。

```
POST /monitor/job/edit HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

jobId=99999&jobName=test&jobGroup=DEFAULT&invokeTarget=ryTask.ryParams('ry')&cronExpression=0/10 * * * * ?
```

未授权可达时响应（HTTP 200，进入业务层）：

```json
{"code": 500, "msg": "定时任务不存在"}
```

鉴权正常时响应（拦截器层）：

```
HTTP/1.1 302 Found
Location: /login
```

### 2. 利用思路（仅限授权测试）

在 4.7.0 之前，`invokeTarget` 未做调用目标白名单校验，可构造恶意调用目标写入任务，
再通过 `/monitor/job/run`（立即执行一次）触发。完整利用链请参考下方公开资料，
并在自建靶场中验证后再用于授权测试。

### 3. 官方修复

RuoYi 4.7.0 对 `invokeTarget` 引入白名单校验（拒绝 `java.lang.Runtime`、
`java.lang.ProcessBuilder` 等敏感调用目标），请升级至 4.7.0+ 并确保
`/monitor/job/**` 在拦截器鉴权范围内。

## 漏洞POC

非破坏性探测（仅验证接口未授权可达，不修改任何任务）：

```bash
curl -X POST "http://target/monitor/job/edit" \
  -d "jobId=99999&jobName=test&jobGroup=DEFAULT&invokeTarget=ryTask.ryParams('ry')&cronExpression=0/10 * * * * ?"
# 预期：响应含"定时任务不存在"类业务错误（未授权可达）/ 302 登录页（鉴权正常）
```

批量探测可使用 [ruoyi-scan](https://github.com/xiabai2008/ruoyi-scan)（若依专项扫描器）：

```bash
ruoyi-scan -p http://target/ --cms ruoyi
```

## 参考链接

- RuoYi 官方仓库与 4.7.0 版本变更：https://github.com/yangzongzhuan/RuoYi
- PeiQi 文库 - 若依管理系统：https://github.com/PeiQi0/PeiQi-WIKI-Book
- ruoyi-scan 检测插件（本 POC 来源，含三态判定实现）：
  https://github.com/xiabai2008/ruoyi-scan/blob/main/plugins/ruoyi/job_rce.py
