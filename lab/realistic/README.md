# RuoYi Realistic Lab — 行为级若依仿真靶场

> **用途**：让扫描器**不能靠字符串签名蒙对**，必须真的走若依的登录 / 验证码 /
> 会话 / 权限路径去验证。`vuln` 与 `safe` 两套语义通过 `LAB_PROFILE` 切换。
>
> ⚠️ 仅用于本机 / 授权测试环境。默认绑定 `127.0.0.1`，严禁暴露到公网。
> 本服务不实现任何真实漏洞利用；`invokeTarget` 的「执行」仅记录在内存。

---

## 1. 快速启动

```bash
# bash / git-bash
LAB_PROFILE=vuln LAB_PORT=8090 python lab/realistic/server.py
LAB_PROFILE=safe LAB_PORT=8091 python lab/realistic/server.py

# PowerShell
$env:LAB_PROFILE="vuln"; $env:LAB_PORT="8090"; .venv\Scripts\python.exe lab\realistic\server.py
```

| 环境变量 | 默认值 | 说明 |
|---|---|---|
| `LAB_PROFILE` | `vuln` | `vuln`（漏洞语义）/ `safe`（已修复语义） |
| `LAB_PORT` | `8090` | 监听端口 |
| `LAB_HOST` | `127.0.0.1` | 监听地址 |

依赖：标准库 + Flask；绘制验证码时优先使用 Pillow，缺失或失败会自动降级为 1x1 PNG。

---

## 2. 真实登录流程（必须按若依交互路径走）

| 步骤 | 请求 | 行为 |
|---|---|---|
| 1 | `GET /login`（或 `GET /`） | 返回约 5.2 KB 仿若依登录页，含 `若依`、`/captcha/captchaImage`、`Copyright © 2018-2024 ruoyi.vip`；下发 `JSESSIONID`，页面内嵌隐藏字段 `uuid=<sid>` |
| 2 | `GET /captcha/captchaImage` | 默认 `image/png`（Pillow 绘制 4 位数字），验证码写入服务端会话；带 `Accept: application/json`、`X-Requested-With: XMLHttpRequest` 或 `?format=json` 时返回 `{"code":200,"img":"<base64>","uuid":"<sid>"}` |
| 3 | `POST /login`（form: `username,password,code,uuid`） | 验证码错 → `{"code":500,"msg":"验证码错误"}`；账号密码错 → `{"code":500,"msg":"用户不存在/密码错误"}`；`admin/admin123` + 正确验证码 → `{"code":200,"msg":"操作成功"}` 并标记会话已认证 |

- 未认证访问受保护接口：**vuln 与 safe 一致**，返回 HTTP 200 +
  `{"code":401,"msg":"认证失败，无法访问系统资源"}`，不会直接返回业务数据。
- `/common/download/resource` 与真实若依一致，属于 anon 端点（无需登录）。
- `/common/upload`、`/tool/gen/edit`、`/system/**`、`/monitor/job/list` 需要登录。
- `/monitor/job/edit`、`/monitor/job/run` 在 `vuln` 下保留历史越权点：未认证也返回 200。

### 测试钩子（仅供自测脚本 / 人工调试）

| 端点 | 说明 |
|---|---|
| `GET /__lab/health` | `{"profile":"vuln|safe","ok":true}`，不做 20–80ms 抖动 |
| `GET /__lab/session` | 返回当前会话的 `authenticated` 与 `captcha`（供无 OCR 的自测脚本使用） |
| `GET /__lab/executed` | 返回 `vuln` 下记录的 `invokeTarget`「已执行」列表；`safe` 恒为空 |

> 这些钩子不参与漏洞判定，部署到任何非本机环境前应移除或加访问控制。

---

## 3. 漏洞语义矩阵（vuln / safe）

| # | 端点 | `vuln` 语义 | `safe` 语义 | 期望三态 |
|---|---|---|---|---|
| 1 | `POST /system/role/list`、`POST /system/dept/list` | `params[dataScope]` 含 `extractvalue`/`updatexml` → HTTP 200 + `XPATH syntax error`；无载荷 → 正常 `{"total":2,"rows":[...]}` | 带载荷也返回正常列表，无 `XPATH` | 必须做「载荷 vs 基线」差分：vuln → `CONFIRMED`，safe → `SAFE`；只看单次响应不足以判定 |
| 2 | `GET /common/download/resource?resource=...` | 含 `../` 且目标为 `/etc/passwd` 或 `2.txt` → 200 + 真实格式文件内容；否则 400 | 一律 400 | vuln → `CONFIRMED`，safe → `SAFE` |
| 3 | `POST /common/upload`（需登录） | `.jsp/.jspx` 等可执行扩展名 → `{"code":0,"fileName":...,"url":"/profile/upload/..."}`；其它扩展 → `{"code":500,"msg":"文件类型不允许"}` | 可执行扩展名 → `{"code":500,"msg":"文件类型不允许"}` | vuln → `CONFIRMED`，safe → `SAFE` |
| 4 | `GET|POST /monitor/job/edit`、`/monitor/job/run` | 需登录 + `monitor:job:edit`；但**未认证也返回 200 + 操作成功**（历史越权点）；`invokeTarget` 含 `getRuntime().exec` / `new java.lang.ProcessBuilder` 时记录「已执行」 | 未认证一律 `code=401`；已登录提交执行载荷 → 500「调用目标字符串不在白名单内」 | vuln 未认证 → `CONFIRMED`（未授权访问）；safe → `SAFE` |
| 5 | `GET|POST /tool/gen/edit`（需登录） | `template`/`content` 含 `${7*7}` 或 `T(java.lang.Runtime)` → HTTP 500 且响应体含渲染结果 `49` | 原样转义返回，不含 `49` | vuln → `CONFIRMED`，safe → `SAFE` |
| 6 | `GET /druid/index.html`、`GET /druid/websession.json` | 控制台登录页；`websession.json` 未认证可读，含 `SESSIONID` 会话列表 | `index.html` 302 到 `/login`；`websession.json` 401 且无 `SESSIONID` | vuln → `CONFIRMED`，safe → `SAFE` |
| 7 | `GET /nacos/v1/cs/configs?dataId=...&group=...` | 200 + 配置 JSON，含 `spring.datasource.password` 假值 | 403，无任何凭据字段 | vuln → `CONFIRMED`，safe → `SAFE` |

### 三态判定的关键点

- **先登录再判定**：1/3/5/6(部分) 需要真实登录。扫描器若不能完成验证码 + 登录，
  受保护接口会返回 `code=401`，此时正确结论是 `UNKNOWN`，而不是 `SAFE` 或 `CONFIRMED`。
- **差分判定**：SQLi 必须比较「带载荷」与「基线」；只在带载荷时出现 `XPATH` 才算成立。
- **条件判定**：SSTI 只在 `${7*7}` / `T(java.lang.Runtime)` 出现时回显 `49`；普通模板不报错。
- **`safe` 特征扫描**：`safe` 下不会出现 `XPATH`、`root:x:0:0`、`SESSIONID`、
  `49` 回显、Nacos `password` 等可利用特征。

---

## 4. 真实感细节

- 未知路径返回 nginx 风格 404（HTTP 404，body 约 271 字节）。
- `Server: nginx/1.24.0`，不暴露 Flask / Werkzeug；无 `X-Powered-By`。
- 登录页 / 后台首页 >1 KB 时按 `Accept-Encoding` 做 gzip。
- 每个非 health 请求随机抖动 20–80ms。
- `/favicon.ico` 返回若依官方 favicon 原始字节，md5 为
  `e49fd30ea870c7a820464ca56a113e6e`（与 `core/fingerprint_features.py` 一致）。
- 访问日志输出到 stderr。

---

## 5. 与签名靶场（`lab/server.py`）的差别

| 维度 | 签名靶场 | Realistic Lab |
|---|---|---|
| 认证 | 无真实会话 / 验证码 | 真实 `JSESSIONID` + 验证码 + 登录流程 |
| 漏洞成立条件 | 多数端点直接返回固定签名 | SQLi 需载荷、SSTI 需表达式、上传需扩展名、job 需未授权或执行载荷 |
| 未认证语义 | 部分端点直接给业务数据 | 受保护接口统一 `code=401`，不泄露业务数据 |
| HTTP 细节 | Flask 默认 404 / Server 头 | nginx 404 / nginx Server 头 / gzip / 抖动 / 官方 favicon |
| 适用 | 插件匹配逻辑对拍 | 行为级验证、认证链、差分判定、误报控制 |

---

## 6. 已知限制

- **favicon 不是 16x16 PNG**：若依官方 favicon 是 16958 字节的 `.ico`，其 md5 才是扫描器
  指纹库使用的值。若要同时满足「16x16 PNG」与「md5 与官方一致」在密码学上不可行；
  本靶场选择返回**官方原始 ICO 字节**以命中指纹，`Content-Type: image/x-icon`。
  若资产缺失，会降级为生成的 16x16 PNG，此时 md5 不再与官方一致。
- **验证码无 OCR**：简单的 4 位数字图，但未做 OCR 友好的高对比度设计；扫描器需要具备
  验证码识别能力才能完成登录。自测脚本通过 `/__lab/session` 读取验证码，这是**测试钩子**，
  不代表扫描器能力。
- 会话、定时任务、`/__lab/executed` 均为**内存状态**，进程重启即丢失。
- 仅支持 `admin/admin123` 一个账号，没有低权账号 / 权限矩阵；因此越权测试集中在
  「未认证 → 受保护接口」与历史 job 越权点。
- Druid / Nacos 为仿真端点，不连接真实服务；文件读取 / 上传不会落盘。
- `safe` 下仍允许 `admin/admin123` + 正确验证码登录（默认口令不属于本靶场修复的 7 类漏洞）。
- `Server` 头通过覆盖 Werkzeug 开发服务器的 request handler 实现；换用其他 WSGI 服务器时
  需自行配置反向代理头。
- 登录页版权为 `2018-2024`（任务要求）。仓库旧签名靶场的注释曾提示该年份区间可能触发
  扫描器的版本推断；这是本靶场的刻意行为，用于检验版本相关 POC 的过滤逻辑。
- 本靶场不含真实漏洞利用代码；`invokeTarget` 只记录字符串，不会执行命令。
