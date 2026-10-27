# 真实若依 4.7.8 · 生产保真靶场（lab/prod）

> **合法授权**：本目录只用于本地、隔离的扫描器对拍。所有宿主端口绑定 `127.0.0.1`，
> 内置默认口令与自签证书。**不要**改绑 `0.0.0.0`，不要放到公网，不要对未授权资产使用。
>
> 与 `lab/` 签名靶场的区别一句话：**这里跑的是官方 Java 若依 4.7.8 + MySQL 8 + nginx +
> ModSecurity CRS，不是 Python 模拟。** 跑不起来时，本目录选择如实报错，而不是降级成假服务。

---

## 1. 这套栈比签名靶场多测了什么

`lab/`（Tier A）验证的是「插件的判定逻辑是否正确」；`lab/prod`（Tier B）验证的是
「同一套判定逻辑在真实运行时、真实中间件、真实代理层上的表现」。

| 维度 | `lab/` 签名靶场 | `lab/prod` 真实栈 |
|---|---|---|
| 运行时 | Python Flask | JDK 8 + Spring Boot 2.5.15 + 内嵌 Tomcat |
| 会话/鉴权 | 手写 Cookie/响应 | Shiro 1.13.0 过滤链、`JSESSIONID`、在线会话、RememberMe |
| 登录 | 直接返回 token | 表单登录 + **kaptcha 数学验证码** + 失败锁定 |
| SQL 注入 | 字符串签名 | MySQL 8.0 真实解析/报错、JDBC 堆栈（漏洞需回退后才出现） |
| 数据库 | 无 | MySQL 8.0、真实 DDL、utf8mb4、JDBC 驱动 |
| Druid | 伪造 200 | Druid 1.2.20 真实 StatViewServlet + 独立登录口令 |
| 定时任务 | 伪造 JSON | Quartz + `sys_job` 初始化、真实调度器 |
| 上传 | 返回假 URL | Spring Multipart + 真实扩展名白名单 + 落盘 |
| 传输层 | HTTP | nginx 1.24 自签 TLS、80→443、`client_max_body_size 20m` |
| WAF | 伪造拦截页 | OWASP ModSecurity CRS v4，paranoia=1，真实规则/异常分 |
| 启动特征 | 秒级 | MySQL 初始化 + JVM 冷启动 60–180s、healthcheck 依赖链 |
| 构建 | `pip install` | Maven 多阶段构建、依赖解析、非 root JRE 运行时 |
| 误报语义 | 签名阈值 | 真实 302/401/403/500、Shiro 跳转、WAF 拦截页 |

**它测不到的东西**（先说清楚）：真实 4.7.8 已经修复了扫描器主要覆盖的 SQLi、路径穿越、
定时任务白名单；stock 档不会凭空产生 CONFIRMED。要测「检出」，需要按
[`lab/VULN-REINTRODUCE.md`](../VULN-REINTRODUCE.md) 回退对应修复后再构建。见 §6.3。

---

## 2. 拓扑

```
                         ┌──────────────────────────────┐
  scan ── https://:8443 ─▶│ nginx 1.24 (TLS, 80→443)     │──┐
                         │  └─ plain :8081 (WAF upstream)│  │
                         └──────────────────────────────┘  │
  scan ── http://:8085 ──▶ waf (CRS, profile=waf)           │
                         └── proxy ──▶ nginx:8081 ─────────┤
                                                            ▼
                         ┌─────────────────────────────────────────┐
  scan ── https://:8444 ─▶│ nginx-harden (profile=harden, 403)     │
                         └── proxy ──▶ ruoyi:8080                 │
                                                                   │
                         ┌─────────────────────────────────────────┴──┐
                         │ ruoyi:8080  (official RuoYi 4.7.8, JRE 8)  │
                         └──────────────────┬─────────────────────────┘
                                            │ JDBC
                                   ┌────────▼────────┐
                                   │ mysql:3306 (8.0)│
                                   └─────────────────┘

  redis:6379 (profile=redis) — defined for parity only; RuoYi 4.7.8 does not use it.
```

默认不发布 `ruoyi:8080` 到公网；宿主上的 `127.0.0.1:18080` 是调试直连口，
**它会绕过 nginx / harden / WAF**，不要用它做三档对照扫描。

---

## 3. 版本、端口与账号

| 组件 | 镜像 / 版本 | 容器端口 | 宿主端口（默认） |
|---|---|---|---|
| MySQL | `mysql:8.0` | 3306 | `127.0.0.1:13306` |
| Redis（可选） | `redis:7-alpine` | 6379 | `127.0.0.1:16379` |
| RuoYi | 官方 `v4.7.8`，本地多阶段构建 | 8080 | `127.0.0.1:18080` |
| nginx | `nginx:1.24-alpine` | 80 / 443 / 8081 | `127.0.0.1:8088` / `8443` |
| nginx-harden | `nginx:1.24-alpine` | 80 / 443 | `127.0.0.1:8089` / `8444` |
| WAF | `owasp/modsecurity-crs:nginx-alpine` | 8080 / 8443 | `127.0.0.1:8085` / `8445` |
| 构建 | `maven:3.8-openjdk-8` | — | — |
| 运行时 | `eclipse-temurin:8-jre` | — | — |

账号（真实上游哈希）：

| 账号 | 密码 | 说明 |
|---|---|---|
| `admin` | `admin123` | 超级管理员，`salt=111111` |
| `ry` | `admin123` | 普通角色，`salt=222222` |
| Druid 控制台 | `ruoyi` / `123456` | **先通过 Shiro 登录**后才能到达 Druid 自己的登录页 |

> **密码算法说明**：若依 4.7.8（Thymeleaf/Shiro 单体）使用
> `new Md5Hash(loginName + password + salt).toHex()`，**不是 BCrypt**。
> 种子哈希已用 `md5("admin"+"admin123"+"111111") = 29c67a…4934` 校验。
> BCrypt 属于 RuoYi-Vue（前后端分离版），不要混用。
> 验证码默认开启（`shiro.captchaEnabled=true`），所以自动化登录要么处理数学验证码，
> 要么接受扫描器的 `UNKNOWN`。

---

## 4. 快速开始

### 4.1 前置条件

- Docker Engine / Docker Desktop（Compose v2）
- 能访问 Docker Hub、Gitee/GitHub、Maven 仓库（或按 §7 做好镜像/依赖加速）
- 建议 4 GB RAM、2 CPU、4 GB 空闲磁盘
- `make`（Windows 上可用 Git Bash；没有 make 就直接执行 §4.3 的 compose 命令）
- 本地 `openssl`（Git for Windows 自带）

### 4.2 一条命令（推荐）

```bash
cd lab/prod
cp .env.example .env
make cert          # 生成 certs/server.crt|key（自签，幂等）
make config        # 静态校验 5 种 profile 组合
make up            # build + 启动（首次 10–20 分钟，主要耗在 Maven）
make smoke         # 等 /login 就绪后跑 5 个探针
```

访问：

- `https://127.0.0.1:8443/` — 浏览器会提示自签证书不受信任，继续即可
- `http://127.0.0.1:8088/` — 应 301 到上面的 HTTPS 地址
- `https://127.0.0.1:8443/druid/index.html` — 先出现若依登录页；登录 admin 后再访问 Druid
- `http://127.0.0.1:8085/` — WAF 档（先 `make up-waf`）
- `https://127.0.0.1:8444/` — harden 档（先 `make up-harden`）

### 4.3 不用 make 的等价命令

```bash
cd lab/prod
cp .env.example .env
sh certs/generate.sh

docker compose -f docker-compose.yml config -q
docker compose -f docker-compose.yml up -d --build
docker compose -f docker-compose.yml logs -f --tail=200

# 可选档
docker compose -f docker-compose.yml --profile waf up -d --build
docker compose -f docker-compose.yml --profile harden up -d --build
docker compose -f docker-compose.yml --profile redis up -d

# 冒烟
python ../../scripts/prod_smoke.py --insecure
python ../../scripts/prod_smoke.py --tier harden --base-url https://127.0.0.1:8444 --insecure
python ../../scripts/prod_smoke.py --tier waf --base-url http://127.0.0.1:8085 --insecure
```

### 4.4 首次启动为什么慢

1. `mysql:8.0` 初始化 data volume，执行 `01-schema.sql` + `02-data.sql`（约 20–40s）；
2. Maven 首次下载 Spring Boot/Shiro/Druid 等依赖（10–20 分钟，取决于网络）；
3. JVM 冷启动 + Druid 连接池 + MyBatis Mapper 扫描（60–120s）；
4. nginx 等 `ruoyi` healthy 才启动（healthcheck `start_period: 120s`）。

看到 `ruoyi-prod-app` 一直是 `health: starting` 不是故障；等 `healthy` 后再访问。

---

## 5. 三档对照

| 档位 | 入口 | 做了什么 | 不是什么 |
|---|---|---|---|
| **stock / vuln** | `:8443`（默认） | 官方 4.7.8 原版 + 默认账号 + Druid 默认口令 + 自签 TLS | 没有人为回退漏洞；4.7.8 对该扫描器的主要 POC 已修复 |
| **harden** | `:8444` | 同一 ruoyi 镜像，nginx 对 4 类端点返回 403 | 不是代码修复；`:18080` 直连可绕过 |
| **waf** | `:8085` | CRS paranoia=1，代理层拦截攻击载荷 | 不是应用层修复；拦截后应用完全收不到请求 |

### 5.1 三档的原始 HTTP 形态（`scripts/prod_smoke.py` 实测口径）

| 探针 | stock | harden | waf |
|---|---|---|---|
| `GET /login` | 200 HTML | 200 HTML | 200 HTML（CRS 放行） |
| `GET /captcha/captchaImage` | 200 image/jpeg | 200 image/jpeg | 200 image/jpeg |
| `GET /druid/index.html` | 302 → `/login` | **403** | 302 → `/login`（CRS 不针对 Druid） |
| `POST /system/role/list`（extractvalue） | 302 → `/login` | 302 → `/login`（不在 harden 清单） | **403**（CRS 942xxx） |
| `GET /common/download/resource?resource=../../../../etc/passwd` | 302 → `/login` | **403** | **403**（CRS 930xxx） |

> **重要口径修正**：题目里写「`/system/role/list` 未认证应 401 JSON」。真实若依 4.7.8 的
> `ShiroConfig` 把 `/**` 交给 `user` 过滤器，未登录返回 **302 → `/login`**；401 JSON 是
> RuoYi-Vue（JWT/前后端分离）的形态。`prod_smoke.py` 两种都识别，并在输出里明确标注
> 实际形态，不会把 302 冒充成 401。

### 5.2 期望三态结果（扫描器当前实现）

图例：**C** = CONFIRMED，**S** = SAFE，**U** = UNKNOWN。

| 插件 / 检测项 | stock | harden | waf | 依据 |
|---|---|---|---|---|
| 指纹识别（RuoYi） | **C** | **C** | **C** | `/login` 与静态资源仍可访问 |
| 后台默认口令 `admin/admin123` | **U** | **U** | **U** | 验证码开启，插件识别 `captcha` 后判 UNKNOWN |
| Druid 弱口令爆破 | **S** | **S** | **S** | `/druid/submitLogin` 被 Shiro/WAF 拦截，拿不到 `success` |
| 未授权访问（Druid/Swagger/后台） | **S** | **S** | **S** | 302/403 被当作「已保护」 |
| SQL 注入（role/dept，extractvalue） | **S** | **S** | **S** | 302/403 响应没有 MySQL 报错特征 |
| 任意文件读取（`file_read`） | **S** | **S** | **S** | 302/403 无 passwd 特征 |
| 任意文件读取（`file_read_path`） | **U** | **S** | **S** | 该插件把 302 判 UNKNOWN、403 判 SAFE |
| 定时任务 RCE（`job_rce`） | **U** | **S** | **S** | 302 判 UNKNOWN；403 判 SAFE |
| 文件上传 | **S/U** | **S/U** | **S/U** | 未认证 302；认证后扩展名白名单 |
| Thymeleaf/SpEL SSTI | **S/U** | **S/U** | **S/U** | 4.7.8 无可控视图名入口 |
| TLS / 证书 | 自签，扫描器默认不校验证书 | 同左 | 同左 | `config/settings.py: VERIFY_TLS=False` |

**这张表暴露了当前实现的一个真实边界**：

- 三档在扫描器输出上几乎无法区分。harden 的 403 与 WAF 的 403 被多个插件直接映射成
  `SAFE`，而按三态纪律，「请求被 WAF 拦截、根本没测到应用」应当是 **UNKNOWN**，不是
  「确认不存在」。本栈的最大价值就是把这条假阴性边界稳定复现出来。
- 要得到真正的 **CONFIRMED** 检出对照，必须回退官方修复（§6.3），而不是期待 stock 档。
- stock 档适合做**误报基线**：除指纹外不应出现 CONFIRMED；出现即优先怀疑插件误报。

### 5.3 理想三态（回退漏洞后）

| 插件 | stock（回退后） | harden | waf |
|---|---|---|---|
| SQLi / 文件读取 / 定时任务 RCE | **C** | **S**（403） | **U**（被拦截，未测到应用） |
| 后台默认口令 | **C**（若关闭验证码） | 同 stock | 同 stock |
| Druid 弱口令 | **C**（若登录链可绕过 Shiro） | **S**（403） | **U/S**（取决于规则） |

理想值与当前实现的差距，就是插件判定逻辑的改进清单：**403/302 不应无条件等于 SAFE**。

### 5.4 扫描器对拍命令

```bash
# 默认不校验证书（self-signed lab），不要加 --verify-tls
python main.py -p https://127.0.0.1:8443/ --report ./reports/prod-stock

python main.py -p https://127.0.0.1:8444/ --report ./reports/prod-harden

# WAF 档：先用默认策略，再用绕过策略做对照
python main.py -p http://127.0.0.1:8085/ --report ./reports/prod-waf
python main.py -p http://127.0.0.1:8085/ --bypass-waf on --report ./reports/prod-waf-bypass
```

注意：`--verify-tls` 会让自签证书目标在每个请求上 SSLError，插件按纪律降级为 UNKNOWN；
这不是本栈的预期用法。

---

## 6. 如何做检出 / 误报实验

### 6.1 误报基线（stock）

1. 确保只扫描 `https://127.0.0.1:8443/`，不要扫 `:18080`（直连口）或 `:8081`；
2. `python main.py -p https://127.0.0.1:8443/ --report ./reports/stock`；
3. 期望：指纹 CONFIRMED；默认口令 UNKNOWN（验证码）；其余不应 CONFIRMED；
4. 任何额外的 CONFIRMED 都是候选误报，在报告里保存完整证据（状态码 + 片段）。

### 6.2 加固 / WAF 档

1. `make up-harden` / `make up-waf`；
2. 用对应入口重扫；
3. 期望：harden 的四个端点为 403；WAF 对注入/穿越载荷为 403；
4. 如果仍然 CONFIRMED：先确认扫描目标端口没有绕过代理（`:18080`），再检查
   `nginx -T` / `docker compose exec waf nginx -T` 与 CRS 日志。

### 6.3 得到真正带洞的 stock 档

stock 是**官方原版**。要得到可被扫描器 CONFIRMED 的真实漏洞，按
[`lab/VULN-REINTRODUCE.md`](../VULN-REINTRODUCE.md) 对源码做最小回退，然后把源码放到
构建上下文里：

```bash
git clone --depth 1 -b v4.7.8 https://gitee.com/y_project/RuoYi.git lab/prod/ruoyi/RuoYi
# 按 VULN-REINTRODUCE.md 修改 lab/prod/ruoyi/RuoYi 下的文件
docker compose -f lab/prod/docker-compose.yml build --no-cache ruoyi
docker compose -f lab/prod/docker-compose.yml up -d
```

Dockerfile 会优先使用 `lab/prod/ruoyi/RuoYi/pom.xml`，不会再远程拉源码。
建议每次只回退一类漏洞，便于把 CONFIRMED 精确归因到插件。

---

## 7. 镜像加速与离线导入

### 7.1 症状

```text
$ docker pull hello-world
... registry-1.docker.io ... EOF
```

这是 Docker Hub 不可达，不是本栈配置错误。`docker compose up --build` 会先拉
`mysql:8.0`、`nginx:1.24-alpine`、`maven:3.8-openjdk-8`、`eclipse-temurin:8-jre` 等基础镜像，
在加速完成前会一直失败。

### 7.2 配置 registry mirror

Docker Desktop：Settings → Docker Engine，加入：

```json
{
  "registry-mirrors": [
    "https://docker.m.daocloud.io",
    "https://dockerproxy.com"
  ]
}
```

Linux：写入 `/etc/docker/daemon.json` 后 `sudo systemctl restart docker`。

> 公共镜像站经常失效/限流，上面的地址只是示例；企业环境优先用私有 registry
> 或一台能出网的构建机。改完必须重启 daemon 才生效。

### 7.3 代理

- **拉镜像**：Docker Desktop → Settings → Resources → Proxies；Linux 用 systemd
  `HTTP_PROXY/HTTPS_PROXY` drop-in。
- **构建期**（git/curl/maven 在 builder 容器内）：

```bash
docker compose -f lab/prod/docker-compose.yml build \
  --build-arg HTTPS_PROXY=http://host.docker.internal:7890 \
  --build-arg HTTP_PROXY=http://host.docker.internal:7890 \
  ruoyi
```

`.env` 里的 `HTTP_PROXY/HTTPS_PROXY` 也会作为构建参数传入。

### 7.4 Maven 依赖慢

`.env.example` 默认使用阿里云：

```dotenv
MAVEN_MIRROR=https://maven.aliyun.com/repository/public
```

置空则走 Maven Central。构建日志里出现大量 `Downloading from central` 时，先换镜像。

### 7.5 离线导入（推荐给隔离环境）

在能联网的机器上：

```bash
cd lab/prod
docker compose -f docker-compose.yml build
docker pull mysql:8.0
docker pull nginx:1.24-alpine
docker pull redis:7-alpine
docker pull owasp/modsecurity-crs:nginx-alpine

docker save -o prod-images.tar \
  ruoyi-prod-lab/ruoyi:v4.7.8 mysql:8.0 nginx:1.24-alpine \
  redis:7-alpine owasp/modsecurity-crs:nginx-alpine
```

把 `prod-images.tar` 和 `lab/prod/`（含 `certs/server.crt|key` 或重新 `make cert`）拷到离线机：

```bash
docker load -i prod-images.tar
cd lab/prod
cp .env.example .env
make cert
make up NO_BUILD=1          # 不 build，直接用已 load 的镜像
```

`eclipse-temurin:8-jre` 与 `maven:3.8-openjdk-8` 只在构建阶段用到；如果目标机只运行不构建，
不需要导入这两个。

### 7.6 手动放置源码（Gitee/GitHub 都不通）

```bash
git clone --depth 1 -b v4.7.8 https://gitee.com/y_project/RuoYi.git lab/prod/ruoyi/RuoYi
# 或解压 GitHub tag archive 到 lab/prod/ruoyi/RuoYi
docker compose -f lab/prod/docker-compose.yml build ruoyi
```

Dockerfile 检测到 `RuoYi/pom.xml` 后直接使用本地树；`.dockerignore` 已排除 `.git` 与
`target/`。

---

## 8. 资源消耗与耗时

| 项 | 估算 |
|---|---|
| 运行时内存 | MySQL 400–600 MB；RuoYi JVM 600–900 MB（`-Xmx512m`）；nginx ~20 MB；WAF 100–200 MB |
| 建议宿主 | 4 GB RAM / 2 CPU 起；同时开 waf + harden 建议 6 GB |
| 镜像磁盘 | MySQL ~600 MB、Temurin ~250 MB、Maven builder ~500 MB、WAF ~400 MB、nginx ~50 MB |
| 构建缓存 + Maven 依赖 | 1–2 GB（首次构建后） |
| 数据卷 | MySQL 初始化后 ~200 MB；上传/日志随使用增长 |
| 首次 `make up` | 10–25 分钟（Maven 下载占大头） |
| 后续 `make up` | 1–3 分钟（镜像已缓存，JVM 冷启动 60–120s） |
| 单次 smoke | 就绪后 <5 秒 |

---

## 9. 常见失败排查

| 现象 | 原因 | 处理 |
|---|---|---|
| `registry-1.docker.io ... EOF` | Docker Hub 不可达 | 配 mirror / 代理 / 离线导入，见 §7 |
| `failed to solve: ... git clone` | Gitee 不通 | 配代理、改 `GITEE_REPO`，或手动放源码到 `ruoyi/RuoYi` |
| `Could not resolve dependencies` | Maven 下载失败 | 设置 `MAVEN_MIRROR`，或在能出网的机器上构建后 `docker save` |
| builder 里 `apt-get update` 404 | `maven:3.8-openjdk-8` 的 Debian 源可能已 EOL | 换成 `maven:3.8.8-eclipse-temurin-8` 等仍维护的 JDK 8 构建镜像，或为该镜像配置 archive 源；本目录未固定镜像 digest |
| `Table 'ry.sys_config' doesn't exist` | 数据卷已存在，init 脚本没再执行 | `make reset`（会删卷并重新初始化）；不要只 `down/up` |
| `Access denied for user 'ruoyi'` | `.env` 改了密码但 MySQL 卷还是旧密码 | `make reset`，或删 `mysql_data` 卷 |
| `Communications link failure` | MySQL 未 healthy / 网络未就绪 | 等健康检查；看 `docker compose logs mysql` |
| `502 Bad Gateway` | ruoyi 还在启动 | 等 `ruoyi` healthy；`make logs` 看 JVM 异常 |
| `curl: (60) SSL certificate problem` | 自签证书 | 用 `--insecure` 或 `--ca-cert certs/server.crt` |
| `nginx: [emerg] cannot load certificate` | 没生成证书 | `make cert`（或 `sh certs/generate.sh`） |
| 登录一直提示验证码错误 | 验证码开启；OCR/手工输入错误 | 浏览器访问 `/captcha/captchaImage`；自动化场景接受 UNKNOWN |
| Druid 登录页打不开 | 未先通过 Shiro 登录 | 先用 admin/admin123 登录，再访问 `/druid/index.html` |
| WAF 对正常请求也 403 | CRS 规则/异常分误伤 | 降低 paranoia、看 `docker compose logs waf`（该镜像的 `MODSEC_AUDIT_LOG=/dev/stdout`）；或换 `--bypass-waf` |
| harden 档仍能访问 Druid | 扫描到了 `:18080` 直连口，或模板未挂载 | 只扫 `:8444`；`docker compose exec nginx-harden nginx -T` |
| `make: command not found`（Windows） | 未装 make | 用 §4.3 的原生 compose 命令 |
| `Permission denied` 跑证书脚本 | Windows 挂载权限 | `sh certs/generate.sh`，不要依赖 `./` |
| Apple Silicon 构建慢/失败 | 部分基础镜像多架构支持不一 | 在 compose 服务上加 `platform: linux/amd64`，或改用原生 arm64 镜像 |

---

## 10. 生产保真度评估（诚实版）

### 10.1 真实的部分

- **真实 Java 运行时**：官方 RuoYi 4.7.8 源码、Maven 构建、JDK 8、Spring Boot 2.5.15、
  内嵌 Tomcat、Shiro 1.13.0、Thymeleaf、MyBatis、Druid 1.2.20、Quartz。
- **真实数据库**：MySQL 8.0，DDL 直接来自上游 `sql/ry_20230706.sql`，JDBC 驱动与 SQL
  报错都是真的；SQLi 回退后会出现真实的 `XPATH syntax error` 堆栈。
- **真实会话/验证码**：Shiro 过滤链、`JSESSIONID`、在线会话同步、kaptcha 数学验证码。
- **真实代理/TLS**：nginx 1.24 终止 TLS、80→443、20 MB body 限制、真实 403。
- **真实 WAF**：ModSecurity + CRS v4，paranoia=1，真实规则拦截与异常分。
- **真实启动/健康检查**：MySQL init、JVM 冷启动、`depends_on: service_healthy` 链。
- **真实构建/运行隔离**：多阶段构建、非 root 用户、只读证书挂载。

### 10.2 仍是裁剪或代理层模拟的部分

| 项 | 现状 | 影响 |
|---|---|---|
| 应用漏洞 | stock = 官方 4.7.8，主要 POC 已修复 | 不产生 CONFIRMED；需按 §6.3 回退 |
| harden | nginx 403，不是改 Java 代码 | 只验证「代理层能否挡住扫描器」，`:18080` 可绕过 |
| waf | 代理层拦截，应用收不到请求 | 只能验证「WAF 是否命中」，不能验证应用层修复 |
| 种子数据 | 5 个部门、2 个用户、精简菜单/字典 | 数据量与真实生产库不同；分页/数据权限样本有限 |
| Redis | 4.7.8 不使用；仅保留可选定义 | 不代表若依 Vue/Cloud 的 Redis 依赖 |
| Nacos / 微服务 / 集群 | 未包含 | 不覆盖 RuoYi-Cloud-Plus 等变体 |
| TLS | 自签证书，无 HSTS、无真实 CA | 浏览器/客户端会告警；不能验证证书链策略 |
| 上传目录 | 命名卷 | 没有杀毒、对象存储、CDN 等生产链路 |
| 镜像 tag | `mysql:8.0`、`nginx:1.24-alpine`、`owasp/...:nginx-alpine` 等浮动 tag | 规则/补丁可能随上游变化；复现实验建议 pin digest |
| 构建依赖 | 首次必须联网拉 Maven 依赖 | 离线机需要预构建镜像 + `docker save/load` |
| 验证码 | 未集成 OCR | 自动化登录链只能判 UNKNOWN 或人工输入 |

### 10.3 结论

这是一个**真实的 Java 若依运行系统**，不是 Python 模拟；但它是一个**测试用生产切片**，
不是生产集群。它最适合回答三个问题：

1. 插件在真实 Shiro/MySQL/nginx 响应上会不会误报？（stock 基线）
2. 代理层加固后，扫描器是否把 403 误当 SAFE？（harden/WAF）
3. WAF 拦截时，三态是否仍守住「测不到 ≠ 安全」？（UNKNOWN 纪律）

---

## 11. 文件清单

```
lab/prod/
├── .env.example                     # 端口/口令/版本/代理/镜像参数
├── Makefile                         # up/down/logs/reset/up-waf/up-harden/smoke/config
├── docker-compose.yml               # mysql / redis(profile) / ruoyi / nginx / harden / waf
├── README.md                        # 本文件
├── certs/
│   ├── .gitignore                   # 不提交自签私钥
│   └── generate.sh                  # 生成 server.crt / server.key（幂等）
├── db/init/
│   ├── 01-schema.sql                # 上游 DDL，20 张表（含启动必需的 config/dict 等）
│   └── 02-data.sql                  # admin/ry、部门/角色/菜单/字典/参数/任务/代码生成
├── nginx/templates/
│   ├── default.conf.template        # 80→443、TLS、8081 WAF upstream
│   └── harden.conf.template         # 四类端点 403 + 代理其余流量
└── ruoyi/
    ├── Dockerfile                   # Maven 构建 + JRE 非 root 运行时
    └── .dockerignore

scripts/prod_smoke.py                # 5 端点冒烟，stock/harden/waf 三档期望
```

---

## 12. 安全声明

- 仅限本地、隔离、授权环境；所有端口默认 `127.0.0.1`。
- 内置 `admin/admin123`、Druid `ruoyi/123456`、MySQL 弱口令与自签私钥，**禁止**用于生产。
- `lab/prod/certs/server.key` 是测试密钥，已在 `.gitignore` 中排除；不要复用。
- WAF/harden 只是测试对照层，不代表真实生产加固方案。
- 对任何非自有资产发起扫描都可能违法；本目录不提供任何批量目标获取能力。
