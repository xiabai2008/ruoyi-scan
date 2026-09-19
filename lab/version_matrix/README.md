# RuoYi 多版本靶场矩阵

把「同一套若依插件在不同 RuoYi 版本上的三态判定表现」变成可复现的实验数据。

这是 `lab/REAL-RUOYI.md` 里最后一项未打勾的 TODO（`real-ruoyi 自动化`）的落地实现。

---

## 为什么需要它

此前只对 **RuoYi 4.7.8** 做过真实环境交叉验证（见 `../REAL-RUOYI.md`：5 CONFIRMED 零误报）。
但近一年若依系公开 CVE 表明，**4.8.x 各小版本各有独立漏洞**：

| 版本 | CVE | 类型 | CVSS |
|---|---|---|---|
| 4.8.0 | CVE-2025-46174 | `resetPwd` 缺 `checkUserDataScope` 权限校验 | 7.5 |
| 4.8.2 | CVE-2025-70986 | `selectDept` 越权访问部门数据 | 7.5 |

单版本结论不足以支撑「多版本适配」的论断。评审只要问一句「你验过几个版本」，
单版本验证就站不住。本矩阵给出 **4 个版本 × 全部插件** 的三态分布，作为可复现的实验凭证。

---

## 版本矩阵

| 版本 | JDK | Spring Boot | 端口 | 数据库 | 说明 |
|---|---|---|---|---|---|
| `v4.7.8` | 8 | 2.5.x | 18101 | `ry_matrix_478` | 基线（已有单版本验证） |
| `v4.8.0` | 8 | 2.5.x | 18102 | `ry_matrix_480` | CVE-2025-46174 |
| `v4.8.2` | 8 | 2.5.x | 18103 | `ry_matrix_482` | CVE-2025-70986 |
| `v4.8.3` | **17** | **4.0.3** | 18104 | `ry_matrix_483` | 框架大版本跃迁 |

**注意 v4.8.3 需要 JDK 17**，其余三个用 JDK 8。脚本会按版本自动切换 `JAVA_HOME`。

RuoYi 4.x 是 Thymeleaf + Shiro 单体，**不依赖 Redis**（已核实源码中无 `RedisTemplate` 用法），
因此矩阵不需要额外中间件。

---

## 前置条件

| 项 | 本机实测 | 说明 |
|---|---|---|
| JDK 8 | `D:/develop/java-se-8u44-ri` | 4.7.8 / 4.8.0 / 4.8.2 |
| JDK 17 | `D:/develop/jdk-17.0.0.1` | 仅 4.8.3 |
| Maven | `D:/tools/apache-maven-3.9.12` | **必须以 `mvn.cmd` 调用**，Git Bash 下的 Unix `mvn` 脚本会报 `找不到主类 Launcher` |
| MySQL | 8.0.46，3306 监听中 | 需提供可用凭据 |
| 网络 | Gitee 可达 | 拉源码用；Maven 依赖走项目内镜像配置 |

Maven 镜像配置在 `maven-settings.xml`（阿里云 public），通过 `mvn -s` 显式指定，
**不修改你的 `~/.m2/settings.xml`**。国内直连 Maven Central 容易超时。

---

## 快速开始

```bash
# 1. 拉源码（幂等，已存在则跳过）
python lab/version_matrix/run_matrix.py prepare

# 2. 核对配置结构（确认运行时可被命令行覆盖）
python lab/version_matrix/run_matrix.py check

# 3. 编译全部版本（首次约 10-20 分钟，下载 Maven 依赖）
#    这一步不需要数据库，可以先跑
python lab/version_matrix/run_matrix.py build

# 4. 起项目自带的独立 MySQL（端口 13306，root 无密码，不碰宿主 MySQL）
python lab/version_matrix/run_matrix.py dbstart

# 5. 建库导数据
python lab/version_matrix/run_matrix.py db \
    --db-port 13306 --db-user root --db-password ''

# 6. 创建低权限探测账号（越权类 POC 的前置条件，详见 ANALYSIS.md 5.2）
#    造出「持有所需功能权限、但数据范围不含超管」的普通账号 scanner_low
python lab/version_matrix/run_matrix.py seed \
    --db-port 13306 --db-user root --db-password ''

# 7. 起服务 + 扫描 + 出矩阵
python lab/version_matrix/run_matrix.py run \
    --db-port 13306 --db-user root --db-password ''

# 收尾
python lab/version_matrix/run_matrix.py stop     # 结束若依实例
python lab/version_matrix/run_matrix.py dbstop   # 结束独立 MySQL
```

若你已有可用 MySQL，跳过第 4 步，把第 5/6 步的 `--db-*` 换成你自己的连接参数即可。

也可以只跑单版本或单阶段：

```bash
python lab/version_matrix/run_matrix.py build --only v4.8.0
python lab/version_matrix/run_matrix.py start --only v4.8.2
python lab/version_matrix/run_matrix.py scan  --only v4.8.3
python lab/version_matrix/run_matrix.py matrix          # 仅重新汇总
```

密码也可用环境变量传入，避免出现在 shell 历史里：

```bash
export MATRIX_DB_PASSWORD='...'
python lab/version_matrix/run_matrix.py run
```

> **不要用 `taskkill /F /IM mysqld.exe` 清理**。宿主可能同时运行着自己的 MySQL 服务
> （实测：3306 为宿主服务，13306 为矩阵实例），按镜像名结束会连带杀掉它。
> `dbstop` 按端口定位 PID 后只结束那一个进程。

---

## 产物

| 路径 | 内容 |
|---|---|
| `out/MATRIX.md` | **主交付物**：版本概览 + 逐插件 × 逐版本的三态分布表 |
| `out/matrix.csv` | 同一份数据的 CSV（供进一步统计/绘图） |
| `out/reports/<版本>/report.json` | 各版本的完整扫描报告 |
| `out/logs/<版本>.build.log` | Maven 编译日志 |
| `out/logs/<版本>.app.log` | 应用启动与运行日志 |
| `out/logs/<版本>.scan.log` | 扫描器输出日志 |
| `out/pids/<版本>.pid` | 已启动实例的进程号（供 `stop` 收尾） |

矩阵表图例：**C** = CONFIRMED（确认存在）／S = SAFE（确认不存在）／U = UNKNOWN（无法判定）／— = 该版本未覆盖此插件。

---

## 设计决策

**1. 端口与数据库凭据不写进 jar，启动时用命令行覆盖**

启动参数形如：

```
java -jar ruoyi-admin.jar \
  --server.port=18102 \
  --spring.datasource.druid.master.url=jdbc:mysql://127.0.0.1:3306/ry_matrix_480?... \
  --spring.datasource.druid.master.username=root \
  --spring.datasource.druid.master.password=***
```

Spring Boot 中命令行参数优先级高于 `application.yml`。好处：

- **凭据变化无需重新编译**（编译是全流程最慢的一步，且需要下载依赖）
- 各版本源码保持原样，便于对照上游与复现
- 4 个版本共享同一份产物形态，减少变量

**2. 一库一版本，互不污染**

`ry_matrix_478` / `_480` / `_482` / `_483` 四个独立库，`db` 阶段会先 `DROP DATABASE IF EXISTS` 再建。
各版本自带 `ry_*.sql`（文件名随版本变化，脚本自动发现）+ 公共的 `quartz.sql`。

**3. 端口隔离，可同时运行**

18101–18104，四个实例可并行起，便于同机反复对照。

**4. 阶段粒度高且幂等**

`prepare` 已存在则跳过；`build` 有产物则跳过（`--force` 可强制重编）；
`start` 检测端口已就绪则跳过。中断后重跑不会重复劳动。

---

## 已知限制

- **只做存在性/可达性层面的对照**。矩阵反映的是「插件在真实版本上的三态判定」，
  不含登录链打通后的越权类验证（`resetPwd` / `selectDept` 这两个 CVE 需登录态才能验），
  那属于后续「D1-D5 登录链」范畴。
- **各版本默认配置下的行为**，不含 WAF/反向代理等部署层变量。
- 首次编译依赖网络；离线环境需预先填充 `~/.m2/repository`。
- 4.8.3 与另外三个版本 JDK 不同，若同时起服务注意内存占用（4 个 Spring Boot 进程）。

---

## 目录结构

```
lab/version_matrix/
├── README.md                 # 本文件
├── run_matrix.py             # 编排器（prepare/check/build/db/start/stop/scan/matrix）
├── maven-settings.xml        # 项目内 Maven 镜像配置（不改用户全局配置）
├── src/                      # 各版本官方源码（浅克隆，不入库）
└── out/                      # 日志、报告、矩阵产物（不入库）
```
