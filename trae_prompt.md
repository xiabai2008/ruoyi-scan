# Trae 长程任务提示词 — Ruoyi-Scan 做深若依

> **2026-07-18 重大调整**：原"多 CMS 扩充"提示词已废弃。
> 项目转向**专注若依做深**路线，thinkphp/weaver/shiro/struts2/nuclei 已抽离至 `../cms-scan-extras/`。
> 本提示词驱动做深阶段的逐阶段执行。

请按以下阶段顺序，逐阶段完成 Ruoyi-Scan 若依专项做深。每个阶段完成后请自行运行全量测试（pytest + regression_ruoyi + real-ruoyi 扫描），确认全部通过再进入下一阶段，并将完成情况汇报给我。

---

## 项目当前基线（2026-07-18 抽离后）

这是一款合法授权的**若依专项漏洞扫描器**，当前覆盖 `ruoyi`（16 POC）+ `spring`（14 POC）+ `common`（通用漏洞包），已实现批量扫描（`-f`）与报告（HTML/JSON/CSV + batch_report）。

**目录结构（关键部分）**
```
./
├── main.py                      # CLI 入口（argparse，--cms choices=ruoyi/spring）
├── core/
│   ├── fingerprint.py           # detect_cms(target, session) 多CMS自动识别
│   ├── router.py                # 指纹→插件包路由（mapping: ruoyi/spring）
│   ├── engine.py                # 扫描引擎（并发/限速，锁外 sleep 已修）
│   ├── report.py                # ReportBuilder(单目标) + BatchReport(批量汇总)
│   ├── models.py                # ScanResult / FingerprintResult / STATUS_*
│   ├── loader.py                # load_plugins(package) 动态导入
│   ├── cache.py                 # FingerprintCache 请求级缓存
│   └── session.py               # SessionManager(requests.Session封装)
├── plugins/
│   ├── base.py                  # PluginBase抽象基类
│   ├── ruoyi/                   # 16个POC插件
│   ├── spring/                  # 14个POC插件
│   └── common/                  # 通用漏洞包（.git/.env/备份等）
├── lib/
│   ├── fingerprint_features.py  # CMS_FEATURES（仅 ruoyi + spring）
│   ├── http.py                  # normalize_target / join_url / host_of
│   ├── colors.py                # 终端颜色
│   └── matcher.py               # 响应匹配工具
├── lab/
│   ├── server.py                # RuoYi Flask签名靶场(LAB_MODE=vuln/safe)
│   ├── spring_server.py         # Spring Boot Flask签名靶场
│   ├── real-spring/             # Spring 真实响应靶场（Flask，CI 自动跑）
│   └── real-ruoyi/              # 真实 RuoYi 4.7.8 Java 应用（手动触发）
├── tests/
│   ├── test_fingerprint.py      # 指纹模块单元测试（ruoyi/spring）
│   ├── test_cache.py            # 缓存单元测试
│   ├── regression_ruoyi.py      # RuoYi插件回归(requests_mock)
│   └── regression_spring.py     # Spring插件回归(requests_mock)
└── config/
    └── settings.py              # 全局配置(VERSION/AUTHOR/REPORT_DIR等)
```

**已抽离内容**（在 `../cms-scan-extras/`，不再维护）：thinkphp / weaver / shiro / struts2 / nuclei 插件包 + nuclei_adapter + thinkphp/weaver 靶场 + real-thinkphp。

---

## 核心约定（务必遵守，违反会导致框架崩溃）

1. **判定三态**：`CONFIRMED` / `SAFE` / `UNKNOWN`。网络异常等不可判定情况必须返回 `ScanResult(status=STATUS_UNKNOWN, ...)`，**绝不判 SAFE**。
2. **插件接口**：继承 `plugins.base.PluginBase`，实现 `verify(self, target, session) -> ScanResult`；类属性 name/cve/severity/category/description/fix。
3. **URL 拼接**：一律用 `lib.http.join_url(target, '/path')`；path 用**前导斜杠**（`/index.php` 而非 `index.php`）。
4. **降误报**：SAFE 判定必须基于明确证据（响应缺签名/关键字），不能仅看 200。
5. **框架零改动原则**：新增 POC 仅加插件文件，`core/engine.py`、`core/router.py`、`core/report.py`（主体逻辑）不改动。
6. **真实响应优先**：新 POC 判定基于真实漏洞响应特征，**不依赖签名 marker 魔法常量**。
7. **版本适配**：每个 POC 标注 `affected_versions`，指纹识别版本后定向跑。
8. **回归测试**：用 `requests_mock` 模拟 HTTP 响应，每个插件至少 vuln→CONFIRMED 和 safe→SAFE 两个用例。
9. **端到端验证**：启动 `lab/real-ruoyi` → `main.py -p http://127.0.0.1:8080/` → 确认 vuln 全 CONFIRMED / safe 全 SAFE。

---

## 测试验证命令（每阶段完成后执行）

```bash
# 1. 单元测试
python -m pytest tests/ -q

# 2. 插件回归
python tests/regression_ruoyi.py
python tests/regression_spring.py

# 3. 签名靶场对拍
LAB_MODE=vuln LAB_PORT=8090 python lab/server.py &
python main.py -p http://127.0.0.1:8090/   # 期望全部 CONFIRMED
LAB_MODE=safe LAB_PORT=8091 python lab/server.py &
python main.py -p http://127.0.0.1:8091/   # 期望全部 SAFE

# 4. 真实 RuoYi 靶场（如已启动）
python main.py -p http://127.0.0.1:8080/   # 真实 RuoYi 4.7.8
```

**注意：真实 RuoYi 4.7.8 实例长期运行于 127.0.0.1:8080（java 进程），清理靶场时勿误杀。**

---

## 【D4】real-ruoyi 自动化验收（优先执行，建基线）

### 背景
当前 `lab/real-ruoyi` 是真 Java 应用，CI 设为手动触发。签名 marker 循环验证（nacos_unauth / file_read_path）无真实保证。需先建真实验收基线，后续改动才有底气。

### 步骤 1：删除签名 marker 循环验证

修改 `plugins/ruoyi/nacos_unauth.py`：
- 删除 `NACOS_UNAUTH_MARKER` 常量依赖
- 改为判定 `/nacos/v1/auth/users?pageNo=1&pageSize=10` 返回 JSON 含 `username` / `password` 字段
- 网络异常返回 UNKNOWN，401/403 返回 SAFE，200 且含用户字段返回 CONFIRMED

修改 `plugins/ruoyi/file_read_path.py`：
- 删除 `FILE_READ_PATH_MARKER` 常量依赖
- 改为判定响应含 `root:x:0:` 或 `daemon:x:1:` 等真实 `/etc/passwd` 特征
- 参考 `lib/matcher.py` 的 `match_file_read_leak` 函数

修改 `lab/server.py`：
- 去掉 `NACOS_UNAUTH_MARKER` / `FILE_READ_PATH_MARKER` 魔法常量
- `/nacos/v1/auth/users` 返回真实风格 JSON：`{"totalCount":1,"data":[{"username":"nacos","password":"$2a$10..."}]}`
- `/common/download/resource` 返回真实 `/etc/passwd` 内容片段

### 步骤 2：CI 自动化 real-ruoyi

修改 `.github/workflows/ci.yml`：
- 将 `real-ruoyi` 作业从 `workflow_dispatch` 改为 `push`/`pull_request` 自动触发
- 用 Docker Compose 起 MySQL + RuoYi（新增 `lab/real-ruoyi/docker-compose.ci.yml`）
- `scripts/run_e2e.py` 新增 `--real-ruoyi` 模式：等 Java 进程就绪、跑扫描、断言 CONFIRMED 数 ≥ 5

### 步骤 3：验证
1. `pytest tests/ -q` → 全部通过
2. `regression_ruoyi.py` → 全部通过（nacos_unauth / file_read_path 用例同步更新）
3. 签名靶场对拍：vuln 全 CONFIRMED / safe 全 SAFE
4. real-ruoyi 扫描：CONFIRMED 数 ≥ 5（与 `lab/REAL-RUOYI.md` 记录一致）
5. 汇报：修改文件列表 + real-ruoyi CONFIRMED 数

---

## 【D1】登录链打通

### 背景
`plugins/ruoyi/file_read_time.py` 用硬编码 `settings.JOB_JSESSIONID`，真实若依需先登录拿会话。这是最大漏报源。

### 步骤 1：新增 `core/auth_chain.py`

```python
# 若依登录链编排器
class RuoYiAuthChain:
    def __init__(self, target, session, username='admin', password='admin123'):
        self.target = target
        self.session = session
        self.username = username
        self.password = password

    def login_v4_session(self):
        """RuoYi v4 Session 鉴权：POST /login → 提取 JSESSIONID"""
        # POST {target}/login with form data
        # 解析响应 Set-Cookie 或 JSON token
        # 后续请求自动带 Cookie（session 复用）
        pass

    def login_v5_jwt(self):
        """RuoYi v5 JWT 鉴权：POST /login → 提取 token → 加 Authorization 头"""
        # POST {target}/login with JSON body
        # 解析响应 JSON token
        # session.headers['Authorization'] = f'Bearer {token}'
        pass

    def detect_auth_mode(self):
        """探测鉴权模式：v4 Session / v5 JWT / 无鉴权"""
        # GET /login 观察响应特征
        # v4: HTML 表单 + Set-Cookie JSESSIONID
        # v5: JSON 响应 / 前端 SPA
        pass
```

### 步骤 2：改造需鉴权 POC

修改 `plugins/ruoyi/file_read_time.py` / `job_rce.py` / `thymeleaf_ssti.py`：
- `verify()` 开头调用 `RuoYiAuthChain.login_v4_session()` 拿会话
- 用拿到的会话发后续请求
- 登录失败返回 UNKNOWN（不判 SAFE）

### 步骤 3：配置与测试
- `config/settings.py` 新增 `RuoYiAuth` 配置类（默认口令、超时、重试）
- `tests/test_auth_chain.py`：mock `/login` 响应，验证 v4/v5 双链路
- `regression_ruoyi.py`：file_read_time / job_rce 用例改为先 mock 登录再 mock 漏洞响应

### 步骤 4：验证
1. 在 `lab/real-ruoyi`（开启鉴权）上跑 `file_read_time` / `job_rce`，CONFIRMED
2. 全量测试通过
3. 汇报：修改文件列表 + real-ruoyi CONFIRMED 数变化

---

## 【D2】多版本 POC 适配

### 背景
若依 4.2 / 4.4 / 4.6 / 4.7 / v5 各版本漏洞点与接口路径有差异，单 POC 打天下必漏报。

### 步骤 1：新增 `lib/ruoyi_versions.py`

版本指纹库（响应特征 → 版本范围）：
- `/system/info` 返回的 RuoYi 版本字符串
- `/actuator/info` 或静态资源路径中的版本 hash
- 默认首页 footer 的版本号
- API 路径前缀差异（v5 用 `/prod-api/`）

### 步骤 2：POC 标注 affected_versions

每个若依 POC 类属性新增 `affected_versions`：
```python
class SqlInjectRolePlugin(PluginBase):
    affected_versions = '>=4.2,<4.6'  # 4.6+ 已修 params[dataScope] 注入
```

### 步骤 3：指纹识别版本 + 定向路由
- `core/fingerprint.py` 的 `detect_cms` 返回 `FingerprintResult(version=...)`
- `core/router.py` 的 `resolve` 过滤掉 `affected_versions` 不匹配的 POC

### 步骤 4：重点覆盖的差异点
- `/system/role/list` 的 `params[dataScope]` 注入在 4.6+ 已修
- `/monitor/job/edit` 白名单在 4.7+ 收紧
- `/common/upload` 扩展名校验在 4.6+ 加强
- v5 用 JWT 鉴权，接口路径前缀 `/prod-api/`

### 步骤 5：验证
1. 在 4.2 / 4.7.8 / v5 三个版本上分别扫描（如无 v5 靶场，至少 4.2 + 4.7.8）
2. POC 命中范围与 `affected_versions` 一致
3. 全量测试通过

---

## 【D5】误报率实测

### 步骤 1：准备非若依测试集
5-10 个非若依 Java 站点：
- Spring 纯净站（spring-initializr 生成）
- JeecgBoot（另一款 Java 快速开发框架）
- JFinal 站点
- 纯静态站

### 步骤 2：跑扫描
每个站点 `python main.py -p <target>`，记录 CONFIRMED 数

### 步骤 3：统计与修复
- 假阳数 / 总扫描数 = 假阳率
- 假阳率 > 5% 的 POC 必须修判定逻辑
- 修复后重测

### 步骤 4：文档
- `lab/FALSE-POSITIVE-TEST.md`：记录测试集、结果、修复动作
- README 写明假阳率实测数据

---

## 【D3】验证码处理

### 步骤 1：检测验证码
- `core/auth_chain.py` 新增 `detect_captcha()`：GET `/captcha/image` 观察响应
- 无验证码 / 可绕过（旧版）/ 必校验 三态

### 步骤 2：分支处理
- 无验证码：走原逻辑
- 可绕过（RuoYi 4.2- 验证码不校验）：直接爆破
- 必校验：接 OCR（引入 `ddddocr` 轻量库，破"零依赖"但合理）

### 步骤 3：配置
- `config/settings.py` 新增 `captcha_mode`：`auto` / `ocr` / `skip`
- `main.py` 新增 `--captcha` 参数

### 步骤 4：验证
- 在 `lab/real-ruoyi` 开启验证码模式下，`default_password` 能 CONFIRMED

---

## 完成标准（每个阶段）

- [ ] `python -m pytest tests/ -q` → 全部通过
- [ ] `regression_ruoyi.py` / `regression_spring.py` 全部通过（退出码 0）
- [ ] 签名靶场对拍通过（vuln 全 CONFIRMED / safe 零误报）
- [ ] `lab/real-ruoyi` 扫描 CONFIRMED 数不回退
- [ ] 新建/修改的代码符合核心约定（三态、插件接口、URL 拼接、真实响应优先、版本适配）
- [ ] 汇报：阶段名 + 新增文件列表 + 测试结果摘要 + real-ruoyi CONFIRMED 数
