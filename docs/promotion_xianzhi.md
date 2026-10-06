# 若依专项扫描：从指纹识别到 AI 生成 POC 的完整实现

> 作者：XIABAI
> 项目：Ruoyi-Scan（若依专项漏洞扫描器）— https://github.com/xiabai2008/ruoyi-scan
> 声明：本文所有检测均在自建签名靶场（仅 127.0.0.1 绑定）或授权环境下验证，请勿对未授权目标使用。

---

## 一、为什么需要"专项"扫描器

若依（RuoYi）是国内应用最广的开源 Java 后台框架之一，政企系统、外包项目、毕业设计大量基于其二次开发。但它有一个现实问题：

- **通用扫描器覆盖浅**：往往只停留在"能扫到 Shiro / Spring Boot"层面，对若依专有攻击面（特定路径泄露、版本差异化漏洞、二次开发引入的未授权接口）覆盖不足；
- **误报率高**：若依及其变体（Vue3 / App / Plus / Cloud-Plus）指纹差异大，通用工具经常把不存在的端点判定为漏洞，人工复核成本高。

因此我做了 Ruoyi-Scan：**插件化架构 + 三态判定（CONFIRMED / SAFE / UNKNOWN）**，专为若依生态设计。

---

## 二、整体架构

```
main.py（CLI 参数解析与模式分发）
   │
   ▼
core/orchestrator.py（扫描编排：recon / vuln / brute 插件分组调度）
   │
   ├── core/fingerprint.py  指纹识别 → 目标判定（若依/变体）
   ├── core/router.py       指纹 → 插件路由（只跑匹配的插件）
   ├── core/engine.py       并发编排 + 令牌桶限速
   ├── core/chain.py        漏洞利用链（DAG 拓扑编排）
   └── core/report.py       多格式报告渲染
   │
   ▼
plugins/（每漏洞一插件，继承 PluginBase）
   ├── ruoyi/    若依 20 个插件（含 2 个 Plus 变体专属）+ 5 变体识别
   ├── spring/   Spring Boot 14 个 POC
   ├── common/   通用漏洞包 11 个插件（.git/.env 泄露、CORS、Swagger 等）
   ├── jeecgboot/ JeecgBoot 8 个插件（首个非若依框架拓展实证）
   └── chain/    3 条内置利用链
```

三种交付形态共用同一引擎：CLI（`pip install ruoyi-scan`）、**单文件桌面端**（Tauri，引擎与 53 个插件编译期嵌入，双击即用，无需 Python/Docker）、Docker 镜像。

核心设计原则（对应 `plugins/base.py`）：

- **每漏洞一插件**，继承 `PluginBase`；
- **三态判定**：`verify()` 必须返回 `ScanResult`，网络异常等不可判定情形**必须返回 UNKNOWN，不得误判为 SAFE**（判定逻辑的底线）；
- **元信息驱动**：CVSS v3.1 自动评分、等保/OWASP 合规映射、复现命令、修复建议全部挂在插件类属性上，报告直接引用。

---

## 三、插件系统：一个真实 POC 长什么样

以若依最经典的**任意文件读取（路径穿越）**为例（`plugins/ruoyi/file_read_path.py`）：

- 漏洞：`/common/download/resource?resource=` 接口未对 `resource` 参数做白名单校验，`../` 路径穿越可读取任意文件；
- 影响版本：`>=4.0,<4.7`（4.7 已修复）；
- 编号：CNVD-2021-01931；
- 合规映射：`等保2.0:8.1.4; OWASP:A01:2021`。

插件类属性（节选）：

```python
class RuoyiFileReadPathPlugin(PluginBase):
    name = "任意文件读取（路径穿越）"
    cve = "CNVD-2021-01931"
    severity = "high"
    category = "vuln"
    # 影响版本范围：路径穿越在 4.7.0 已修复
    affected_versions = ">=4.0,<4.7"
    # CVSS v3.1 向量（自动计算 Base Score）
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    compliance = "等保2.0:8.1.4;OWASP:A01:2021"
    # WAF 绕过支持：命中 WAF 后引擎调用 verify_with_bypass()
    vuln_type = "file_read"
    supports_waf_bypass = True
```

判定逻辑（三态判定核心）：

```python
def verify(self, target, session):
    url = join_url(target, "/common/download/resource?resource=../../../etc/passwd")
    try:
        resp = session.get(url)
    except Exception as e:
        # 网络异常 → UNKNOWN，绝不误判为 SAFE
        return ScanResult(kind="vuln", name=self.name,
                          status=STATUS_UNKNOWN, url=url, evidence=str(e))

    text = resp.text or ""
    code = getattr(resp, "status_code", 0)

    # 200 + 真实 /etc/passwd 特征 → CONFIRMED（强特征，不靠签名 marker）
    if code == 200:
        hit, evidence = _is_passwd_file(text)
        if hit:
            return ScanResult(kind="vuln", name=self.name,
                              severity=self.severity, status=STATUS_CONFIRMED,
                              url=url, evidence=evidence, ...)
    # 400/403 → 拦截；404 → 端点不存在；200 无特征 → SAFE
    ...
```

判定上用**真实响应特征**而非简单的"状态码=200"或"响应含关键字"：

- 文件读取 → 校验响应是否为**真实 `/etc/passwd` 格式**（`name:x:uid:gid:` 多行 + root/系统账户特征），从机制上避免"返回 200 就报漏洞"的误报；
- 这是 `CONFIRMED / SAFE / UNKNOWN` 三态判定落地的一个缩影。

新增 POC 时无需改引擎：`python main.py --plugin-init <name>` 生成骨架 → 实现 `verify()` → `--plugin-check` 验证 → 自动被加载。

---

## 四、指纹识别：把"扫得准"做在前面

通用扫描器误报多，很大程度是因为**不知道对面是什么**。Ruoyi-Scan 的指纹层做了三件事：

1. **favicon hash**：采集站点 favicon 计算 hash，与已知若依资产比对；
2. **特征路径 + 关键字**：`/prod-api/`、`/system/` 等若依路由特征、页面关键字；
3. **变体细分**：Vue3 / App / Plus / Cloud-Plus 分别识别。

指纹的结果直接驱动 `router.py` 的插件路由：**只对匹配变体运行对应 POC**（`variant` 字段控制），避免跨变体误报。

---

## 五、WAF 绕过：三态判定保护矩阵

遇到 WAF 时，引擎自动切换到绕过通道：

- 11 种绕过策略（编码变形、大小写混合、注释混淆、双写等）；
- 命中 WAF 后调用插件的 `verify_with_bypass()`，传入已应用传输层变换的 `BypassSession`；
- 内置**成功率追踪**，统计每种策略对不同漏洞类型的命中率；
- 判定仍遵循三态：绕过后确认才是 CONFIRMED，防止"绕过失败误报漏洞"。

---

## 六、AI 生成 POC：自然语言 → 自验证回灌

写 POC 有一定门槛，Ruoyi-Scan 提供了 AI 通道：

```bash
python main.py --ai "检测若依任意文件读取漏洞" --category ruoyi
```

流程：

1. 自然语言描述 → 生成插件骨架；
2. **LLM 自验证回灌**：生成的 POC 先由模型自检，不通过则回炉重生成；
3. 无 Key 时降级为规则模板，不阻塞使用。

---

## 七、nuclei 模板兼容：白嫖社区生态

```bash
python main.py -p http://target:8080/ --nuclei examples/nuclei/
python main.py --nuclei-validate examples/nuclei/   # 只校验不扫描
```

实现上是 **http 协议子集 + 安全白名单**：

- 支持 nuclei 模板中常用的 `http` 请求块（method/path/headers/body/matchers）；
- 白名单机制隔离模板中的危险动作（如重定向跳转、文件写入），避免模板本身成为攻击面；
- 支持 `--nuclei-tags` / `--nuclei-severity` 过滤。

---

## 八、漏洞利用链：DAG 拓扑编排

单个漏洞往往不够，利用链把多个 POC 串起来：

```bash
python main.py --chain ruoyi_sql_to_rce -u http://target:8080/
python main.py --chain list
```

- DAG 拓扑编排 + 条件分支（前一步未确认则不执行后续步骤）；
- 内置 3 条链：SQL 注入→RCE、Nacos 未授权→数据库凭证、默认口令→WebShell。

---

## 九、实战验证：内置签名靶场

为避免"没环境测"，仓库内置了签名靶场（`lab/`）：

```bash
docker compose up -d lab-ruoyi
# 扫描内置靶场
docker compose run --rm scanner -p http://lab-ruoyi:8080/ --report /app/reports
```

安全约束（硬性）：

- `lab-ruoyi` / `lab-spring` 默认仅绑定 `127.0.0.1`；
- 启动时展示安全警告横幅：**本靶场含漏洞响应签名，仅限本机/授权测试环境使用，严禁部署到公网或未授权网络**；
- 涉及利用的插件默认仅做存在性验证，不做实际破坏。

---

## 十、报告与工程化

- **多格式**：HTML（SVG 图表）/ JSON / CSV / PDF / Word / Excel / SARIF；
- **Web API**：`python main.py --serve` 启动 REST + WebSocket 实时推送 + Web 控制台，权限分级（read / scan / admin），支持定时扫描；
- **组件版本检测**：fastjson / SpringBoot / Shiro / Nacos / Log4j 版本比对 CVE 映射（`--components`）；
- **CVE 数据源**：NVD + CNVD + GHSA + 离线 CVE 库四源，24h TTL 缓存；
- **CI/CD**：SARIF 对接 GitHub Code Scanning，严重度阈值退出码控制。

### 交付形态

- **CLI**：`pip install ruoyi-scan`（PyPI 受信任发布）；
- **桌面端**：单文件 exe（Tauri），引擎与 53 个插件在编译期嵌入，双击即用，无需 Python / Docker；
- **Docker**：`docker compose up -d` 一键起扫描器 + API + 内置靶场；
- **在线文档站**：https://xiabai2008.github.io/ruoyi-scan/（mkdocs-material）。

### 可信度不是靠嘴说

「有多少插件」和「验证过多少检出」是两回事。项目维护了一份**检出能力矩阵**
（`docs/verification-matrix.md`），逐插件标注验证级别：

| 级别 | 含义 |
|------|------|
| L1 | 签名靶场：验证判定逻辑与三态分流 |
| L2 | 真实响应靶场：复现真实漏洞响应特征（无 marker） |
| L3 | 真实软件双向验证：官方版全 SAFE（零误报）+ 补丁回退后 CONFIRMED |

配套的还有：SLSA 构建来源证明、Ed25519 插件签名分发（远程安装强制验签、fail-closed）、
OpenSSF Scorecard 评分项。每晚另有真实靶场验收（vuln 模式防漏报 + safe 模式零误报）。

---

## 结语

Ruoyi-Scan 的定位很明确：**在若依这个垂直生态里，把检测做深、做准**。三态判定从机制上控制误报，AI 生成 POC 降低插件编写门槛，nuclei 兼容复用社区生态，单文件桌面端把使用门槛降到「双击」。

- 仓库：https://github.com/xiabai2008/ruoyi-scan（MIT）
- 在线文档：https://xiabai2008.github.io/ruoyi-scan/
- 演示动图见 README；Releases 附单文件 exe
- 欢迎 star、提交 POC、交流若依生态的漏洞研究

---

## 附录：常用命令速查

```bash
# 综合扫描（目录 + 漏洞 + 爆破）
python main.py -u http://target:8080/

# 漏洞检测
python main.py -p http://target:8080/

# 组件版本检测
python main.py -p http://target:8080/ --components

# nuclei 模板
python main.py -p http://target:8080/ --nuclei examples/nuclei/

# AI 生成插件
python main.py --ai "检测若依任意文件读取漏洞" --category ruoyi

# 漏洞利用链
python main.py --chain ruoyi_sql_to_rce -u http://target:8080/

# Web API + 控制台
python main.py --serve   # http://localhost:8000/

# 批量扫描
python main.py -f targets.txt -p --report ./reports
```
