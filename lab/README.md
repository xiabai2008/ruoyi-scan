# 若依漏洞扫描器 — 本地验证靶场（Tier A 签名靶场）

> **用途**：在**合法、零风险**的前提下验证 `Ruoyi-Scan` 插件化扫描器的判定逻辑。
> 本靶场不发起任何对第三方资产的请求，仅供本地对拍（scanner ↔ target）。
>
> ⚠️ 真实目标只能是你**有权限测试**的资产（自建靶场 / 授权渗透 / 厂商 SRC 在 scope 内）。
> 严禁对 FOFA / Shodan 批量拉取的若依资产发起扫描，这属于非法侵入。

---

## 1. 靶场形态

| 项目 | 说明 |
|---|---|
| 技术栈 | Python Flask（无需 Java / Maven） |
| 模式 | `vuln`（全漏洞开启）/ `safe`（全修复，零漏洞）双模式 |
| 端口 | 环境变量 `LAB_PORT` 控制，默认 `8080` |
| 覆盖 | 精确复现 11 个插件的请求路径与判定签名 |

靶场响应特征与插件判定一一对应，因此可反向验证：
- **漏报**：vuln 模式下某 POC 未报 `CONFIRMED` → 插件判定逻辑缺陷
- **误报**：safe 模式下某 POC 误报 `CONFIRMED` → 插件判定过宽

---

## 2. 快速启动

### 方式 A：直接运行（推荐，秒级）

```bash
cd lab/
pip install -r requirements.txt

# vuln 模式（应全 CONFIRMED）
LAB_MODE=vuln LAB_PORT=8080 python server.py

# safe 模式（应全 SAFE，零误报）
LAB_MODE=safe LAB_PORT=8081 python server.py
```

### 方式 B：Docker

```bash
cd lab/
docker compose up --build        # 默认 vuln 模式，端口 8080
# 切换 safe 模式：编辑 docker-compose.yml 中 LAB_MODE=safe 后重跑
```

---

## 3. 与扫描器对拍

另开终端，在**项目根目录**运行扫描器（需已装 `requests`）：

```bash
# vuln 模式对拍
python main.py -u http://127.0.0.1:8080

# safe 模式对拍（重点验证零误报）
python main.py -u http://127.0.0.1:8081
```

---

## 4. 预期结果表

### 4.1 VULN 模式（应全部命中）

| 插件 | 预期输出 | 判定签名 |
|---|---|---|
| 指纹识别 | `cms=ruoyi 置信度=0.70` | `login:RuoYi` + `keyword:RuoYi` |
| 任意文件读取 | `存在` | 响应含 `root:x:0:0` |
| 定时任务任意文件读取 | `存在` | edit/run 200 + 2.txt 含 `root:/` |
| POST 报错注入（role） | `存在` | 响应含 `运行时异常` + `extractvalue` |
| POST 报错注入（dept） | `存在` | 响应含 `database()` |
| 任意文件上传 | `存在` | JSON 含 `url` 或 `fileName` |
| 定时任务 RCE | `存在` | 未鉴权进入业务层（code=200/500） |
| Thymeleaf/SpEL 注入 | `存在` | 响应含 `49` + 引擎关键字 |
| 未授权访问批量 | `存在` | Actuator/Druid/Swagger/后台 任一暴露 |
| 后台默认口令 | `存在` | 登录返回 `token` |
| Druid 弱口令爆破 | `登录成功 user=ruoyi pwd=123456` | JSON `success==true` |

### 4.2 SAFE 模式（应全部未命中，零误报）

- 9 个漏洞插件全部输出 `不存在`
- Druid 爆破**全部 `登录失败`**（旧逻辑 `"success":false` 子串误判已修复）

---

## 5. 已通过对拍验证的修复

在执行对拍过程中，发现并修复了以下真实缺陷：

| 缺陷 | 修复 |
|---|---|
| `druid_brute.py` 用 `'success' in text` 子串匹配，把 `{"success":false}` 误判为命中 | 改为解析 JSON 严格比对 `success is True`；非 JSON 退化为精确子串 `"success":true` |
| 靶场 safe 响应曾含 `success` 关键字 | 改为 `{'code':0,'message':'用户名或密码错误'}` |
| 回归测试 `test_hit_correct_password` mock 用裸 `success` 适配旧逻辑 | 改为合法 JSON `{"success": true, ...}` |

配套回归测试（无靶场也能跑）：`python tests/regression_ruoyi.py` → **30/30 通过**。

---

## 6. 覆盖范围说明（签名 vs 真实）

本靶场是**签名级**验证——验证的是「插件的匹配逻辑是否正确」，而非「真实漏洞的可利用性」。
例如：
- 文件上传插件验证的是「响应含 url/fileName 即判命中」，并未真的在靶场上写入 Webshell；
- 定时任务 RCE 验证的是「未鉴权进入业务层即判存在」，并未真的反弹 Shell。

若需验证**真实利用链路**（真实文件落地、真实命令执行），见 **Tier B（真实 RuoYi 部署）** 计划。

---

## 7. Tier B 计划（真实 RuoYi，待执行）

- `docker-compose` 起 MySQL + 构建/运行官方 RuoYi（JDK + Maven 或预构建 jar）
- 提供「漏洞重引入」说明（精确 `file:line`），使真实环境可验证文件上传与定时任务 RCE 的真实利用
- 与 Tier A 的差异：接近实战，但构建重、启动慢

> 是否执行 Tier B 由使用者决定；Tier A 已能满足「判定逻辑可信验证」的核心目标。
