# 阶段 4 · 未污染验证方案（R13 hold-out）

> 目的：证明阶段 3 的修复是**真实能力提升**，而不是对已有靶场的拟合。
> 建立时间：2026-11-01

## 一、为什么需要 hold-out

阶段 3 的修复都是对着阶段 2 暴露的问题改的。改完再拿同一批靶场复扫，结果变好是必然的 ——
那可能只是「对着答案改代码」。要证明改进是真实的，必须有一个**修复过程中从没见过**的目标。

07 的原则：**最忌讳看到结果不好直接改靶场迎合扫描器 —— 那这套环境就废了，
它的全部价值就是「它不知道扫描器存在」。**

## 二、R13 是什么

| 项 | 内容 |
|---|---|
| 编号 | R13 |
| 业务名 | 桂平港务集团 · 集装箱调度系统 |
| 入口 | `http://127.0.0.1:19113` |
| 后端 | 复用 R2（19202），数据与 R2 一致 |
| 本质 | R2 + **加固版 WAF** |

### 与 R12 的区别

R12 只是「6 条正则拦明显 payload」。R13 复刻真实商业 WAF 的**四类行为**，
每一类都对着扫描器最容易出错的地方：

| # | WAF 行为 | 测扫描器的什么 | 正确应对 |
|---|---|---|---|
| 1 | **特征拦截**（穿越 / SQLi / 模板表达式 / 命令执行 / XXE / 反序列化 / NoSQL / LDAP） | 扫到 403 时判 SAFE 还是 UNKNOWN | **UNKNOWN**（请求没到应用层，不能证明不存在） |
| 2 | **扫描器 UA 拦截**（sqlmap / nikto / nuclei / acunetix 等） | 被识别后拿到统一拒绝页，会不会当漏洞 | 同 1，UNKNOWN |
| 3 | **统一拒绝页**（含 `Incident ID` 的固定 HTML） | 拒绝页里偶现的特征词会不会误报 | 识别为拒绝页，不采信 |
| 4 | **敏感路径假 200** ← **最狠的一条** | 状态码 200 但内容是假的，会不会当泄露 | **内容比对**：真 `.git/HEAD` 是 `ref: refs/heads/`，假的是维护提示 |

第 4 条是 R13 的核心价值：探测 `.git/HEAD`、`.env`、`.svn/entries` 时
**返回 200 + 一份看起来合理但无害的内容**（真实商业 WAF 的"蜜罐响应"就这么干）。

对比：

```
R7 真 .git/HEAD    → 200 + "ref: refs/heads/master"        → 应判 CONFIRMED
R13 假 .git/HEAD   → 200 + "Connecting to backend service…" → 应判 SAFE
```

状态码完全一样，**只能靠内容区分**。不接内容比对的扫描器会误报。

## 三、未污染纪律

1. **盲测 v2 阶段 1 全程不碰 19113**：不扫描、不 curl、不写进目标清单
2. **R13 的 WAF 规则不告诉盲测执行者**（规则由 lead 写，执行者不知道它存在）
3. **阶段 3 修复期间也不碰 R13**：不能拿它做「边改边验」
4. **阶段 4 一次性使用**：第一次也是唯一一次扫它。扫完就记录结果，不许反复调优
5. `lab.py` 里 R13 在 `holdout` 分组，**不在 `site` 分组** —— 常规 `lab.py up site` 不会拉起它
   （常规启停不见它，减少误碰）

## 四、验证流程

### 步骤 1：准备（阶段 3 结束后）

```bash
cd "C:\Users\HZR\Desktop\若依系统"

# 确认 R13 已停用（阶段 1-3 全程保持停用）
python scripts\r13_start.py status     # 应为「已停用」

# 起后端 + R13
python scripts\lab.py up R2
python scripts\r13_start.py start

# 四类行为自检
python scripts\r13_start.py status
```

期望输出：

```
配置      已启用
入口      19113 监听中
后端      19202 监听中
/login                          -> 200
/.git/HEAD                      -> 200      ← 假的，内容比对才发现
/?id=1%20union%20select%201     -> 403
```

### 步骤 2：扫一遍（唯一一次）

```bash
cd D:\HZR_PROJECTS\ruoyi-scan
"D:\tools\Python 3.12.9\python.exe" main.py -u http://127.0.0.1:19113 \
    --report artifacts/blind_v2/phase4-r13 \
    --no-pause --no-cta
```

### 步骤 3：判定每一项

| 扫描器结论 | 正确与否 |
|---|---|
| `.git` / `.env` / `.svn` 判 SAFE | ✅ **正确**（假 200 内容不匹配） |
| `.git` / `.env` / `.svn` 判 CONFIRMED | ❌ **误报** —— 状态码骗到了，没用内容比对 |
| SQLi 类插件判 UNKNOWN（因 403） | ✅ **正确**（请求没到应用层） |
| SQLi 类插件判 SAFE（因 403） | ❌ 假阴性 —— 把「被拦截」当成「不存在」 |
| 把 WAF 拒绝页当漏洞证据 | ❌ 误报 |
| 正常业务（`/login`、验证码）判 SAFE | ✅ 正确，WAF 不该影响正常业务判定 |

### 步骤 4：产出对照表

```markdown
| 项 | 期望 | R13 实测 | 判定 |
|---|---|---|---|
| .git 泄露（假 200） | SAFE | ? | ? |
| .env 泄露（假 200） | SAFE | ? | ? |
| .svn 泄露（假 200） | SAFE | ? | ? |
| SQLi（被 403 拦） | UNKNOWN | ? | ? |
| 模板注入（被 403 拦） | UNKNOWN | ? | ? |
| 正常登录页判定 | 不受影响 | ? | ? |
```

## 五、结果怎么用

### 如果 R13 表现符合预期

> 说明阶段 3 的修复是**通用能力**，不是对该批靶场的拟合。

### 如果 R13 表现不符合预期

这是**更有价值的发现**，说明：
- 修复只解决了那批靶场上的表象，根因还在
- 或者修复引入了新的适配（比如为了通过某个靶场特判）

两种都要写进报告，**不许为了好看而隐藏**。

## 六、报告的固定表述

阶段 4 报告里必须包含这一段（原文照抄，不许改写）：

> R13 是本次盲测的 hold-out 验证站：盲测阶段 1–3 全程未接触，
> 其 WAF 规则未告知盲测执行者。阶段 4 首次也是唯一一次扫描它。
> 因此 R13 上的表现可以反映**未受靶场反馈影响**的真实检测能力。
>
> 局限：R13 只覆盖「WAF 前置 + 同源后端」这一种形态，
> 不能代表所有真实环境；它证明的是「不是对已知靶场的拟合」，
> 不等于「在任意生产环境都准确」。

## 七、附：R13 的 WAF 规则清单（**不对外发布**）

| 类别 | 拦截特征 |
|---|---|
| 路径穿越 | `../`、`%2e%2e%2f`、`%252e%252e`（`$request_uri` 原始串匹配） |
| SQL 注入 | `union select`、`select..from`、`insert into`、`drop table`、`update..set`、`delete from` |
| 模板/XSS | `%24%7b`、`${`、`{{`、`__${`、`<script`、`javascript:`、`onerror=`、`onload=` |
| 命令执行 | `runtime.getRuntime`、`java.lang.`、`processbuilder`、`class.module.classLoader` |
| XXE | `<!DOCTYPE`、`<!ENTITY`、`xmllib`、`xmlReader`、`saxParser` |
| 反序列化 | `rO0AB`、`aced0005`、`ysoserial`、`jndi:`、`ldap://`、`rmi://` |
| 扫描器 UA | sqlmap、nikto、nmap、masscan、zgrab、nuclei、acunetix、nessus、openvas、awvs |
| 假 200 | `.git/HEAD`、`.env`、`.svn/entries` → 200 + 维护提示文案 |

**故意没拦的**：`python-requests`、`curl` 的 UA —— 拦了就等于考卷只给扫描器看假的，
不符合「复刻真实环境」的要求。

## 八、已知的坑（实施时注意）

1. **curl 会自动规范化 `../`**：`curl http://host/admin/../etc/passwd` 实际发的是
   `/etc/passwd`，WAF 收不到穿越串。要测真实穿越必须加 `--path-as-is`。
2. **server 级 `if` 在 location 选择之前执行**：最初把 `if ($waf_block = 1) { return 403; }`
   写在 server 级末尾，导致假 200 的 location 永远不命中。现在 WAF 判断放进 `location /` 内部。
3. **`$uri` 已被规范化，`$request_uri` 才是原始串**：穿越规则必须用后者。
