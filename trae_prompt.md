# Trae 长程任务提示词 — Ruoyi-Scan 后续升级开发

请按以下阶段顺序，逐阶段完成 Ruoyi-Scan 多 CMS 漏洞扫描器的后续升级开发。每个阶段完成后请自行运行全量测试（pytest + 各 regression 回归脚本），确认全部通过再进入下一阶段，并将完成情况汇报给我。

---

## 项目当前基线

这是一款合法授权的**多 CMS 漏洞扫描器**，当前覆盖 3 个 CMS 共 30 个 POC 插件，已实现批量扫描（`-f`）与报告（HTML/JSON/CSV + batch_report）。

**目录结构（关键部分）**
```
./
├── main.py                      # CLI 入口（argparse）
├── core/
│   ├── fingerprint.py           # detect_cms(target, session) 多CMS自动识别
│   ├── router.py                # 指纹→插件包路由（mapping dict）
│   ├── engine.py                # 扫描引擎（并发/限速）
│   ├── report.py                # ReportBuilder(单目标) + BatchReport(批量汇总)
│   ├── models.py                # ScanResult / FingerprintResult / STATUS_*
│   ├── loader.py                # load_plugins(package) 动态导入
│   └── session.py               # SessionManager(requests.Session封装)
├── plugins/
│   ├── base.py                  # PluginBase抽象基类
│   ├── ruoyi/                   # 11个POC插件
│   ├── thinkphp/                # 10个POC插件
│   └── spring/                  # 9个POC插件
├── lib/
│   ├── fingerprint_features.py  # CMS_FEATURES数据驱动特征库
│   ├── http.py                  # normalize_target / join_url / host_of
│   ├── colors.py                # 终端颜色
│   └── matcher.py               # 响应匹配工具
├── lab/
│   ├── server.py                # RuoYi Flask签名靶场(LAB_MODE=vuln/safe)
│   ├── thinkphp_server.py       # ThinkPHP Flask签名靶场
│   └── spring_server.py         # Spring Boot Flask签名靶场
├── tests/
│   ├── test_fingerprint.py      # 指纹模块单元测试
│   ├── test_report.py           # 报告模块单元测试
│   ├── regression_ruoyi.py      # RuoYi插件回归(requests_mock, 30例)
│   ├── regression_thinkphp.py   # ThinkPHP插件回归(20例)
│   └── regression_spring.py     # Spring插件回归(18例)
└── config/
    └── settings.py              # 全局配置(VERSION/AUTHOR/REPORT_DIR等)
```

**当前 POC 分布**
| CMS | 插件数 | RCE | 信息泄露 | SQLi | 其他 |
|-----|--------|-----|----------|------|------|
| ruoyi | 11 | 5 | 2 | 0 | 4 |
| thinkphp | 10 | 6 | 2 | 1 | 1 |
| spring | 9 | 6 | 3 | 0 | 0 |
| **合计** | **30** | **17** | **7** | **1** | **5** |

---

## 核心约定（务必遵守，违反会导致框架崩溃）

1. **判定三态**：`CONFIRMED` / `SAFE` / `UNKNOWN`。网络异常等不可判定情况必须返回 `ScanResult(status=STATUS_UNKNOWN, ...)`，**绝不判 SAFE**。
2. **插件接口**：继承 `plugins.base.PluginBase`，实现 `verify(self, target, session) -> ScanResult`；类属性 name/cve/severity/category/description/fix。
3. **URL 拼接**：一律用 `lib.http.join_url(target, '/path')`；path 用**前导斜杠**（`/index.php` 而非 `index.php`）。
4. **降误报**：SAFE 判定必须基于明确证据（响应缺签名/关键字），不能仅看 200。
5. **框架零改动原则**：新增 CMS 或漏洞仅加数据/插件，`core/engine.py`、`core/report.py`（主体逻辑）不改动。`core/router.py` 仅 mapping 加一行。
6. **签名靶场**：仅返回与判定规则匹配的响应签名，不含真实漏洞利用。`LAB_MODE=vuln` 返回签名，`LAB_MODE=safe` 返回 404 或正常响应。
7. **回归测试**：用 `requests_mock` 模拟 HTTP 响应，每个插件至少 vuln→CONFIRMED 和 safe→SAFE 两个用例。
8. **端到端验证**：启动靶场 → `main.py -p http://127.0.0.1:8090/` → 确认 vuln 全 CONFIRMED / safe 全 SAFE。

---

## 测试验证命令（每阶段完成后执行）

```bash
# 1. 单元测试
python -m pytest tests/ -q

# 2. 各 CMS 插件回归
python tests/regression_ruoyi.py
python tests/regression_thinkphp.py
python tests/regression_spring.py
# 新增 CMS 加对应 regression_<cms>.py

# 3. 端到端对拍（以阶段四泛微为例）
# 3a. 杀旧靶场进程
PIDS=$(netstat -ano | grep -E ":809[01]" | grep LISTENING | awk '{print $5}' | sort -u)
for pid in $PIDS; do taskkill /F /PID $pid 2>/dev/null; done
# 3b. 启动 vuln 靶场
LAB_MODE=vuln LAB_PORT=8090 python lab/weaver_server.py > /tmp/wv_vuln.log 2>&1 &
# 3c. 启动 safe 靶场
LAB_MODE=safe LAB_PORT=8091 python lab/weaver_server.py > /tmp/wv_safe.log 2>&1 &
# 3d. 等待就绪后对拍
python main.py -p http://127.0.0.1:8090/   # 期望全部 CONFIRMED
python main.py -p http://127.0.0.1:8091/   # 期望全部 SAFE
# 3e. 清理
PIDS=$(netstat -ano | grep -E ":809[01]" | grep LISTENING | awk '{print $5}' | sort -u)
for pid in $PIDS; do taskkill /F /PID $pid 2>/dev/null; done
```

**注意：真实 RuoYi 4.7.8 实例长期运行于 127.0.0.1:8080（java 进程），清理靶场时勿误杀。8080 不是靶场端口范围（8090/8091 用于临时靶场）。**

---

## 【阶段四】第四个 CMS — 泛微 e-cology OA 插件包

### 步骤 1：特征库注册
在 `lib/fingerprint_features.py` 的 `CMS_FEATURES` 字典末尾（`'spring':` 条目之后，`}` 之前）新增：
```python
'weaver': {
    'display': 'Weaver e-cology',
    'favicon_hashes': set(),
    'strong_paths': [
        {'path': '/login/Login.jsp', 'expect': 'any'},  # OA 登录页
    ],
    'login_keywords': ['泛微', 'e-cology', 'weaver'],
    'weak_keywords': ['ecology', 'weaver', 'OA'],
    'weight_strong': 0.5,
    'weight_weak': 0.2,
},
```

### 步骤 2：创建 6 个 POC 插件（`plugins/weaver/`）

每个插件遵循已有模式（参考 `plugins/spring/actuator_unauth.py` 或 `plugins/thinkphp/invoke_rce.py`）：
- 文件顶部注释说明漏洞原因、影响版本
- 定义 `XXX_MARKER = 'weaver-xxx-confirmed'` 签名常量
- 类继承 `PluginBase`，类属性完整（name/cve/severity/category/description/fix）
- `verify(target, session)` 方法：构造探针请求 → 检查响应含 marker → 返回 `ScanResult`
- 网络异常 catch 返回 `ScanResult(status=STATUS_UNKNOWN)`
- SAFE 返回 `ScanResult(status=STATUS_SAFE)`

**插件清单（6 个，按危害度排序）**

**(A) `weaver_file_upload.py` — 任意文件上传 getshell（CNVD-2021-49104，high）**
- 探针：POST `/weaver/weaver.file.FileDownloadForOutDoc` 或 `/page/exportImport/uploadOperation.jsp`，multipart 上传测试文件
- 签名：`weaver-file-upload-rce-confirmed`

**(B) `weaver_xml_rce.py` — XMLDecoder 反序列化 RCE（CVE-2022-26134，high）**
- 探针：POST `/weaver/bsh.servlet.BshServlet` 或 XML 相关端点
- 签名：`weaver-xml-rce-confirmed`

**(C) `weaver_bsh_rce.py` — Beanshell 脚本执行 RCE（high）**
- 探针：POST `/weaver/bsh.servlet.BshServlet`，`bsh.script=print("probe")`
- 签名：`weaver-bsh-rce-confirmed`

**(D) `weaver_sqli.py` — SQL 注入（CNVD-2022-43245，high）**
- 探针：GET `/weaver/` 路径带 SQL 注入 payload（union select 或 extractvalue 探针）
- 签名：`weaver-sqli-confirmed`

**(E) `weaver_unauth.py` — 未授权访问 / 敏感信息泄露（medium）**
- 探针：GET `/weaver/` 或 `/login/Login.jsp` → 200 + 含 `weaver` 关键字（无需认证即可访问内部路径）
- 判定：路径 200 + 响应含关键字即判 CONFIRMED（不需要 marker，类似 `actuator_unauth.py` 模式）

**(F) `weaver_info_leak.py` — 配置文件 / 数据库连接泄露（medium）**
- 探针：GET `/weaver/ecology.properties` 或 `/weaver/prop/` 等配置文件路径
- 签名：`weaver-info-leak-confirmed`

**插件包入口 `__init__.py`**
```python
# Weaver e-cology 插件包
from plugins.weaver.file_upload import WeaverFileUploadPlugin
from plugins.weaver.xml_rce import WeaverXmlRcePlugin
from plugins.weaver.bsh_rce import WeaverBshRcePlugin
from plugins.weaver.sqli import WeaverSqliPlugin
from plugins.weaver.unauth import WeaverUnauthPlugin
from plugins.weaver.info_leak import WeaverInfoLeakPlugin

plugin_list = [
    WeaverFileUploadPlugin,
    WeaverXmlRcePlugin,
    WeaverBshRcePlugin,
    WeaverSqliPlugin,
    WeaverUnauthPlugin,
    WeaverInfoLeakPlugin,
]
```

### 步骤 3：Router 注册
在 `core/router.py` 的 `mapping` dict 中加一行：
```python
'weaver': 'plugins.weaver',
```

### 步骤 4：签名靶场（`lab/weaver_server.py`）

Flask 双模式，参考 `lab/spring_server.py` 结构。需支持以下端点：

| 路径 | 方法 | vuln 响应 | safe 响应 |
|------|------|-----------|-----------|
| `/` | GET | HTML 含 "泛微 e-cology" 标题（指纹） | 同 vuln（指纹始终返回） |
| `/login/Login.jsp` | GET | HTML 含 "weaver" 登录页（指纹 + unauth） | 同 vuln |
| `/weaver/weaver.file.FileDownloadForOutDoc` | POST | 含 `weaver-file-upload-rce-confirmed` marker | 404 JSON |
| `/weaver/bsh.servlet.BshServlet` | POST | 含 `weaver-bsh-rce-confirmed` marker | 404 JSON |
| `/weaver/xml_endpoint` | POST | 含 `weaver-xml-rce-confirmed` marker | 404 JSON |
| `/weaver/sqlinject` | GET | 含 `weaver-sqli-confirmed` marker | 404 JSON |
| `/weaver/ecology.properties` | GET | 含 `weaver-info-leak-confirmed` marker | 404 |

靶场模板结构：
```python
import os, json
from flask import Flask, request, Response

MODE = os.environ.get('LAB_MODE', 'vuln')
PORT = int(os.environ.get('LAB_PORT', '8090'))
app = Flask(__name__)

# 定义 marker 常量（与插件 MARKER 一致）
MARKER_UPLOAD = 'weaver-file-upload-rce-confirmed'
MARKER_XML = 'weaver-xml-rce-confirmed'
MARKER_BSH = 'weaver-bsh-rce-confirmed'
MARKER_SQLI = 'weaver-sqli-confirmed'
MARKER_LEAK = 'weaver-info-leak-confirmed'

def is_vuln(): return MODE == 'vuln'

def dispatch(path, method):
    vuln = is_vuln()
    if path == '/':
        return html_body('<html><head><title>泛微 e-cology OA</title></head><body>Weaver e-cology</body></html>')
    # ... 各端点判断
    return json_err(404, path)

@app.route('/', defaults={'p': ''}, methods=['GET','POST'])
@app.route('/<path:p>', methods=['GET','POST'])
def _route(p): return dispatch(request.path, request.method)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PORT, debug=False)
```

### 步骤 5：回归测试（`tests/regression_weaver.py`）

参考 `tests/regression_spring.py` 结构，6 个插件 × 2 status = 12 例。每个测试类含 `test_hit`（mock 返回 marker → 断言 `STATUS_CONFIRMED`）和 `test_safe`（mock 返回 404 → 断言 `STATUS_SAFE`）。

**同时更新 `tests/test_fingerprint.py`**：
- 新增 `test_detect_cms_selects_weaver()`：FakeSession mock `/login/Login.jsp` 返回含 `e-cology` 响应
- 新增 `test_router_resolves_weaver()`：断言 `len(plugins) == 6`
- 在 `if __name__ == '__main__':` 块中按顺序注册这两个新测试函数

### 步骤 6：验证
1. `python -m pytest tests/ -q` → 全部通过（含新指纹测试）
2. `python tests/regression_weaver.py` → 12/12 全绿
3. `python tests/regression_ruoyi.py` / `regression_thinkphp.py` / `regression_spring.py` → 全部通过（无回退）
4. 启动靶场 `main.py -p http://127.0.0.1:8090/` → vuln 模式 6 个全 CONFIRMED
5. 启动靶场 `main.py -p http://127.0.0.1:8091/` → safe 模式 6 个全 SAFE（零误报）
6. 清理靶场进程

---

## 【阶段五】指纹去重优化

### 背景
`core/fingerprint.py` 的 `detect_cms()` 为每个注册 CMS 独立发送主页和 favicon 请求，多个 CMS 时重复 GET 相同 URL。

### 步骤 1：新建 `core/cache.py`

```python
# 指纹识别请求级缓存：同一 URL 的 GET 结果在单次检测中只发一次
class FingerprintCache:
    def __init__(self, session):
        self._cache = {}
        self._session = session

    def get(self, url):
        """返回缓存响应或发起请求并缓存结果"""
        if url not in self._cache:
            try:
                self._cache[url] = self._session.get(url)
            except Exception:
                self._cache[url] = None
        return self._cache[url]
```

### 步骤 2：修改 `core/fingerprint.py` 的 `detect_cms()`

在 `detect_cms(target, session)` 函数内部：
```python
from core.cache import FingerprintCache
cache = FingerprintCache(session)
```
将各 CMS 的 `FeatureBasedFingerprint(cms).detect(target, session)` 改为传入 `cache`：新增 `detect_with_cache(target, cache)` 方法或直接在 `detect_cms()` 中创建缓存共享给各 `FeatureBasedFingerprint` 实例。

简明实现：修改 `FeatureBasedFingerprint.detect()` 的参数，增加可选 `cache=None`。当 cache 存在时，`session.get(target)` 和 `session.get(target+'favicon.ico')` 等调用改用 `cache.get(url)`。

### 步骤 3：单元测试（`tests/test_cache.py`）

```python
import unittest
from core.cache import FingerprintCache
from core.session import SessionManager

class TestFingerprintCache(unittest.TestCase):
    def test_cache_hit(self):
        sess = SessionManager()
        cache = FingerprintCache(sess)
        # 需要使用 mock 验证第二次 get 不发起新请求
        # 这里用 requests_mock 验证
        
    def test_cache_key_url(self):
        # 验证不同 URL 缓存隔离
        pass
```

### 步骤 4：验证
1. `python -m pytest tests/ -q` → 全部通过
2. 所有 regression 验证确认无回退
3. 用 `main.py -p <target> --debug` 观察请求数减少

---

## 【阶段六】报告可视化加强

### 背景
当前 HTML 报告仅表格，增加纯 SVG 图表（零外部依赖）。

### 步骤：修改 `core/report.py`

在 `ReportBuilder.to_html()` 的模板中，风险分布 `<div>` 之后、详细结果 `<h2>` 之前，插入内联 SVG 环形图代码。数据源来自 `self.risk_distribution()` 已有的 high/medium/low 计数。

```html
<!-- 内嵌 SVG 风险分布环形图 -->
<div style="margin:15px 0">
  <svg viewBox="0 0 200 200" width="200" height="200">
    <!-- 三色环形图，使用 stroke-dasharray 计算比例 -->
    <circle cx="100" cy="100" r="80" fill="none" stroke="#e0e0e0" stroke-width="20"/>
    <!-- high: 红色弧 -->
    <!-- medium: 黄色弧 -->
    <!-- low: 绿色弧 -->
    <!-- 中心文字：合计漏洞数 -->
    <text x="100" y="100" text-anchor="middle" dominant-baseline="central"
          font-size="28" font-weight="bold" fill="#333">{total}</text>
    <text x="100" y="120" text-anchor="middle" font-size="12" fill="#999">确认漏洞</text>
  </svg>
</div>
```

同时更新 `BatchReport.to_html()` 的汇总表增加简单的柱状图（SVG rect 元素）。

### 验证
1. 用 `main.py -p <target> --report ./reports` 生成报告
2. 打开 `report.html` 查看图表是否正常渲染
3. 打开 `batch_report.html` 查看汇总图表
4. pytest + regression 全绿（报告测试 `test_report.py` 需要更新以验证新 HTML 输出）

---

## 【阶段七】Docker 一键部署

### 步骤 1：创建 `requirements.txt`（若不存在）

运行 `pip freeze > requirements.txt` 或手动列出：
```
requests>=2.28
flask>=2.3
requests-mock>=1.11
```

### 步骤 2：创建 `Dockerfile`

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENTRYPOINT ["python", "main.py"]
```

### 步骤 3：创建 `lab/Dockerfile`（靶场通用镜像）

```dockerfile
FROM python:3.11-slim
WORKDIR /app
RUN pip install flask
COPY . /app
# 入口点由环境变量 SERVER_FILE 决定运行哪个靶场
ENV SERVER_FILE=server.py
ENV LAB_MODE=safe
ENV LAB_PORT=8080
CMD sh -c "python $SERVER_FILE"
```

### 步骤 4：创建 `docker-compose.yml`

```yaml
version: '3.8'
services:
  scanner:
    build: .
    volumes:
      - ./reports:/app/reports
    command: -f targets.txt -p --report /app/reports
  
  lab-ruoyi:
    build: ./lab
    environment:
      SERVER_FILE: server.py
      LAB_MODE: safe
      LAB_PORT: 8080
  
  lab-thinkphp:
    build: ./lab
    environment:
      SERVER_FILE: thinkphp_server.py
      LAB_MODE: vuln
      LAB_PORT: 8090
  
  lab-spring:
    build: ./lab
    environment:
      SERVER_FILE: spring_server.py
      LAB_MODE: vuln
      LAB_PORT: 8091
```

### 验证
```bash
docker-compose up -d
curl http://localhost:8090/       # ThinkPHP vuln 靶场主页
docker-compose run scanner -p http://lab-thinkphp:8090/    # 扫描靶场
docker-compose down
```

---

## 【阶段八】各 CMS 深度扩充（增量迭代）

此阶段可在以上完成后，根据剩余时间选择性推进：

### RuoYi (11→13)
- `plugins/ruoyi/nacos_unauth.py`：Nacos 未授权访问
- `plugins/ruoyi/file_read_path.py`：文件下载路径穿越

### ThinkPHP (10→12)
- `plugins/thinkphp/request_rce_v2.py`：5.0.x Request input 其他变体
- `plugins/thinkphp/dispatch_rce.py`：5.1.x 路由调度其他链

### Spring Boot (9→11)
- `plugins/spring/jolokia_mlet_rce.py`：Jolokia MLet 链
- `plugins/spring/trace_leak.py`：/actuator/trace 泄露

### 泛微 OA (6→8)
- 新增 2 个插件（任意文件删除、XSS 等，按实际研究确认）

**每次扩充遵循相同流程：** 写插件 → 更新 __init__.py → 靶场加端点 → 回归测试加用例 → test_fingerprint 断言更新 → pytest + regression + 端到端验证。

---

## 【阶段九】真实目标交叉验证（可选）

1. 对 ThinkPHP：用 vulhub 的 thinkphp 镜像 `docker pull vulhub/thinkphp:5.0.23` 验证
2. 对 Spring：用公开 Spring Boot 靶场或自行部署含已知漏洞的版本验证
3. 记录验证结果到 `lab/REAL-*.md`，发现漏报/误报则修复对应插件并更新回归测试

---

## 完成标准（每个阶段）

- [ ] `python -m pytest tests/ -q` → 全部通过
- [ ] 所有 regression_*.py 全部通过（退出码 0）
- [ ] 新建/修改的代码符合核心约定（判定三态、插件接口、URL 拼接、降误报）
- [ ] 端到端对接通过（vuln 全 CONFIRMED / safe 零误报）
- [ ] 靶场已清理（真实 RuoYi 8080 不受影响）
- [ ] 汇报：阶段名 + 新增文件列表 + 测试结果摘要
