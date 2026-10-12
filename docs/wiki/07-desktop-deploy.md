# 07 · 桌面端、靶场与部署

> 本篇回答：除了命令行，项目还能怎么跑？靶场怎么起？容器怎么部署？CI 门禁盯的是什么？测试怎么执行？

本章覆盖四类"运行形态"：**桌面端（Tauri）**、**靶场（lab/）**、**容器部署（Docker）**、**CI 与测试**。

---

## 1. 四种运行形态总览

| 形态 | 入口 | 依赖 | 适用场景 |
|------|------|------|---------|
| CLI | [main.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/main.py) | `pip install .` | 日常扫描、CI 集成 |
| Web API | `main.py --serve` | `pip install ".[serve]"` | 团队共用、被其它系统调用 |
| 桌面端 | `desktop/`（Tauri 壳） | 发布版自带引擎 | 非技术用户一键使用 |
| 容器 | [Dockerfile](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/Dockerfile) / [docker-compose.yml](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/docker-compose.yml) | Docker | 批量部署、靶场联调 |

四者共用同一套 `core/` 引擎——桌面端与容器只是**换了个进程外壳**，不存在第二份扫描逻辑。

---

## 2. 桌面端：Tauri 壳 + 内嵌引擎

### 2.1 设计目标

单 exe、双击即用、零 Python 环境依赖。做法是把 PyInstaller 打出的引擎**编译期嵌入** Rust 壳，运行时自解压后拉起。

目录结构：

```
desktop/
├── src/                 # React 18 + Vite + Tailwind 前端
├── src-tauri/           # Rust 壳（Tauri 2）
│   ├── build.rs         # 编译期嵌入引擎
│   ├── src/lib.rs       # 运行时：自解压 + 拉起 + JobObject 回收
│   └── tauri.conf.json
├── engine/              # PyInstaller 打包脚本与产物（dist/ruoyi-scan-engine.exe）
├── package.json / vite.config.ts / tsconfig.json
└── make_icon.py / app-icon.png
```

### 2.2 编译期嵌入：`build.rs`

[build.rs](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/desktop/src-tauri/build.rs) 只有 25 行，逻辑是"有引擎就复制，没有就写 0 字节占位"：

```
engine/dist/ruoyi-scan-engine.exe
        │ 存在 → std::fs::copy
        ▼
$OUT_DIR/embedded_engine.bin  ← lib.rs 用 include_bytes! 固定路径读取
```

- **有引擎**：复制到 `OUT_DIR`，打印 `cargo:warning=嵌入引擎 xxx (N MB)`。
- **无引擎**：写入 `b""`（0 字节），提示"开发模式构建（不嵌入引擎）"。
- `cargo:rerun-if-changed` 指向引擎文件，保证引擎换了会重新触发构建。

这样开发者本地 `cargo tauri dev` 无需先构建引擎（会自动回退 Python），而 CI/发布流水线先跑引擎打包再构建壳，得到单文件 exe。

### 2.3 运行时：引擎自解压

[lib.rs](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/desktop/src-tauri/src/lib.rs) 中：

```rust
const API_PORT: u16 = 8123;
static EMBEDDED_ENGINE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/embedded_engine.bin"));
```

`materialize_engine()` 的流程与三个关键设计：

| 步骤 | 实现 | 为什么 |
|------|------|--------|
| 判断是否需解压 | 以「字节数 + 简单校验和」写入 `.engine-stamp`，与当前不匹配才解压 | 壳升级换引擎时自动覆盖旧产物；同版本启动零解压开销 |
| 解压目录 | Windows `%LOCALAPPDATA%\Ruoyi-Scan\engine\`，其它平台 `~/.ruoyi-scan/engine/` | 用户目录可写，不触发 UAC |
| 原子写入 | 先写 `.engine.tmp` 再 `rename` | 写入中断不会留下残缺引擎 |
| 被占用时 | `rename` 失败且 8123 端口已开 → **复用现有引擎** | 引擎正在运行、文件被锁定时仍能启动 |
| 0 字节判断 | `EMBEDDED_ENGINE.is_empty()` → 返回 `None` | 开发模式信号，触发 Python 回退 |

### 2.4 进程回收：Windows JobObject

壳进程崩溃或被任务管理器强杀时，必须保证引擎进程树被回收，否则 8123 端口被孤儿进程长期占用。

`tie_to_job()` 用 `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` 解决：

```rust
info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
SetInformationJobObject(job, JobObjectExtendedLimitInformation, ...);
AssignProcessToJobObject(job, child.as_raw_handle());   // 失败重试 3 次
```

三个实现细节值得注意：

1. **Job 句柄刻意不 `CloseHandle`**——它必须随壳进程存活，壳退出时由内核关闭句柄并触发 `KILL_ON_JOB_CLOSE`。源码注释明确写着「句柄泄漏在此处是设计意图，不是缺陷」。
2. **挂接失败重试 3 次（每次间隔 50ms）**——子进程可能已先挂进别的 Job（嵌套限制），瞬时失败可被吸收。
3. **`write_job_diag()` 落盘诊断**——release 版壳是 GUI 子系统，stderr 不可见，只能写文件。
4. 非 Windows 平台 `tie_to_job` 是空实现（返回 `false`），靠 `RunEvent::Exit` 时显式 `child.kill() + child.wait()` 兜底。

### 2.5 拉起后端：`spawn_backend()`

```
port_open(8123)? ──是──→ 跳过拉起，直接连已有服务
        │否
        ▼
materialize_engine() ──Some(exe)──→ 拉起引擎 exe        ← 发布路径
        │None
        ▼
python main.py --serve                                  ← 开发回退（RUOYI_SCAN_PYTHON 可覆盖解释器）
```

两种路径的启动参数完全一致：

```
--serve --host 127.0.0.1 --port 8123 --cors-origins <列表> --no-cta
```

- **只绑 `127.0.0.1`**：桌面端后端不对外暴露。
- **CORS 白名单**固定四项：`http://tauri.localhost`、`https://tauri.localhost`、`http://localhost:5173`、`http://127.0.0.1:5173`（后者供 `vite dev` 调试）。
- **`--no-cta`**：桌面端不显示 CLI 的 Star 引导。

子进程句柄存在 Tauri 的 `BackendChild(Mutex<Option<Child>>)` 里，`RunEvent::Exit` 时取出并 kill。

### 2.6 前端结构

`desktop/src/` 按职责分层：

| 目录 | 内容 |
|------|------|
| `views/` | 六个主视图：`Overview`、`LiveScan`、`Reports`、`VulnDb`、`Assets`、`Settings` |
| `components/` | `Sidebar`、`Topbar`、`NewScanDialog`、`SchedulePanel`、`charts/`、`icons/`、`ui/` |
| `state/` | `AppCtx` / `PersonaCtx` 上下文、`useScanConsole`（WS 事件消费）、`personalize`、`personaHooks`、`widgets/`、`visual/` |
| `services/backend.ts` | 后端 HTTP + WebSocket 客户端封装 |
| `data/mock.ts` | 离线/演示数据 |
| `persona.ts` / `persona.css` / `tokens.ts` | 主题与角色定制（含 10 个头像资源） |
| `styles/theme.css` | 全局样式基线 |

前端不直接扫描，全部经 `services/backend.ts` → 本地引擎的 REST/WS 接口。

---

## 3. 靶场：`lab/`

靶场是**误报红线的物理保障**——每个插件必须有"vuln 模式命中 / safe 模式零命中"的证据。

### 3.1 文件构成

| 路径 | 作用 |
|------|------|
| [lab/server.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/lab/server.py) | 若依签名靶场（Flask），覆盖 ruoyi 插件包的签名路径 |
| [lab/spring_server.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/lab/spring_server.py) | Spring 签名靶场 |
| [lab/run_acceptance.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/lab/run_acceptance.py) / `.sh` | 验收驱动脚本 |
| `lab/real-spring/` | 真实 Spring 靶场（纯 Flask 模拟，CI 自动跑） |
| `lab/real-ruoyi/` | 真实 RuoYi（Java + MySQL + Maven，源码不入 git，体积过大） |
| `lab/fp_lab/` | 误报测试语料 |
| `lab/version_matrix/` | 版本感知路由的验证矩阵 |
| `lab/Dockerfile` | 靶场镜像（`SERVER_FILE` 选择哪个 server） |
| `REAL-RUOYI.md` / `REAL-SPRING.md` / `VULN-REINTRODUCE.md` | 复现与"漏洞重新引入"操作手册 |

### 3.2 双模式开关

靶场由环境变量驱动，**同一份代码两种姿态**：

| 变量 | 取值 | 含义 |
|------|------|------|
| `SERVER_FILE` | `server.py` / `spring_server.py` | 选靶场实现 |
| `LAB_MODE` | `vuln` | 带洞，扫描器应全部 `CONFIRMED` |
| `LAB_MODE` | `safe` | 已修复，扫描器必须 **0 命中**（误报红线） |
| `LAB_PORT` | 端口 | 监听端口（默认 8080 / 8091） |
| `LAB_HOST` | 绑定地址 | 容器内用 `0.0.0.0`，本机如需隔离可设 `127.0.0.1` |

`safe` 模式的存在不是为了"跑通"，而是为了让**误报**在 CI 里变成一个会红的 job。

---

## 4. 容器部署

### 4.1 Dockerfile：两阶段构建

[Dockerfile](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/Dockerfile) 结构：

```
阶段 1 builder  python:3.11-slim + gcc
                venv 建在 /opt/venv → pip install -r requirements.txt（利用层缓存）
        │ COPY --from=builder /opt/venv
        ▼
阶段 2 runtime  python:3.11-slim
                非 root 用户 scanner（nologin shell）
                PYTHONUNBUFFERED=1 / PYTHONDONTWRITEBYTECODE=1
                ENTRYPOINT ["python", "main.py"]   CMD ["-h"]
```

要点：

- **`ENTRYPOINT` 固定为 `main.py`，`CMD` 只提供默认参数**——所以 `docker run ruoyi-scan -p http://target/` 追加的参数会正确落到 CLI。
- **非 root 用户 `scanner`**，并以 `--chown=scanner:scanner` 复制源码，`/app/reports`、`/app/data` 预先 chown（非 root 下可写）。
- **先 COPY requirements.txt 再装依赖**，改代码不失效依赖层缓存。

### 4.2 docker-compose：六服务

[docker-compose.yml](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/docker-compose.yml) 定义：

| 服务 | 镜像/构建 | 端口 | 说明 |
|------|----------|------|------|
| `scanner` | `build: .` | — | CLI 形态，`command: -h`，运行扫描用 `docker compose run --rm scanner ...` |
| `api` | `build: .` | `8000:8000` | `--serve --host 0.0.0.0 --port 8000`，挂载 `./data`（SQLite）与 `./reports` |
| `lab-ruoyi` | `build: ./lab` | `127.0.0.1:8080:8080` | 若依靶场，`LAB_MODE=vuln` |
| `lab-spring` | `build: ./lab` | `127.0.0.1:8091:8091` | Spring 靶场，`LAB_MODE=vuln` |
| `prometheus` | 官方镜像 | `127.0.0.1:9090:9090` | `profiles: ["monitor"]` |
| `grafana` | 官方镜像 | `127.0.0.1:3000:3000` | `profiles: ["monitor"]` |

### 4.3 网络与安全收口

**两个独立网络**，避免监控栈与靶场互通：

- `default`：`scanner` / `api` / 两个靶场互通
- `monitor`：`api` / `prometheus` / `grafana` 互通（`api` 同时挂两个网络）

**端口绑定是本文件最值得注意的安全设计**：

```
lab-ruoyi:  "127.0.0.1:8080:8080"     # 带洞靶场绝不暴露到局域网
lab-spring: "127.0.0.1:8091:8091"
prometheus: "127.0.0.1:9090:9090"
grafana:    "127.0.0.1:3000:3000"
```

容器内 `LAB_HOST=0.0.0.0` 保证 `scanner`/`api` 能互通，但**宿主侧强制回环绑定**——"带洞靶场暴露到局域网"是这类项目最常见的事故，这里用一行端口映射堵死。

其它收口：

- `api` 默认不设 API Key（注释明确"仅允许容器内/本地访问；生产部署请设置 `--api-key` 或环境变量"）。
- `grafana` 默认密码走 `GRAFANA_ADMIN_PASSWORD` 环境变量，`GF_USERS_ALLOW_SIGN_UP=false`。
- `api` 带 healthcheck，打 `/api/system/health`。
- Prometheus 保留 7 天（`--storage.tsdb.retention.time=7d`），配置挂载 `monitoring/prometheus.yml` 只读。

**注**：`thinkphp` / `weaver` 靶场已随插件迁移到外部 `cms-scan-extras/`，compose 里只剩两个 CMS 签名靶场。

---

## 5. CI 工作流

`.github/workflows/` 下 8 个文件：

| 工作流 | 触发 | 职责 |
|--------|------|------|
| [ci.yml](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/.github/workflows/ci.yml) | push/PR/tag | 主门禁（见下） |
| `codeql.yml` | 定时/PR | CodeQL 静态分析 |
| `security-scan.yml` | 定时/PR | 依赖与漏洞扫描 |
| `scorecard.yml` | 定时 | OpenSSF Scorecard 供应链评分 |
| `release.yml` | tag | 发布（等待 CI 门禁通过） |
| `desktop-release.yml` | tag | 桌面端打包与发布 |
| `docs-site.yml` | push | mkdocs 文档站构建 |
| `nightly-acceptance.yml` | 每日 | 夜间验收 |

### 5.1 `ci.yml` 七个 job

```
lint ──┬── unit（os × py 矩阵）
       └── nuclei-templates
unit ──┬── signature-e2e（ruoyi + spring 靶场，要求全部 CONFIRMED）
       ├── report-format（PDF/Word/Excel + 去重）
       ├── waf-bypass（D7）
       ├── web-api（D9）
       ├── real-spring（期望 ≥11 CONFIRMED）
       └── real-ruoyi（Java+MySQL，源码缺失时自动跳过，continue-on-error）
```

**lint job 的三道硬门禁**（都值得留意）：

1. **ruff check 覆盖 `tests/` 与 `scripts/`**——注释说明"测试代码同样是仓库主体（65 文件），此前不受约束导致未用导入与导入顺序持续漂移"，而 `desktop/`、`lab/` 不纳入（独立产物 / 一次性脚本）。
2. **版本固定**：`pip install ruff==0.16.2 mypy==2.1.0`。理由写在注释里：「ruff format 输出随版本演进，不固定会造成 CI 与本地格式漂移（v1.2.3/v1.2.4 期间 CI 连红的根因）」。
3. **mypy 门禁分层**：`common/` 与 `core/` 全量 `--strict`（G2 完成后从 350 个错误清零，去掉软门禁 `|| true`），`lib/` 只锁定已 strict 化的 `reporter.py`、`soft404.py`。

**两道"文档—代码一致性"门禁**（较少见但很有价值）：

```bash
python scripts/verification_matrix.py --check --max-none 13   # 无验证插件数只许降不许升
python scripts/verification_matrix.py > /tmp/matrix.md         # 生成物必须与 docs/verification-matrix.md 一致
diff -u docs/verification-matrix.md /tmp/matrix.md
```

第一条用**上限而非"必须为 0"**：注释解释"立即清零不现实，但数量只应下降——避免插件数涨、验证覆盖率降这种静默劣化"。

**unit job 的覆盖率棘轮**（按目录，而非全仓统一阈值）：

| 目录 | 实测 | CI 阈值 |
|------|------|--------|
| `core` | 81% | 78 |
| `common` | 87% | 84 |
| `lib` | 75% | 72 |
| `api` | 88% | 85 |
| `plugins` | 78% | 75 |
| `chains` | 100% | 95 |

放弃 `--cov-fail-under` 全仓门槛的理由写得很清楚：「统一阈值会让低覆盖模块躲在平均值后面（lib/ 5774 语句仅 75%，api/ 88%——均值把它们拉平）」。阈值取"当前值下浮 3 个点"，只许升不许降。

**e2e 的 `--allow-safe` 名单**：`signature-e2e` 要求全部 `CONFIRMED`，但显式豁免 4 项，理由是它们**结构性不可能 CONFIRMED**：

- `Redis 未授权访问` / `MinIO 未授权访问` / `RocketMQ Dashboard 未授权`——中间件探测，靶机无该服务即 `SAFE`；
- `shiro_rememberme`——指纹类探测，只有 `SAFE`（无特征）或 `UNKNOWN`（有特征需验密钥）两种判定。

**Windows 矩阵的作用**：`os: [ubuntu-latest, windows-latest]`，注释写"国内使用主力环境之一，防编码（GBK）/路径分隔符回归"。pytest 超时方式也随平台切换：POSIX 用 `signal`，Windows 用 `thread`。

---

## 6. 测试体系

### 6.1 规模与配置

`tests/` 约 66 个 `.py`。配置在 [pyproject.toml](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/pyproject.toml)：

```toml
[tool.pytest.ini_options]
testpaths = ["tests"]
python_files = ["test_*.py"]
addopts = "-q --timeout=30 --timeout-method=thread"
```

两个回归脚本不走 pytest：`tests/regression_ruoyi.py`、`tests/regression_spring.py`（CI 直接 `python` 执行）。

### 6.2 `conftest.py` 的三个关键设计

[tests/conftest.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/tests/conftest.py) 不只是堆 fixture，它解决了两个真实踩过的坑：

**① 进程退出安全网（CI 挂起根因）**

`concurrent.futures` 在 import 时通过 `atexit.register(_python_exit)` 注册了 handler，它会 join 所有 `ThreadPoolExecutor` 线程——**包括 `ScanEngine` 内部线程池的非 daemon 线程**。当 mock fixture 失效后后台线程加载真实插件并发起 HTTP 请求，join 无限等待 → pytest 进程挂起。

解法是抢在 `_python_exit` 之前注册自己的 handler，用 `os._exit` 绕过后续所有 atexit：

```python
def _force_exit_bypass_thread_join():
    _sys.stdout.flush(); _sys.stderr.flush()
    _os._exit(_exit_code_holder["code"])

atexit.register(_force_exit_bypass_thread_join)
```

配套的 `pytest_sessionfinish` 记录 exitstatus，保证退出码正确。这与 [03 章](03-core.md) 里 `_DaemonThreadPoolExecutor` 的做法是**同一个问题的两个战场**。

**② 会话级输出静默**

`_quiet_reporter` fixture（`autouse=True, scope="session"`）默认调 `set_quiet(True)`。原因：误报基线测试单次执行要跑 51 插件 × 多条语料，此前会倾倒约 **2 MB** 文本淹没失败信息。需要观察时设 `RUOYI_SCAN_TEST_VERBOSE=1`。

**③ fixture 分层**

| 层 | fixture | 用途 |
|----|---------|------|
| 网络 mock | `mock_router`、`mock_network` | mock `Router` / `detect_cms` / `detect_waf` / `load_plugins` |
| 应用 | `app`、`app_with_key`、`app_in_memory`、`client`、`client_with_key`、`client_factory` | `create_app()` 带临时 SQLite |
| 核心对象 | `storage`、`registry`、`registry_factory`、`mock_registry`、`orch` | 直接实例化 |
| 请求工厂 | `make_scan_request`、`sample_scan_request` | 替代 22 处 `ScanRequest` 构造 |
| 目录 | `tmp_report_dir`、`cache_db_path` | 统一临时目录风格 |

两处刻意的约束：

- `client` fixture **显式依赖 `mock_network`**——保证 `orchestrator.shutdown()` 在 mock 仍生效时执行，避免后台线程脱离 mock 后加载真实插件发起 HTTP 导致挂起。
- `mock_network` 里 `detect_cms` 返回**真实 `FingerprintResult` 而非裸 `MagicMock`**——保证 fingerprint 事件 payload 可 JSON 序列化，维护 WS 推送 / 历史落盘的契约。
- `conftest.py` 顶部说明：旧文件里的 `sys.path.insert` 与重复 fixture **不立即删除**，新 fixture 供后续迁移，保证渐进式重构安全。

### 6.3 运行方式

```bash
pip install -r requirements-dev.txt

pytest                                  # 全量（addopts 已含 --timeout=30）
pytest tests/test_orchestrator.py -v    # 单文件
pytest -q --timeout-method=signal       # POSIX 上用 signal 超时
pytest --cov=core --cov=common --cov=lib --cov=api --cov=plugins --cov=chains
coverage report --include="*/core/*" --fail-under=78   # 复现 CI 棘轮
RUOYI_SCAN_TEST_VERBOSE=1 pytest        # 需要看插件进度时
```

---

## 7. 辅助脚本 `scripts/`

| 脚本 | 作用 |
|------|------|
| [run_e2e.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/scripts/run_e2e.py) | 端到端验收：起靶场 → 扫描 → 断言命中数（`--require-all-confirmed` / `--min-confirmed N` / `--allow-safe`） |
| [verification_matrix.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/scripts/verification_matrix.py) | 生成检出能力矩阵（"插件 × 有无自动化验证证据"），CI 用它做棘轮门禁 |
| [run_fp_test.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/scripts/run_fp_test.py) | 误报测试驱动 |
| [build_offline_cve.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/scripts/build_offline_cve.py) | 构建离线 CVE 库 `data/cve_offline.json` |
| [export_openapi.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/scripts/export_openapi.py) | 导出 OpenAPI schema（供前端/文档使用） |
| [build_release.sh](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/scripts/build_release.sh) | 发布构建 |

---

## 8. 小结：本章的设计意图

| 现象 | 意图 |
|------|------|
| 引擎编译期嵌入而非运行时下载 | 断网可用、无中间人风险、单 exe |
| Job 句柄故意不关闭 | 壳被杀也要回收引擎树（注释显式声明"不是缺陷"） |
| 靶场 `safe` 模式进 CI | 误报成为会红的 job，而非口头约定 |
| 靶场端口仅绑 `127.0.0.1` | 带洞靶场绝不暴露局域网 |
| 覆盖率按目录设阈值 | 防止低覆盖模块躲在全仓均值后 |
| `--max-none 13` 而非必须为 0 | 用棘轮替代不切实际的一次性清零 |
| ruff/mypy 版本固定 | 消除 CI 与本地格式漂移 |
| `conftest.py` 抢注册 atexit | 绕过 `_python_exit` 的无限 join |
| 旧 fixture 不立即删除 | 渐进式重构，保证测试长期可运行 |

---

**上一篇**：[06 Web API 与控制台](06-api-web.md) · **下一篇**：[08 依赖关系](08-dependencies.md)