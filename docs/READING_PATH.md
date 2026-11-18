# 阅读路径（新人 5 天）

> 目标：第 1 天能跑，第 3 天能改插件，第 5 天能改判定。不要从 `core/orchestrator.py` 开始读。

---

## 路线 A：我要改一个检测插件（最常见）

1. 读 [CONCEPTS.md](CONCEPTS.md) 的 §1–§5（三态、原因码、插件契约、发现、能力声明）。
2. 读一个 60 行的样板：[plugins/ruoyi/ruoyi_swagger_unauth.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/plugins/ruoyi/ruoyi_swagger_unauth.py)。
3. 跑它：
   ```bash
   python main.py -p http://127.0.0.1:8080/ --cms ruoyi --debug
   ```
4. 写自己的：`python main.py --plugin-init my_check --framework ruoyi` → 改 `verify()`。
5. 验证：`python main.py --plugin-check plugins/ruoyi/my_check.py`，再跑 `tests/test_plugin_contracts.py`。

**必须知道的三个坑**（都在 [plugins/base.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/plugins/base.py) 注释里）：
声明必须与实现同批落地；匿名探测用 `session.anonymous()`；异常只能 UNKNOWN。

---

## 路线 B：我要改判定 / 降误报

1. [CONCEPTS.md](CONCEPTS.md) §7–§9（框架/版本/路径作用域/判定辅助）。
2. [lib/matcher.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/lib/matcher.py)：先找现有判据，别新写关键字。
3. [lib/reachability.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/lib/reachability.py)：登录墙/鉴权墙/全站拦截的降级规则。
4. [lib/soft404.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/lib/soft404.py)：catch-all 站点基线。
5. 用靶场验证正/负样本：`lab/` 下每个场景都有 vuln/safe 双模式。

---

## 路线 C：我要改编排 / 报告 / 服务

1. [CONCEPTS.md](CONCEPTS.md) §11–§12（限速/预算/熔断/报告）。
2. 主流程：[core/orchestrator.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/orchestrator.py) 的 `_run()`（先看步骤编号注释，不要逐行读）。
3. 引擎：[core/engine.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/engine.py) 的 `_exec()`（5 步：限速→实例化→verify→WAF→enrich）。
4. 会话：[core/session.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/session.py)（超时/熔断/代理/令牌桶都在这）。
5. 报告：[core/report.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/report.py) 的 `render_all()`；格式器在 `core/report_*.py`。
6. 服务：[api/app.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/api/app.py) + [api/routes/](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/api/routes/)，交互文档 `/docs`。

---

## 5 天计划

| 天 | 读 | 跑 | 产出 |
|---|---|---|---|
| 1 | README 快速上手 + CONCEPTS §1–§2 | `-p` 打 vuln/safe 靶场 | 能解释 CONFIRMED/SAFE/UNKNOWN 的差别 |
| 2 | §3–§5 + 一个插件 + engine._exec | `--debug` 看请求与判定 | 画出一条插件的完整调用链 |
| 3 | plugin_dev.md + plugin_sdk | `--plugin-init` 写一个最小插件 | 插件通过 `--plugin-check` 与靶场 |
| 4 | matcher/reachability/soft404 | 用 C3 蜜罐靶场验证不误报 | 修一个判据 + 回归测试 |
| 5 | report + api + 验收脚本 | `--serve` 看 `/docs`，生成 7 种报告 | 提交第一个 PR |

---

## 第一批安全 PR（不碰判定逻辑）

1. 给一个模块补文件头（职责/层/上下游/先读链接）。
2. 把一条长注释压缩成"规则 + 链接"，历史细节移到 `docs/design/`。
3. 给新判据补一个靶场负样本。
4. 补一条 `CONCEPTS.md` 里缺失的术语。

---

## 不要做的事

- 不要从 `core/orchestrator.py` 第 1 行开始顺序读：它按"流程步骤"组织，不是按概念。
- 不要把 `lib/` 当纯工具库：它包含可选功能（AI/OAST/通知/SIEM/分布式），很多只有一个调用方。
- 不要根据注释里的 `D7/E2/F1` 编号猜功能：编号是历史工单，含义见 `docs/design/` 或 CHANGELOG。
- 不要新增"没有生产调用方"的抽象：先看 `tests/test_cli_flag_consumers.py` 的门禁思路。
