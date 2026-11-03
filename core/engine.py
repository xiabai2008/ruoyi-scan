# 扫描引擎：并发编排 + 令牌桶限速
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import TYPE_CHECKING, Any, Callable, List, Optional, cast

from common.logger import get_logger
from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from lib.attribution import ATTR_KEY, classify

if TYPE_CHECKING:
    from core.session import SessionManager

logger = get_logger(__name__)

# 结果严重度排序（path_scope="both" 双探时取更严重者）
_STATUS_RANK = {STATUS_SAFE: 0, STATUS_UNKNOWN: 1, STATUS_CONFIRMED: 2}


class ScanEngine:
    """插件执行引擎：同步或并发运行插件，可选限速"""

    def __init__(self, threads: int = 1, rate: int = 0, deadline: Optional[float] = None) -> None:
        """初始化扫描引擎

        Args:
            threads: 并发执行插件的线程数（<=1 退化为串行）
            rate: 每秒插件启动数上限（0=不限速，令牌桶实现见 _rate_limit）。
                注意：这是插件级限速，不是逐 HTTP 请求限速——单个插件内部发出
                的多个请求不受此约束
            deadline: time.monotonic() 口径的截止时间；超过后不再启动新插件，
                直接给 UNKNOWN。用于慢站/被限速目标（chaos slow 实测：2–5s/请求的
                站点会让一次 -p 跑过 5 分钟，操作者以为卡死）。None = 不限制
        """
        self.threads = max(1, threads)
        self.rate = rate  # 每秒插件启动数上限，0 表示不限速
        self.deadline = deadline  # 单目标时间预算截止点（monotonic）
        self._timestamps: List[float] = []  # 令牌桶：最近 1 秒内的插件启动时间戳
        self._rate_lock = threading.Lock()  # 保护 _rate_limit 的互斥锁（多线程安全）

    def run(
        self,
        plugin_classes: List[type],
        target: str,
        session: SessionManager,
        on_result: Optional[Callable[[ScanResult], None]] = None,
        waf_bypass_coordinator: Optional[Any] = None,
        should_stop: Optional[Callable[[], bool]] = None,
        root_target: str = "",
    ) -> List[ScanResult]:
        """运行插件集合

        Args:
            plugin_classes: 插件类列表
            target: 目标 URL（已归一化）。若探到 API 前缀，这里已是带前缀的基准
            session: SessionManager 实例
            on_result: 每个结果回调 on_result(ScanResult)
            waf_bypass_coordinator: WAF 绕过协调器（D7，None 则不绕过）
            should_stop: 协作式取消检查（每插件入口调用；True 则不再启动新插件）
            root_target: **不带 API 前缀的站点根 URL**（F9）。为空时等价于 target。
                用于 path_scope="root"/"both" 的插件——它们探的是部署在 web 根的
                静态资源（.git/.env/备份/IDE 残留），加了前缀反而探不到。
        Returns:
            结果列表
        """
        results = []
        _root = root_target or target

        def _target_for(cls: type) -> str:
            """按插件的 path_scope 选择探测基准（F9 单一入口）。

            v1.5.6 WP1 补充：插件路径自带前缀（`self_prefixes`）且与站点
            context-path 相同时，基准必须退回站点根——否则拼成双前缀，
            请求落到登录墙，本该 CONFIRMED 的项会判 SAFE（D1 实测）。
            """
            scope = getattr(cls, "path_scope", "api")
            if scope == "root":
                return _root
            # "both" 的完整双探由插件内部处理（它需要比较两个响应），
            # 这里给它根路径作为基准，插件自己拼前缀版本。
            if scope == "both" and _root != target:
                return _root
            # 插件自带的前缀与探测到的 context-path 重合 → 它自己会拼这一段
            self_prefixes = getattr(cls, "self_prefixes", ()) or ()
            if self_prefixes and _root != target:
                base = target[len(_root) :].strip("/")
                if base and ("/" + base) in self_prefixes:
                    return _root
            return target

        def _exec(cls: type) -> Optional[ScanResult]:
            # 协作式取消：立即停止启动新插件。已启动的插件无法强杀（requests
            # 不支持中断），但会在自身 HTTP 超时内结束，不会无限占住线程。
            if should_stop is not None and should_stop():
                return None
            # 时间预算：慢站/被限速时宁可留 UNKNOWN，也不要让整次扫描无限拖长
            if self.deadline is not None and time.monotonic() > self.deadline:
                return ScanResult(
                    kind="info",
                    name=getattr(cls, "name", cls.__name__),
                    status=STATUS_UNKNOWN,
                    evidence="超出扫描时间预算（--time-budget），本项未执行",
                )
            # 执行前限速（单线程和多线程统一走此路径，线程安全）
            self._rate_limit()
            try:
                inst = cls()
                # ⚠ 共享会话存在「认证状态泄漏」风险：各插件复用同一个 SessionManager，
                # 而 job_invoke_target、cve_2025_46174_resetpwd_scope 等插件会在其上**登录**。
                # 登录状态会一直保留给后续插件，而其余插件普遍以「未认证基线」为前提判定，
                # 于是把「已认证下返回的 200」误读为「文件/接口存在」。
                # 注意：**不能用 cookie 快照/还原来做隔离**——已实测无效：
                # Shiro 把认证状态存在服务端 session（按 JSESSIONID 索引），
                # 把 cookie 还原成同一个 JSESSIONID，服务端仍视其为已认证。
                # 需鉴权的插件必须自建独立会话（见 plugins/ruoyi/job_invoke_target.py 的写法）。
                #
                # F9：按插件声明的 path_scope 选探测基准。分离版站点探到 /prod-api 后，
                # API 类插件要跟着前缀走，而根静态资源插件（.git/.env/备份）必须留在根路径。
                exec_target = _target_for(cls)
                # v1.6：path_scope="both" 表示「端点既可能在 API 前缀下，也可能在站点根」，
                # 引擎对两个基准各跑一次，取更严重的结果。
                #
                # 为什么需要（Y1 芋道实测 2026-11-03）：网关架构下 API 前缀归业务接口
                # （/admin-api/system/**），而 Swagger 文档归应用根
                # （/v3/api-docs 根路径 200+373KB，/admin-api/v3/api-docs 只有 48 字节错误页）。
                # 引擎探到前缀后把基准推过去，文档插件就整类漏报。
                #
                # 放在引擎而不是让每个插件自己拼：插件只需声明 both，不必各自实现双探
                # （file_read/file_read_path 各自维护 passwd 判定最后必须抽到 lib/matcher，
                #  就是「各写一遍然后漂移」的前车之鉴）。
                if getattr(cls, "path_scope", "api") == "both" and _root.rstrip("/") != exec_target.rstrip("/"):
                    _pair = [
                        cast(ScanResult, inst.verify(exec_target, session)),
                        cast(ScanResult, inst.verify(_root, session)),
                    ]
                    original = max(_pair, key=lambda r: _STATUS_RANK.get(r.status, 0))
                else:
                    original = cast(ScanResult, inst.verify(exec_target, session))
                # D7: WAF 绕过（仅当协调器存在且插件支持绕过且原结果非 CONFIRMED）
                if (
                    waf_bypass_coordinator is not None
                    and getattr(inst, "supports_waf_bypass", False)
                    and original.status != STATUS_CONFIRMED
                ):
                    try:
                        original = cast(
                            ScanResult, waf_bypass_coordinator.maybe_bypass(inst, exec_target, session, original)
                        )
                    except Exception as e:
                        # 绕过异常不降级为 SAFE，保持原状态；同时记录日志：
                        # 否则绕过失败（及其部分执行的副作用）只留在 extra 里，对操作者不可见
                        logger.exception("WAF 绕过执行失败，保持原判定: %s", e)
                        if not original.extra:
                            original.extra = {}
                        original.extra["waf_bypass_error"] = str(e)
                # 元信息回填：统一在此补齐 cve/cvss_vector/compliance/fix_detail/reproduce，
                # 只填空值不覆盖插件已写入的值。放在 WAF 绕过之后，保证绕过路径同样生效。
                enrich = getattr(inst, "enrich", None)
                if callable(enrich):
                    original = cast(ScanResult, enrich(original))
                # F13：需会话插件必须在结果回调（CLI 逐条打印）之前按认证纪律降级。
                # 旧行为：orchestrator 在 engine 返回后才统一降级，CLI 已按原状态打印
                # 「存在 XXX」，与 report.json 的 UNKNOWN 自相矛盾（2026-11-02 D1 实测）。
                # session.authenticated 由 orchestrator 调用本引擎前显式设置；未设置的
                # 调用方（单测/嵌入式 API）保持旧行为，不做提前降级。
                if getattr(cls, "requires_auth", False) and getattr(session, "authenticated", None) is False:
                    if original.status in (STATUS_CONFIRMED, STATUS_SAFE):
                        original.status = STATUS_UNKNOWN
                        original.evidence = (
                            "未取得高权会话（主扫描未认证），需登录的结论已在打印前降级为 UNKNOWN。"
                            f"原证据：{original.evidence}"
                        )
                # 归属标注同样必须在回调（CLI 逐条打印）之前完成——与 F13 同一条纪律：
                # 终端与报告口径必须一致。放在 orchestrator 末尾时，终端打出
                # 「存在 Redis 未授权访问」而报告里标着「宿主级」，读者无从分辨
                # 这是本站点的漏洞还是这台机器上别的服务（2026-11-02 实测）。
                original.extra = dict(original.extra or {})
                original.extra[ATTR_KEY] = classify(_root, getattr(original, "url", "") or "")
                return original
            except Exception as e:
                # 网络异常等不阻断整体流程，判为 UNKNOWN（绝不判 SAFE）
                return ScanResult(
                    kind="error",
                    name=getattr(cls, "name", cls.__name__),
                    status=STATUS_UNKNOWN,
                    evidence=f"执行异常: {e}",
                )

        # 单线程模式：按插件定义顺序串行执行，结果顺序稳定（多线程用 as_completed 无序）
        if self.threads <= 1:
            for cls in plugin_classes:
                res = _exec(cls)
                if res is None:  # 已取消：停止启动后续插件
                    break
                results.append(res)
                if on_result:
                    on_result(res)
        else:
            with ThreadPoolExecutor(max_workers=self.threads) as ex:
                futures = {ex.submit(_exec, cls): cls for cls in plugin_classes}
                for fut in as_completed(futures):
                    res = fut.result()
                    if res is None:  # 已取消：跳过未执行项
                        continue
                    results.append(res)
                    if on_result:
                        on_result(res)
        return results

    def _rate_limit(self) -> None:
        """令牌桶限速：保证每秒启动的插件数不超过 self.rate（线程安全）

        注意：限的是一个插件「开始执行」的速率（_exec 入口调用），不是插件内部
        逐 HTTP 请求的 QPS；单插件多请求的场景不受此约束。CLI --rate 的宣传语
        「每秒请求数」在语义上以此为实际行为。

        多线程环境下通过 _rate_lock 保护竞态条件。令牌桶算法：
        维护最近 1 秒内的插件启动时间戳列表，若已达上限则等待令牌释放后重新竞争。

        修复（2026 评审）：原实现「先在锁内预约时间戳、再到锁外睡眠」，多个线程
        会同时预约（列表被撑过 rate）并算出几乎相同的睡眠时间，醒来后一起发起
        请求，形成超过配置速率的突发。现改为：锁内判定无令牌则释放锁睡眠，
        醒来后回到锁内重新竞争，只有真正拿到令牌（写入时间戳）的线程才继续请求。
        """
        if self.rate <= 0:
            return
        while True:
            with self._rate_lock:
                now = time.time()
                self._timestamps = [t for t in self._timestamps if now - t < 1.0]
                if len(self._timestamps) < self.rate:
                    # 拿到令牌：此刻才记录时间戳（即请求即将发出的时刻）
                    self._timestamps.append(now)
                    return
                sleep = 1.0 - (now - self._timestamps[0])
            # 锁外睡眠：不阻塞其他线程；醒来后重新竞争令牌，避免同时醒来的突发
            if sleep > 0:
                time.sleep(sleep)
