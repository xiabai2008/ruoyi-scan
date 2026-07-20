# 漏洞利用链编排器（D6 阶段）
#
# 功能：将独立执行的原子 POC 组合为端到端攻击链，支持 DAG 拓扑排序、
#       条件分支、失败策略（abort/continue/fallback）、上下文共享（facts/secrets）。
#
# 架构红线：
#   - 零改 core/engine.py / core/router.py / core/models.py / plugins/base.py 主逻辑
#   - 链引擎独立模块，通过 PluginBase.verify(target, session) 接口调用现有插件
#   - UNKNOWN 绝不升级为 CONFIRMED（三态判定兼容）
#
# 核心数据结构：
#   - ChainStep:  链节点（plugin_cls + condition + on_fail + depends_on + inputs/outputs）
#   - ChainEdge:  依赖边（from → to，显式声明）
#   - ChainDef:   链定义（steps + edges + meta）
#   - ChainContext: 执行上下文（results/facts/secrets，线程安全）
#   - ChainEngine:  执行引擎（拓扑排序 + 节点执行 + 状态聚合）
#   - ChainResult:  链执行结果（状态 + 节点结果 + 证据）
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from common.models import (
    SEVERITY_HIGH,
    STATUS_CONFIRMED,
    STATUS_SAFE,
    STATUS_UNKNOWN,
    FingerprintResult,
    ScanResult,
)

# === 失败策略常量 ===
ON_FAIL_ABORT = "abort"  # 关键节点失败则整链中断，下游全 skipped
ON_FAIL_CONTINUE = "continue"  # 忽略失败，继续执行下游
ON_FAIL_FALLBACK = "fallback"  # 失败时执行 fallback_steps

# === 节点执行状态 ===
NODE_SUCCESS = "success"  # CONFIRMED
NODE_FAILED = "failed"  # SAFE 或异常
NODE_AMBIGUOUS = "ambiguous"  # UNKNOWN
NODE_SKIPPED = "skipped"  # condition 不满足或上游失败被跳过
NODE_ERROR = "error"  # 执行异常

# === 链整体状态（四级，部分成功不升级为 CONFIRMED）===
CHAIN_CONFIRMED = "CONFIRMED"  # 所有关键节点 success
CHAIN_PARTIAL = "PARTIAL"  # 部分关键节点 success，部分 failed/skipped
CHAIN_BLOCKED = "BLOCKED"  # 关键节点 abort 导致链中断
CHAIN_UNKNOWN = "UNKNOWN"  # 存在 UNKNOWN 且无 failed（无法判定）

# === 敏感字段脱敏 ===
_SECRET_MASK = "******"


@dataclass
class ChainStep:
    """链节点定义

    Attributes:
        id: 节点唯一标识
        plugin_cls: PluginBase 子类（需实现 verify(target, session)）
        condition: 执行前置条件函数，返回 False 则跳过本节点（不计失败）
        on_fail: 失败策略（abort/continue/fallback）
        depends_on: 依赖节点 id 列表（显式声明依赖，用于拓扑排序）
        inputs: 输入映射 {本节点参数名: ctx.facts 中的键名}
        outputs: 输出映射 {ctx.facts 键名: ScanResult 字段名或 extra 键名}
        fallback_steps: on_fail=fallback 时执行的备用节点 id 列表
        severity_override: 覆盖插件默认严重度
        description: 节点描述
    """

    id: str
    plugin_cls: type
    condition: Optional[Callable[["ChainContext"], bool]] = None
    on_fail: str = ON_FAIL_ABORT
    depends_on: List[str] = field(default_factory=list)
    inputs: Dict[str, str] = field(default_factory=dict)
    outputs: Dict[str, str] = field(default_factory=dict)
    fallback_steps: List[str] = field(default_factory=list)
    severity_override: Optional[str] = None
    description: str = ""


@dataclass
class ChainEdge:
    """依赖边（显式声明，用于 DAG 拓扑排序）"""

    from_id: str
    to_id: str


@dataclass
class ChainDef:
    """链定义

    Attributes:
        name: 链标识（CLI --chain <name>）
        display_name: 中文显示名
        description: 链描述
        severity: 链整体严重度
        affected_versions: 影响版本范围
        steps: 节点列表
        edges: 依赖边列表（可选，也可从 steps[].depends_on 推导）
        meta: 元信息（如 {'chain_type': 'sql_to_rce'}）
    """

    name: str
    display_name: str
    description: str
    severity: str = SEVERITY_HIGH
    affected_versions: str = ""
    steps: List[ChainStep] = field(default_factory=list)
    edges: List[ChainEdge] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)

    def step_by_id(self, step_id: str) -> Optional[ChainStep]:
        """按 id 查找节点"""
        for s in self.steps:
            if s.id == step_id:
                return s
        return None

    def validate(self) -> List[str]:
        """校验链定义合法性，返回错误列表（空列表表示合法）

        校验项：
        - 节点 id 唯一
        - depends_on 引用的 id 存在
        - 无循环依赖（DFS 检测环）
        """
        errors = []
        # id 唯一性
        ids = [s.id for s in self.steps]
        seen = set()
        for sid in ids:
            if sid in seen:
                errors.append(f"节点 id 重复: {sid}")
            seen.add(sid)
        # depends_on 引用存在性
        for s in self.steps:
            for dep in s.depends_on:
                if dep not in ids:
                    errors.append(f"节点 {s.id} 依赖不存在的节点: {dep}")
        # 循环依赖检测（DFS）
        if not errors:  # 只有在 id 都合法时才检测环
            cycle = self._detect_cycle()
            if cycle:
                errors.append(f"检测到循环依赖: {' → '.join(cycle)}")
        return errors

    def _detect_cycle(self) -> Optional[List[str]]:
        """DFS 检测循环依赖，返回环路径（无环返回 None）"""
        # 构建邻接表
        adj: Dict[str, List[str]] = {s.id: list(s.depends_on) for s in self.steps}
        WHITE, GRAY, BLACK = 0, 1, 2
        color = dict.fromkeys(adj, WHITE)
        path: List[str] = []

        def dfs(node: str) -> Optional[List[str]]:
            color[node] = GRAY
            path.append(node)
            for neighbor in adj.get(node, []):
                if color.get(neighbor, WHITE) == GRAY:
                    # 找到环
                    idx = path.index(neighbor)
                    return path[idx:] + [neighbor]
                if color.get(neighbor, WHITE) == WHITE:
                    result = dfs(neighbor)
                    if result:
                        return result
            path.pop()
            color[node] = BLACK
            return None

        for sid in adj:
            if color[sid] == WHITE:
                result = dfs(sid)
                if result:
                    return result
        return None


class ChainContext:
    """链执行上下文（线程安全的共享状态）

    Attributes:
        target: 扫描目标 URL
        session: SessionManager 实例（已带凭证）
        fp_result: 指纹识别结果
        results: 各节点执行结果 {step_id: ScanResult}
        node_status: 各节点执行状态 {step_id: NODE_*}
        facts: 共享事实（非敏感，如 db_name、uploaded_url）
        secrets: 敏感数据（如 db_password、token），snapshot() 自动脱敏
    """

    def __init__(self, target: str, session: Any, fp_result: FingerprintResult):
        self.target = target
        self.session = session
        self.fp_result = fp_result
        self.results: Dict[str, ScanResult] = {}
        self.node_status: Dict[str, str] = {}
        self.facts: Dict[str, Any] = {}
        self.secrets: Dict[str, str] = {}

    def set_result(self, step_id: str, result: ScanResult, status: str):
        """记录节点执行结果"""
        self.results[step_id] = result
        self.node_status[step_id] = status

    def extract_outputs(self, step_id: str, step: ChainStep, result: ScanResult):
        """根据 step.outputs 映射，从 ScanResult 提取值到 facts/secrets

        outputs 格式: {ctx_key: 'field:url' 或 'extra:vuln_type' 或 'evidence'}
        - 'field:url'   → ctx.facts[ctx_key] = result.url
        - 'extra:xxx'   → ctx.facts[ctx_key] = result.extra.get('xxx', '')
        - 'evidence'    → ctx.facts[ctx_key] = result.evidence
        - 'secret:xxx'  → ctx.secrets[ctx_key] = result.extra.get('xxx', '')（脱敏存储）
        """
        for ctx_key, source in step.outputs.items():
            try:
                if source.startswith("field:"):
                    field_name = source[6:]
                    value = getattr(result, field_name, "")
                elif source.startswith("extra:"):
                    extra_key = source[6:]
                    value = result.extra.get(extra_key, "")
                elif source.startswith("secret:"):
                    extra_key = source[7:]
                    value = result.extra.get(extra_key, "")
                    self.secrets[ctx_key] = str(value)
                    continue
                else:
                    # 直接取属性名（如 'evidence'）
                    value = getattr(result, source, "")
                self.facts[ctx_key] = value
            except Exception:
                # 提取失败不影响链执行
                pass

    def snapshot(self) -> Dict[str, Any]:
        """返回上下文快照（secrets 脱敏）"""
        return {
            "target": self.target,
            "facts": dict(self.facts),
            "secrets": dict.fromkeys(self.secrets, _SECRET_MASK),
            "node_status": dict(self.node_status),
        }


@dataclass
class ChainResult:
    """链执行结果"""

    chain_name: str
    status: str = CHAIN_UNKNOWN  # CONFIRMED/PARTIAL/BLOCKED/UNKNOWN
    node_results: Dict[str, ScanResult] = field(default_factory=dict)
    node_status: Dict[str, str] = field(default_factory=dict)
    facts: Dict[str, Any] = field(default_factory=dict)
    secrets_masked: Dict[str, str] = field(default_factory=dict)
    duration: float = 0.0
    error: str = ""

    def to_scan_result(self, chain_def: ChainDef) -> ScanResult:
        """转换为 ScanResult（kind='chain'），复用现有报告渲染

        链状态 → ScanResult.status 映射：
        - CONFIRMED → CONFIRMED（链路打通，端到端可利用）
        - PARTIAL   → CONFIRMED（部分节点成功，仍视为存在风险）
        - BLOCKED   → SAFE（关键节点失败，链路未打通）
        - UNKNOWN   → UNKNOWN（存在无法判定的节点）
        """
        if self.status in (CHAIN_CONFIRMED, CHAIN_PARTIAL):
            status = STATUS_CONFIRMED
        elif self.status == CHAIN_BLOCKED:
            status = STATUS_SAFE
        else:
            status = STATUS_UNKNOWN

        # 证据：汇总各成功节点的关键信息
        success_nodes = [sid for sid, st in self.node_status.items() if st == NODE_SUCCESS]
        evidence_parts = []
        for sid in success_nodes:
            r = self.node_results.get(sid)
            if r and r.evidence:
                evidence_parts.append(f"[{sid}] {r.evidence}")
        evidence = " | ".join(evidence_parts) if evidence_parts else "链路未完成"

        # facts 非敏感信息附带到 extra
        extra = {
            "chain_type": "chain",
            "chain_name": chain_def.name,
            "node_count": len(self.node_status),
            "success_count": len(success_nodes),
            "facts": dict(self.facts),
        }

        return ScanResult(
            kind="chain",
            name=chain_def.display_name,
            severity=chain_def.severity,
            status=status,
            url="",
            evidence=evidence,
            extra=extra,
            fix=chain_def.description,
        )


class ChainEngine:
    """链执行引擎（DAG 拓扑排序 + 节点执行 + 状态聚合）

    用法：
        engine = ChainEngine()
        result = engine.run(chain_def, target, session, fp_result)
    """

    def __init__(self, on_unknown: str = "fail"):
        """初始化链引擎

        Args:
            on_unknown: UNKNOWN 节点的处理策略
                - 'fail': 按失败处理（默认，保守）
                - 'continue': 按 success 处理（激进，不推荐）
        """
        self.on_unknown = on_unknown

    def _topological_sort(self, chain_def: ChainDef) -> List[str]:
        """拓扑排序（Kahn 算法），返回节点 id 的执行顺序

        依赖来源：
        1. step.depends_on（主要来源）
        2. chain_def.edges（显式声明，补充）

        同层无依赖关系的节点按定义顺序执行（稳定排序）。
        """
        # 构建邻接表与入度表
        adj: Dict[str, List[str]] = {s.id: [] for s in chain_def.steps}
        in_degree: Dict[str, int] = {s.id: 0 for s in chain_def.steps}

        # 从 depends_on 构建边
        for s in chain_def.steps:
            for dep in s.depends_on:
                if dep in adj:
                    adj[dep].append(s.id)
                    in_degree[s.id] += 1

        # 从显式 edges 补充（去重）
        for edge in chain_def.edges:
            if edge.from_id in adj and edge.to_id in adj and edge.to_id not in adj[edge.from_id]:
                adj[edge.from_id].append(edge.to_id)
                in_degree[edge.to_id] += 1

        # Kahn 算法（按定义顺序处理同层节点，保证稳定）
        result = []
        # 用列表模拟队列，按节点在 steps 中的定义顺序入队
        remaining = {s.id for s in chain_def.steps}
        while remaining:
            # 找出当前入度为 0 的节点（按定义顺序）
            ready = [s.id for s in chain_def.steps if s.id in remaining and in_degree[s.id] == 0]
            if not ready:
                # 不应发生（validate 已检测环），防御性处理
                break
            for sid in ready:
                result.append(sid)
                remaining.discard(sid)
                for neighbor in adj[sid]:
                    if neighbor in remaining:
                        in_degree[neighbor] -= 1
        return result

    def _evaluate_condition(self, condition: Optional[Callable], ctx: ChainContext) -> bool:
        """评估条件函数，异常默认返回 False（不执行）"""
        if condition is None:
            return True
        try:
            return bool(condition(ctx))
        except Exception:
            return False

    def _execute_step(self, step: ChainStep, ctx: ChainContext) -> Tuple[ScanResult, str]:
        """执行单个节点，返回 (ScanResult, node_status)

        节点状态映射：
        - CONFIRMED → success
        - SAFE      → failed
        - UNKNOWN   → ambiguous
        - 异常      → error
        """
        try:
            plugin = step.plugin_cls()
            result = plugin.verify(ctx.target, ctx.session)
            # severity 覆盖
            if step.severity_override:
                result.severity = step.severity_override
            # 状态映射
            if result.status == STATUS_CONFIRMED:
                node_status = NODE_SUCCESS
            elif result.status == STATUS_SAFE:
                node_status = NODE_FAILED
            elif result.status == STATUS_UNKNOWN:
                node_status = NODE_AMBIGUOUS
            else:
                node_status = NODE_FAILED
            return result, node_status
        except Exception as e:
            # 异常等同 failed，记录错误信息
            error_result = ScanResult(
                kind="chain",
                name=step.id,
                status=STATUS_UNKNOWN,
                evidence=f"节点执行异常: {e}",
            )
            return error_result, NODE_ERROR

    def _is_critical_failed(self, step: ChainStep, node_status: str) -> bool:
        """判断节点是否为关键失败（影响链整体状态）"""
        if node_status in (NODE_SUCCESS, NODE_SKIPPED):
            return False
        # UNKNOWN 策略
        if node_status == NODE_AMBIGUOUS:
            return self.on_unknown == "fail"
        # FAILED / ERROR
        return True

    def run(
        self,
        chain_def: ChainDef,
        target: str,
        session: Any,
        fp_result: FingerprintResult = None,
        on_result: Optional[Callable[[ScanResult], None]] = None,
    ) -> ChainResult:
        """执行链定义

        Args:
            chain_def: 链定义
            target: 扫描目标 URL
            session: SessionManager 实例
            fp_result: 指纹识别结果（可选）
            on_result: 节点结果回调（实时输出）

        Returns:
            ChainResult
        """
        result = ChainResult(chain_name=chain_def.name)
        t0 = time.time()

        # 校验链定义
        errors = chain_def.validate()
        if errors:
            result.status = CHAIN_BLOCKED
            result.error = "链定义校验失败: " + "; ".join(errors)
            result.duration = time.time() - t0
            return result

        # 构建上下文
        if fp_result is None:
            fp_result = FingerprintResult()
        ctx = ChainContext(target, session, fp_result)

        # 拓扑排序
        order = self._topological_sort(chain_def)

        # 记录被跳过的节点（上游 abort 传播）
        aborted = set()

        for step_id in order:
            step = chain_def.step_by_id(step_id)
            if step is None:
                continue

            # 检查上游是否已 abort
            if step_id in aborted:
                ctx.set_result(
                    step_id,
                    ScanResult(
                        kind="chain",
                        name=step_id,
                        status=STATUS_SAFE,
                        evidence="上游节点失败，本节点被跳过",
                    ),
                    NODE_SKIPPED,
                )
                result.node_results[step_id] = ctx.results[step_id]
                result.node_status[step_id] = NODE_SKIPPED
                continue

            # 评估 condition
            if not self._evaluate_condition(step.condition, ctx):
                ctx.set_result(
                    step_id,
                    ScanResult(
                        kind="chain",
                        name=step_id,
                        status=STATUS_SAFE,
                        evidence="条件不满足，跳过执行",
                    ),
                    NODE_SKIPPED,
                )
                result.node_results[step_id] = ctx.results[step_id]
                result.node_status[step_id] = NODE_SKIPPED
                continue

            # 执行节点
            scan_result, node_status = self._execute_step(step, ctx)
            ctx.set_result(step_id, scan_result, node_status)
            ctx.extract_outputs(step_id, step, scan_result)
            result.node_results[step_id] = scan_result
            result.node_status[step_id] = node_status

            # 回调
            if on_result and scan_result:
                on_result(scan_result)

            # 失败策略处理
            if self._is_critical_failed(step, node_status):
                if step.on_fail == ON_FAIL_ABORT:
                    # 传播 abort 到所有下游节点
                    self._propagate_abort(chain_def, step_id, aborted)
                elif step.on_fail == ON_FAIL_FALLBACK:
                    # 执行 fallback 节点（标记为待执行）
                    for fb_id in step.fallback_steps:
                        aborted.discard(fb_id)  # 确保 fallback 不被跳过
                # ON_FAIL_CONTINUE: 不传播，继续执行

        # 聚合链整体状态
        result.status = self._aggregate_status(chain_def, result.node_status)
        result.facts = dict(ctx.facts)
        result.secrets_masked = dict.fromkeys(ctx.secrets, _SECRET_MASK)
        result.duration = time.time() - t0
        return result

    def _propagate_abort(self, chain_def: ChainDef, failed_id: str, aborted: set):
        """将 abort 传播到失败节点的所有下游节点（递归）"""
        for s in chain_def.steps:
            if failed_id in s.depends_on and s.id not in aborted:
                aborted.add(s.id)
                self._propagate_abort(chain_def, s.id, aborted)

    def _aggregate_status(self, chain_def: ChainDef, node_status: Dict[str, str]) -> str:
        """聚合链整体状态

        判定规则（考虑 on_unknown 策略）：
        - on_unknown='fail' 时，ambiguous 视为 failed
        - on_unknown='continue' 时，ambiguous 视为 success
        - 存在 ambiguous 且无 failed（on_unknown='fail' 时无效果）→ UNKNOWN
        - 所有关键节点 success → CONFIRMED
        - 部分关键节点 success，部分 failed/skipped → PARTIAL
        - 关键节点 abort 导致大量 skipped → BLOCKED
        """
        if not node_status:
            return CHAIN_UNKNOWN

        has_ambiguous = False
        has_failed = False
        has_success = False
        has_skipped = False

        for status in node_status.values():
            if status == NODE_SUCCESS:
                has_success = True
            elif status == NODE_FAILED or status == NODE_ERROR:
                has_failed = True
            elif status == NODE_AMBIGUOUS:
                has_ambiguous = True
                # 根据 on_unknown 策略将 ambiguous 视为 failed 或 success
                if self.on_unknown == "fail":
                    has_failed = True
                else:
                    has_success = True
            elif status == NODE_SKIPPED:
                has_skipped = True

        # 存在 UNKNOWN 且无 failed（仅在 on_unknown != 'fail' 时可能）
        if has_ambiguous and not has_failed:
            return CHAIN_UNKNOWN

        # 关键节点失败 → BLOCKED
        if has_failed:
            # 如果同时有 success，则 PARTIAL
            if has_success:
                return CHAIN_PARTIAL
            return CHAIN_BLOCKED

        # 无 failed，全部 success 或 skipped
        if has_success:
            # 如果有 skipped 但无 failed，仍视为 CONFIRMED（可选分支跳过不影响主线）
            return CHAIN_CONFIRMED

        # 全部 skipped
        if has_skipped:
            return CHAIN_BLOCKED

        # 只有 ambiguous（on_unknown != 'fail' 且无 failed/success）
        return CHAIN_UNKNOWN
