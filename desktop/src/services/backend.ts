/**
 * Ruoyi-Scan 本地 FastAPI sidecar 客户端（REST + WebSocket）。
 * 与 api/routes、api/ws、api/models/schemas.py 的数据契约一一对应。
 * API Base 可通过 localStorage["ruoyi-scan.apiBase"] 覆盖，默认 http://127.0.0.1:8123。
 */

export const DEFAULT_API_BASE = "http://127.0.0.1:8123";
export const WS_EVENT_TYPES = [
  "status", "complete", "fingerprint", "waf", "waf_bypass", "portscan",
  "category_start", "result", "progress", "report", "plugins_loaded",
  "recon", "recon_start", "recon_error", "component", "template", "auth",
  "plugin_fallback", "nuclei_error", "error", "ping", "connection_closed",
  "preflight", "blocked", "auth_wall", "basepath", "denied_downgrade",
  "evidence_downgrade", "auth_wall_downgrade", "blocked_downgrade",
] as const;

/* ---------- 类型（与后端 DTO 对齐） ---------- */

export type Verdict = "CONFIRMED" | "SAFE" | "UNKNOWN";
export type TaskStatus = "pending" | "running" | "done" | "failed" | "cancelled" | "interrupted";
/** 后端只有 high/medium/low，无 critical；UI 展示映射见 helpers */
export type BackendSev = "high" | "medium" | "low";
export type ScanMode = "u" | "m" | "p" | "l";

export interface FingerprintInfo {
  cms: string;
  variant?: string;
  version?: string;
  confidence: number;
  matched: string[];
}

export interface ScanTask {
  task_id: string;
  status: TaskStatus;
  target: string;
  mode: ScanMode;
  started_at: number;
  finished_at: number;
  duration: number;
  request_count: number;
  result_count: number;
  confirmed_count: number;
  safe_count: number;
  unknown_count: number;
  error: string;
  fingerprint: FingerprintInfo | null;
  waf: Record<string, unknown> | null;
  report_paths: string[];
}

export interface ScanResultItem {
  kind?: string;
  name: string;
  status: Verdict;
  severity: BackendSev;
  severity_cn?: string;
  url: string;
  evidence: string;
  extra: Record<string, unknown>;
  fix?: string;
  fix_detail?: string;
  reproduce?: string;
  cve?: string;
  cvss_score?: number;
  cvss_vector?: string;
  compliance?: Record<string, string>;
}

export interface PluginMeta {
  name: string;
  category: string;
  severity: BackendSev;
  description: string;
  cve: string;
  affected_versions: string;
  vuln_type: string;
  supports_waf_bypass: boolean;
}

export interface ScanSubmitPayload {
  target: string;
  mode: ScanMode;
  cms?: string;
  threads?: number;
  rate?: number;
  proxy?: string;
  timeout?: number;
  report_format?: string;
  no_dedup?: boolean;
  pass_level?: "top100" | "top1000" | "full";
  portscan?: boolean;
  ports?: string;
  bypass_waf?: "auto" | "on" | "off";
  plugins?: string[] | null;
}

export interface WsEvent {
  type: string;
  data: Record<string, unknown> & { [k: string]: unknown };
  task_id: string;
  timestamp: number;
}

export interface EngineInfo {
  version: string;
  author: string;
  github: string;
  python_version: string;
}

export interface ScheduleJob {
  job_id: string;
  cron: string;
  target: string;
  mode: string;
  payload: Record<string, unknown>;
  degraded?: boolean;
  effective_cron?: string;
  warning?: string;
  paused?: boolean;
  paused_reason?: string;
  last_task_id?: string;
  last_run_at?: number;
  last_status?: string;
  consecutive_failures?: number;
}

export interface MetricsSnapshot {
  uptime: number;
  tasks: Record<string, number>;
  active: number;
  results: Record<string, number>;
  storageTasks: number | null;
}

/* ---------- API 客户端 ---------- */

/** localStorage 不可用（SSR / 沙箱 webview）时的会话内兜底，避免所有 API 调用在读取配置时直接抛错 */
let memApiBase: string | null = null;

export function getApiBase(): string {
  if (memApiBase) return memApiBase;
  try {
    return localStorage.getItem("ruoyi-scan.apiBase") || DEFAULT_API_BASE;
  } catch {
    return DEFAULT_API_BASE;
  }
}

export function setApiBase(base: string) {
  const normalized = base.replace(/\/+$/, "");
  memApiBase = normalized;
  try {
    localStorage.setItem("ruoyi-scan.apiBase", normalized);
  } catch {
    /* 存储不可用：地址仅在本会话生效，不向调用方抛错 */
  }
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

/** 默认请求超时：引擎离线时 fetch 会一直挂着，UI 永久“提交中…”（测评 P1-7） */
const DEFAULT_TIMEOUT_MS = 12_000;

function isAbortError(e: unknown): boolean {
  return e instanceof DOMException && e.name === "AbortError";
}

async function http<T>(path: string, init?: RequestInit, timeoutMs = DEFAULT_TIMEOUT_MS): Promise<T> {
  const url = getApiBase() + path;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  let res: Response;
  try {
    res = await fetch(url, {
      ...init,
      signal: ctrl.signal,
      // headers 必须在 init 之后合并，否则调用方传入的 headers 会整体覆盖并丢掉 Content-Type
      headers: { "Content-Type": "application/json", ...(init?.headers || {}) },
    });
  } catch (e) {
    if (isAbortError(e)) {
      throw new ApiError(0, `请求超时（${Math.round(timeoutMs / 1000)}s）—— 引擎可能未启动或目标无响应`);
    }
    if (e instanceof TypeError) {
      throw new ApiError(0, `无法连接引擎 ${getApiBase()}，请确认后端已启动`);
    }
    throw e;
  } finally {
    clearTimeout(timer);
  }
  if (!res.ok) {
    let detail = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      if (body?.detail) detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch {
      /* ignore */
    }
    throw new ApiError(res.status, detail);
  }
  return res.json() as Promise<T>;
}

export const api = {
  health: () => http<{ status: string; version: string; uptime: number }>("/api/system/health", undefined, 6_000),
  version: () => http<EngineInfo>("/api/system/version", undefined, 6_000),
  fingerprint: (target: string, timeout = 8) =>
    http<{
      target: string;
      cms: string;
      version: string;
      confidence: number;
      matched: string[];
      waf: string;
      waf_display: string;
    }>(
      `/api/system/fingerprint?target=${encodeURIComponent(target)}&timeout=${timeout}`,
      undefined,
      25_000,
    ),
  probe: (target: string) =>
    http<{ target: string; ok: boolean; stage: string; reason: string; elapsed_ms: number }>(
      `/api/system/probe?target=${encodeURIComponent(target)}&timeout=5`,
      undefined,
      20_000,
    ),

  listTasks: () => http<ScanTask[]>("/api/scan", undefined, 8_000),
  getTask: (id: string) => http<ScanTask>(`/api/scan/${encodeURIComponent(id)}`, undefined, 8_000),
  taskResults: (id: string) => http<ScanResultItem[]>(`/api/scan/${encodeURIComponent(id)}/results`, undefined, 10_000),
  submitScan: (p: ScanSubmitPayload) => http<{ task_id: string; status: string }>("/api/scan", {
    method: "POST",
    body: JSON.stringify(p),
  }, 20_000),
  cancelScan: (id: string) => http<{ task_id: string; status: string }>(`/api/scan/${encodeURIComponent(id)}`, {
    method: "DELETE",
  }, 8_000),
  listPlugins: () => http<PluginMeta[]>("/api/plugins", undefined, 20_000),
  getPlugin: (name: string) => http<PluginMeta>(`/api/plugins/${encodeURIComponent(name)}`, undefined, 10_000),
  reportMeta: (id: string) =>
    http<{ task_id: string; formats: string[]; paths: string[] }>(`/api/report/${encodeURIComponent(id)}`, undefined, 10_000),
  rebuildReport: (id: string) =>
    http<{ task_id: string; paths: string[] }>(`/api/report/${encodeURIComponent(id)}/rebuild`, { method: "POST" }, 30_000),
  /** 报告下载走 fetch/原生对话框；URL 仍由 FileResponse 提供 Content-Disposition */
  reportDownloadUrl: (id: string, fmt: string) =>
    `${getApiBase()}/api/report/${encodeURIComponent(id)}/${encodeURIComponent(fmt)}`,
  reportPreviewUrl: (id: string) =>
    `${getApiBase()}/api/report/${encodeURIComponent(id)}/html?inline=1`,

  /* E9 定时扫描 */
  listSchedules: () => http<ScheduleJob[]>("/api/schedule", undefined, 8_000),
  createSchedule: (body: { cron: string; target: string; mode?: string; payload?: Record<string, unknown> }) =>
    http<{
      job_id: string;
      cron: string;
      target: string;
      status: string;
      degraded?: boolean;
      effective_cron?: string;
      warning?: string;
    }>("/api/schedule", {
      method: "POST",
      body: JSON.stringify(body),
    }, 10_000),
  /** 查询参数删除：历史 job_id 含 `/`，路径参数在部分网关/路由实现下无法匹配 */
  deleteSchedule: (jobId: string) =>
    http<{ job_id: string; status: string }>(`/api/schedule?job_id=${encodeURIComponent(jobId)}`, { method: "DELETE" }, 8_000),
  resumeSchedule: (jobId: string) =>
    http<{ job_id: string; status: string }>("/api/schedule/resume", {
      method: "POST",
      body: JSON.stringify({ job_id: jobId }),
    }, 8_000),
};

/* ---------- Prometheus 指标解析 ---------- */

/** 拉取 /api/system/metrics 并解析为结构化快照（任务/结果统计、活跃数、uptime） */
export async function fetchMetrics(): Promise<MetricsSnapshot> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 8_000);
  let res: Response;
  try {
    res = await fetch(`${getApiBase()}/api/system/metrics`, { signal: ctrl.signal });
  } catch (e) {
    if (isAbortError(e)) throw new ApiError(0, "指标请求超时（8s）");
    if (e instanceof TypeError) throw new ApiError(0, "无法连接引擎，无法获取指标");
    throw e;
  } finally {
    clearTimeout(timer);
  }
  if (!res.ok) throw new ApiError(res.status, `HTTP ${res.status}`);
  const text = await res.text();
  const uptime = numOf(text, "ruoyi_scan_uptime_seconds");
  const active = numOf(text, "ruoyi_scan_tasks_active");
  const storageTasks = numOfOpt(text, "ruoyi_scan_storage_tasks");
  const tasks = seriesOf(text, "ruoyi_scan_tasks_total");
  const results = seriesOf(text, "ruoyi_scan_results_total");
  return { uptime, tasks, active, results, storageTasks };
}

/** 指标存在时返回值，缺失时返回 null —— 用于区分“后端未暴露该指标”与真实 0（如 storage 未启用） */
function numOfOpt(text: string, metric: string): number | null {
  const m = text.match(new RegExp(`^${metric}\\s+([0-9.]+)$`, "m"));
  return m ? Number(m[1]) : null;
}

function numOf(text: string, metric: string): number {
  return numOfOpt(text, metric) ?? 0;
}

function seriesOf(text: string, metric: string): Record<string, number> {
  const out: Record<string, number> = {};
  const re = new RegExp(`^${metric}\\{status="([^"]+)"\\}\\s+([0-9.]+)$`, "gm");
  for (const m of text.matchAll(re)) out[m[1]] = Number(m[2]);
  return out;
}

/* ---------- WebSocket 客户端 ---------- */

export type WsState = "connecting" | "open" | "closed";

const TERMINAL_STATUSES = new Set(["done", "failed", "cancelled", "interrupted"]);

/**
 * 订阅某个任务的实时事件。服务端连接后会先补播历史事件、随后推送新事件，
 * 任务到达终态（done/failed/cancelled）后由服务端主动关闭。
 * 只有任务仍在 pending/running 时才自动重连。
 */
export function openTaskSocket(
  taskId: string,
  onEvent: (e: WsEvent) => void,
  onState?: (s: WsState) => void,
  onTerminal?: () => void,
): () => void {
  let ws: WebSocket | null = null;
  let closedByUser = false;
  let terminalSeen = false;
  let retry = 0;
  let timer: ReturnType<typeof setTimeout> | null = null;

  const apiBase = getApiBase();
  const wsBase = apiBase.replace(/^http/, "ws");

  const connect = () => {
    if (closedByUser || terminalSeen) return;
    onState?.("connecting");
    ws = new WebSocket(`${wsBase}/ws/scan/${encodeURIComponent(taskId)}`);
    ws.onopen = () => {
      retry = 0;
      onState?.("open");
    };
    ws.onmessage = (msg) => {
      try {
        const e = JSON.parse(msg.data as string) as WsEvent;
        onEvent(e);
        const d = e.data || {};
        // 终态只通知一次：complete 之后常跟一条 status=done，重复触发会让消费方收到重复回调。
        // error 帧仍视为终态 —— 服务端发出后必然关闭连接（任务不存在 / 任务异常），继续重连没有意义。
        const terminal =
          e.type === "complete" || e.type === "error" || TERMINAL_STATUSES.has(String(d.status));
        if (terminal && !terminalSeen) {
          terminalSeen = true;
          onTerminal?.();
        }
      } catch {
        /* ignore bad frames */
      }
    };
    ws.onerror = () => {
      ws?.close();
    };
    ws.onclose = () => {
      onState?.("closed");
      if (closedByUser || terminalSeen) return;
      // 心跳/闪断重连：指数退避，最多 6 次
      if (retry < 6) {
        retry += 1;
        const delay = Math.min(500 * 2 ** retry, 8000);
        timer = setTimeout(connect, delay);
      }
    };
  };

  connect();
  return () => {
    closedByUser = true;
    if (timer) clearTimeout(timer);
    ws?.close();
  };
}

/* ---------- 展示辅助 ---------- */

const SEV_UI: Record<string, "CRITICAL" | "HIGH" | "MED" | "LOW"> = {
  critical: "CRITICAL",
  high: "HIGH",
  medium: "MED",
  low: "LOW",
};

const warnedSev = new Set<string>();

/**
 * 后端级别 → UI 级别。未知级别不静默降级为 LOW（会把潜在高危显示成低危）：
 * 以中性 MED 呈现并打印一次告警，暴露后端契约漂移。
 */
export const sevToUi = (s: BackendSev | string): "CRITICAL" | "HIGH" | "MED" | "LOW" => {
  const key = String(s).toLowerCase();
  const ui = SEV_UI[key];
  if (ui) return ui;
  if (!warnedSev.has(key)) {
    warnedSev.add(key);
    console.warn(`[sevToUi] 未知严重级别 "${String(s)}"，按 MED 展示`);
  }
  return "MED";
};

export const MODE_LABEL: Record<ScanMode, string> = {
  u: "综合扫描 u",
  m: "目录扫描 m",
  p: "漏洞检测 p",
  l: "登录爆破 l",
};

/** 任务状态统一文案：任务页/资产页/报告页共用，避免 CANCELLED / STOPPED 两套说法 */
export const TASK_STATUS_LABEL: Record<string, string> = {
  pending: "QUEUED",
  running: "RUNNING",
  done: "DONE",
  failed: "FAILED",
  cancelled: "CANCELLED",
  interrupted: "INTERRUPTED",
};

/** 状态色使用 CSS token（图表/表格/徽标共用） */
export const TASK_STATUS_COLOR: Record<string, string> = {
  pending: "var(--c-sem-amber)",
  running: "var(--c-accent-primary)",
  done: "var(--c-sem-green)",
  failed: "var(--c-sem-red)",
  cancelled: "var(--c-text-muted)",
  interrupted: "var(--c-text-muted)",
};

/** CVE 占位符判断：后端已把 "N/A" 归一化为空串，前端再兜一层旧数据 */
export function hasCve(cve?: string | null): boolean {
  const s = String(cve ?? "").trim().toLowerCase();
  return !!s && !["n/a", "na", "none", "null", "-", "—"].includes(s);
}

export const fmtClock = (ts: number) => {
  const d = new Date(ts * 1000);
  const p = (n: number) => String(n).padStart(2, "0");
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
};

export const fmtDuration = (sec: number) => {
  const s = Math.max(0, Math.floor(sec));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const r = s % 60;
  return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}:${String(r).padStart(2, "0")}`;
};
