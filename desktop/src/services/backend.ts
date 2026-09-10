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
] as const;

/* ---------- 类型（与后端 DTO 对齐） ---------- */

export type Verdict = "CONFIRMED" | "SAFE" | "UNKNOWN";
export type TaskStatus = "pending" | "running" | "done" | "failed" | "cancelled";
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
  name: string;
  status: Verdict;
  severity: BackendSev;
  url: string;
  evidence: string;
  extra: Record<string, unknown>;
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
}

export interface MetricsSnapshot {
  uptime: number;
  tasks: Record<string, number>;
  active: number;
  results: Record<string, number>;
  storageTasks: number | null;
}

/* ---------- API 客户端 ---------- */

export function getApiBase(): string {
  return localStorage.getItem("ruoyi-scan.apiBase") || DEFAULT_API_BASE;
}

export function setApiBase(base: string) {
  localStorage.setItem("ruoyi-scan.apiBase", base.replace(/\/+$/, ""));
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function http<T>(path: string, init?: RequestInit): Promise<T> {
  const url = getApiBase() + path;
  const res = await fetch(url, {
    headers: { "Content-Type": "application/json", ...(init?.headers || {}) },
    ...init,
  });
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
  health: () => http<{ status: string; version: string; uptime: number }>("/api/system/health"),
  version: () => http<EngineInfo>("/api/system/version"),
  fingerprint: (target: string) =>
    http<{
      target: string;
      cms: string;
      version: string;
      confidence: number;
      matched: string[];
      waf: string;
      waf_display: string;
    }>(`/api/system/fingerprint?target=${encodeURIComponent(target)}`),

  listTasks: () => http<ScanTask[]>("/api/scan"),
  getTask: (id: string) => http<ScanTask>(`/api/scan/${encodeURIComponent(id)}`),
  taskResults: (id: string) => http<ScanResultItem[]>(`/api/scan/${encodeURIComponent(id)}/results`),
  submitScan: (p: ScanSubmitPayload) => http<{ task_id: string; status: string }>("/api/scan", {
    method: "POST",
    body: JSON.stringify(p),
  }),
  cancelScan: (id: string) => http<{ task_id: string; status: string }>(`/api/scan/${encodeURIComponent(id)}`, {
    method: "DELETE",
  }),
  listPlugins: () => http<PluginMeta[]>("/api/plugins"),
  getPlugin: (name: string) => http<PluginMeta>(`/api/plugins/${encodeURIComponent(name)}`),
  reportMeta: (id: string) =>
    http<{ task_id: string; formats: string[]; paths: string[] }>(`/api/report/${encodeURIComponent(id)}`),
  /** 报告下载走 <a href> 直下（FileResponse 带 Content-Disposition），不需要 fetch */
  reportDownloadUrl: (id: string, fmt: string) =>
    `${getApiBase()}/api/report/${encodeURIComponent(id)}/${fmt}`,

  /* E9 定时扫描 */
  listSchedules: () => http<ScheduleJob[]>("/api/schedule"),
  createSchedule: (body: { cron: string; target: string; mode?: string; payload?: Record<string, unknown> }) =>
    http<{ job_id: string; cron: string; target: string; status: string }>("/api/schedule", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  deleteSchedule: (jobId: string) =>
    http<{ job_id: string; status: string }>(`/api/schedule/${encodeURIComponent(jobId)}`, { method: "DELETE" }),
};

/* ---------- Prometheus 指标解析 ---------- */

/** 拉取 /api/system/metrics 并解析为结构化快照（任务/结果统计、活跃数、uptime） */
export async function fetchMetrics(): Promise<MetricsSnapshot> {
  const res = await fetch(`${getApiBase()}/api/system/metrics`);
  if (!res.ok) throw new ApiError(res.status, `HTTP ${res.status}`);
  const text = await res.text();
  const uptime = numOf(text, "ruoyi_scan_uptime_seconds");
  const active = numOf(text, "ruoyi_scan_tasks_active");
  const storageTasks = numOf(text, "ruoyi_scan_storage_tasks");
  const tasks = seriesOf(text, "ruoyi_scan_tasks_total");
  const results = seriesOf(text, "ruoyi_scan_results_total");
  return { uptime, tasks, active, results, storageTasks };
}

function numOf(text: string, metric: string): number {
  const m = text.match(new RegExp(`^${metric}\\s+([0-9.]+)$`, "m"));
  return m ? Number(m[1]) : 0;
}

function seriesOf(text: string, metric: string): Record<string, number> {
  const out: Record<string, number> = {};
  const re = new RegExp(`^${metric}\\{status="([^"]+)"\\}\\s+([0-9.]+)$`, "gm");
  for (const m of text.matchAll(re)) out[m[1]] = Number(m[2]);
  return out;
}

/* ---------- WebSocket 客户端 ---------- */

export type WsState = "connecting" | "open" | "closed";

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
        if (
          e.type === "complete" ||
          (e.type === "error") ||
          (d.status && ["done", "failed", "cancelled"].includes(String(d.status)))
        ) {
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

const SEV_UI: Record<BackendSev, "HIGH" | "MED" | "LOW"> = { high: "HIGH", medium: "MED", low: "LOW" };
export const sevToUi = (s: BackendSev | string): "HIGH" | "MED" | "LOW" => SEV_UI[s as BackendSev] || "LOW";

export const MODE_LABEL: Record<ScanMode, string> = {
  u: "综合扫描 u",
  m: "目录扫描 m",
  p: "漏洞检测 p",
  l: "登录爆破 l",
};

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
