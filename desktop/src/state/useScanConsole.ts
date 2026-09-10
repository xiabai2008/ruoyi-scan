/**
 * useScanConsole — 把后端结构化 WS 事件合成为 LiveScan 所需的终端流。
 * 服务端无“日志”类事件（见 core/orchestrator.py），所有行由前端按事件类型渲染：
 *   result        → 三态彩色行（CONFIRMED/SAFE/UNKNOWN）
 *   fingerprint   → 指纹行
 *   waf/plugins_loaded/category_start/progress/report/complete/error → info/route 行
 */
import { useEffect, useMemo, useRef, useState } from "react";
import {
  api, fmtClock, openTaskSocket,
  type ScanTask, type TaskStatus, type Verdict, type WsEvent, type WsState,
} from "../services/backend";

export type LogLevel = "info" | "route" | "confirmed" | "safe" | "unknown" | "error" | "meiyi";
export interface LogLine { id: number; time: string; level: LogLevel; text: string }

interface ConsoleState {
  lines: LogLine[];
  status: TaskStatus;
  fingerprint: string;
  waf: string;
  progress: { done: number; total: number; percent: number };
  tally: Record<Verdict, number>;
  resultCount: number;
  wsState: WsState;
  taskDone: boolean;
  error: string;
  connectedAt: number;
}

const empty: ConsoleState = {
  lines: [], status: "pending", fingerprint: "", waf: "",
  progress: { done: 0, total: 0, percent: 0 },
  tally: { CONFIRMED: 0, SAFE: 0, UNKNOWN: 0 },
  resultCount: 0, wsState: "connecting", taskDone: false, error: "", connectedAt: 0,
};

function verdictOf(s: string): Verdict {
  return s === "CONFIRMED" || s === "SAFE" || s === "UNKNOWN" ? s : "UNKNOWN";
}

/** 从 task 补一条离线快照行（WS 断开/任务已终态时仍可显示概况） */
export function useScanConsole(task: ScanTask | null, key: string) {
  const taskId = task?.task_id ?? null;
  const [st, setSt] = useState<ConsoleState>(empty);
  const idRef = useRef(0);
  const lastPctRef = useRef(-1);
  const tick = useRef(0);

  useEffect(() => {
    if (!taskId || !task) return;
    const push = (level: LogLevel, text: string, ts?: number) => {
      const time = ts ? fmtClock(ts) : fmtClock(Date.now() / 1000);
      setSt((prev) => ({
        ...prev,
        lines: [...prev.lines.slice(-200), { id: ++tick.current, time, level, text }],
      }));
    };

    // 初始化：任务快照（非空 task 一定在线，先重置）
    idRef.current = 0;
    tick.current = 0;
    lastPctRef.current = -1;
    setSt((prev) => ({
      ...empty,
      status: task.status,
      fingerprint: task.fingerprint?.cms ? `${task.fingerprint.cms} ${task.fingerprint.variant || task.fingerprint.version || ""}`.trim() : "",
      progress: { done: 0, total: 0, percent: 0 },
      wsState: "connecting",
    }));
    const t0 = Date.now() / 1000;
    push("info", `task ${task.task_id} · ${task.mode} mode · target ${task.target}`);

    const onEvent = (e: WsEvent) => {
      const d = (e.data || {}) as Record<string, unknown>;
      switch (e.type) {
        case "status": {
          const s = String(d.status);
          push("info", `status: ${s}`, e.timestamp);
          setSt((prev) => ({ ...prev, status: s as TaskStatus }));
          break;
        }
        case "fingerprint":
          setSt((prev) => ({
            ...prev,
            fingerprint: `${d.cms ?? ""} ${d.variant ?? d.version ?? ""}`.trim(),
          }));
          push("info", `fingerprint: ${d.cms}${d.version ? " " + d.version : ""} detected (confidence ${d.confidence})`, e.timestamp);
          break;
        case "waf":
          setSt((prev) => ({ ...prev, waf: String(d.waf || "") }));
          push("info", `waf: ${d.display || d.waf || "none"}${d.bypass_hint ? " · " + d.bypass_hint : ""}`, e.timestamp);
          break;
        case "waf_bypass":
          push("route", `waf_bypass: ${d.payload || d.bypass || d.detail || "applied"}`, e.timestamp);
          break;
        case "portscan":
          push("route", `portscan: ${d.host || d.target || ""} · ${Array.isArray(d.open_ports) ? d.open_ports.join(",") : (d.ports ?? d.summary ?? "done")}`, e.timestamp);
          break;
        case "recon_start":
          push("info", `recon: probing ${d.target || ""}`, e.timestamp);
          break;
        case "recon":
          push("info", `recon: ${d.summary || d.detail || JSON.stringify(d).slice(0, 120)}`, e.timestamp);
          break;
        case "recon_error":
          push("error", `recon_error: ${d.error || "unknown"}`, e.timestamp);
          break;
        case "component":
          push("info", `component: ${d.name || d.component || "?"}${d.version ? " " + d.version : ""}`, e.timestamp);
          break;
        case "template":
          push("info", `template: ${d.name || d.template || "?"} loaded`, e.timestamp);
          break;
        case "auth":
          push("route", `auth: ${d.summary || d.detail || "credential probe"}`, e.timestamp);
          break;
        case "plugin_fallback":
          push("info", `plugin_fallback: ${d.plugin || "?"} → ${d.reason || "fallback"}`, e.timestamp);
          break;
        case "nuclei_error":
          push("error", `nuclei_error: ${d.error || "engine unavailable"}`, e.timestamp);
          break;
        case "plugins_loaded":
          push("route", `plugins_loaded: ${d.total_count} total (common ${d.common_count ?? "-"})`, e.timestamp);
          break;
        case "category_start":
          push("route", `category_start: ${d.category} · ${d.count} plugins`, e.timestamp);
          break;
        case "result": {
          const v = verdictOf(String(d.status));
          const sev = String(d.severity || "low").toUpperCase();
          push(v === "CONFIRMED" ? "confirmed" : v === "SAFE" ? "safe" : "unknown",
            `${v.padEnd(9)}  [${sev}] ${d.name}  ${d.url ? "· " + d.url : ""}`, e.timestamp);
          setSt((prev) => ({
            ...prev,
            tally: { ...prev.tally, [v]: prev.tally[v] + 1 },
            resultCount: prev.resultCount + 1,
          }));
          if (v === "CONFIRMED") {
            void import("./personaHooks").then((m) => m.fireConfirmAlert(String(d.name || "")));
          }
          break;
        }
        case "progress": {
          const done = Number(d.done ?? 0);
          const total = Number(d.total ?? 0);
          const percent = Number(d.percent ?? 0);
          setSt((prev) => ({ ...prev, progress: { done, total, percent } }));
          const bucket = Math.floor(percent / 5);
          if (bucket !== lastPctRef.current) {
            lastPctRef.current = bucket;
            push("route", `progress: ${done}/${total} plugins · ${percent}%`, e.timestamp);
          }
          break;
        }
        case "report":
          push("info", `report: ${(d.paths as string[])?.join(", ") || "generated"}`, e.timestamp);
          break;
        case "complete":
          push("meiyi", `complete: ${d.result_count} findings · ${d.confirmed_count} confirmed · duration ${(Number(d.duration) || 0).toFixed(1)}s`, e.timestamp);
          setSt((prev) => ({ ...prev, taskDone: true }));
          void import("./personaHooks").then((m) =>
            m.fireScanDone({
              target: task?.target ?? "",
              total: Number(d.result_count) || 0,
              confirmed: Number(d.confirmed_count) || 0,
              duration: Number(d.duration) || 0,
            }),
          );
          break;
        case "error": {
          const msg = String(d.error || "");
          push("error", `error: ${msg}`, e.timestamp);
          setSt((prev) => ({ ...prev, error: msg, taskDone: true }));
          break;
        }
        case "connection_closed":
          break;
        case "ping":
          break;
        case "plugins_loaded":
          break; // 已在上方处理（防御重复 case 警告）
        default: {
          // 未知事件类型也落一行，保证终端流不吞事件
          const brief = JSON.stringify(d);
          push("info", `${e.type}: ${brief === "{}" ? "" : brief.slice(0, 120)}`, e.timestamp);
          break;
        }
      }
    };

    const onTerminal = () => setSt((prev) => ({ ...prev, taskDone: true }));
    const close = openTaskSocket(taskId, onEvent, (s) => setSt((prev) => ({ ...prev, wsState: s })), onTerminal);
    void t0;
    return close;
  }, [taskId, key]);

  // WS 在任务终态后会立刻关闭 → 用 REST 兜底补全最终 tally（避免用户只开列表就看到空统计）
  useEffect(() => {
    if (!taskId || !st.taskDone) return;
    let alive = true;
    api.taskResults(taskId).then((r) => {
      if (!alive) return;
      const tally = { CONFIRMED: 0, SAFE: 0, UNKNOWN: 0 };
      for (const it of r) tally[verdictOf(it.status)] += 1;
      setSt((prev) => ({ ...prev, tally, resultCount: r.length }));
    }).catch(() => { /* 后端离线忽略 */ });
    return () => { alive = false; };
  }, [taskId, st.taskDone]);

  return useMemo(() => ({ ...st, hasLines: st.lines.length > 0 }), [st]);
}
