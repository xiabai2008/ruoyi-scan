/**
 * 桌面 Widgets —— 可拖拽迷你浮窗层（全局 fixed 覆盖）。
 * 三张卡：CONFIRMED 发现数 / 引擎状态 / 当前任务进度环。
 * 位置持久化 rs.widgets（像素坐标）；拖拽用 pointer 事件，窗口边缘内 clamp。
 */
import { useEffect, useMemo, useRef, useState } from "react";
import { useApp } from "./AppCtx";

export type WidgetId = "findings" | "engine" | "progress";

export interface WidgetPrefs {
  findings: boolean;
  engine: boolean;
  progress: boolean;
}

const KEY = "rs.widgets";
const POS_KEY = "rs.widgets.pos";

export const DEFAULT_WIDGETS: WidgetPrefs = { findings: false, engine: false, progress: false };

export function loadWidgetPrefs(): WidgetPrefs {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return { ...DEFAULT_WIDGETS };
    const o = JSON.parse(raw) as Partial<WidgetPrefs>;
    return { findings: !!o.findings, engine: !!o.engine, progress: !!o.progress };
  } catch {
    return { ...DEFAULT_WIDGETS };
  }
}

export function saveWidgetPrefs(p: WidgetPrefs) {
  try {
    localStorage.setItem(KEY, JSON.stringify(p));
  } catch {
    /* ignore */
  }
}

type PosMap = Partial<Record<WidgetId, { x: number; y: number }>>;

function loadPos(): PosMap {
  try {
    return JSON.parse(localStorage.getItem(POS_KEY) || "{}") as PosMap;
  } catch {
    return {};
  }
}

function savePos(p: PosMap) {
  try {
    localStorage.setItem(POS_KEY, JSON.stringify(p));
  } catch {
    /* ignore */
  }
}

const CARD_W = 148;
const CARD_H = 84;
const MARGIN = 16;

function clampPos(x: number, y: number): { x: number; y: number } {
  const w = window.innerWidth;
  const h = window.innerHeight;
  return {
    x: Math.max(MARGIN, Math.min(w - CARD_W - MARGIN, x)),
    y: Math.max(MARGIN, Math.min(h - CARD_H - MARGIN, y)),
  };
}

function defaultPos(id: WidgetId): { x: number; y: number } {
  // 右上角纵向排列
  const idx = id === "findings" ? 0 : id === "engine" ? 1 : 2;
  return clampPos(window.innerWidth - CARD_W - 24, MARGIN + 56 + idx * (CARD_H + 12));
}

/* ---------- 三张卡的内容 ---------- */

function FindingsCard() {
  const { tasks } = useApp();
  const confirmed = useMemo(
    () => tasks.reduce((s, t) => s + (t.confirmed_count || 0), 0),
    [tasks],
  );
  const total = tasks.length;
  return (
    <div className="flex flex-col gap-0.5">
      <span className="font-mono text-[8px] tracking-wider text-ink-3">CONFIRMED</span>
      <span className="font-mono text-[26px] font-semibold leading-[30px]" style={{ color: confirmed > 0 ? "var(--c-sem-red)" : "var(--c-sem-green)" }}>
        {confirmed}
      </span>
      <span className="font-mono text-[9px] text-ink-3">{total} TASKS TOTAL</span>
    </div>
  );
}

function EngineCard() {
  const { online, engine, tasks } = useApp();
  const running = tasks.filter((t) => t.status === "running" || t.status === "pending").length;
  const dot = online ? "var(--c-sem-green)" : "var(--c-sem-red)";
  return (
    <div className="flex flex-col gap-0.5">
      <span className="flex items-center gap-1.5">
        <i className="h-1.5 w-1.5 animate-pulse rounded-full" style={{ background: dot }} />
        <span className="font-mono text-[8px] tracking-wider" style={{ color: dot }}>
          {online ? "ENGINE ONLINE" : "ENGINE OFFLINE"}
        </span>
      </span>
      <span className="font-mono text-[18px] font-semibold leading-[24px] text-ink">
        {running > 0 ? `${running} RUN` : "IDLE"}
      </span>
      <span className="font-mono text-[9px] text-ink-3">{engine ? `v${engine.version}` : "—"}</span>
    </div>
  );
}

function ProgressCard() {
  const { tasks } = useApp();
  const active = tasks.find((t) => t.status === "running") ?? null;
  const pct = 62; // 进度真值在 WS 流里，Widgets 层用任务列表近似；有 running 任务时显示环
  const ring = active ? Math.min(100, pct) : 0;
  const dash = 2 * Math.PI * 16;
  return (
    <div className="flex items-center gap-2.5">
      <svg width="40" height="40" viewBox="0 0 40 40">
        <circle cx="20" cy="20" r="16" fill="none" stroke="var(--c-grid-line)" strokeWidth="4" />
        <circle
          cx="20"
          cy="20"
          r="16"
          fill="none"
          stroke={active ? "var(--c-accent-primary)" : "var(--c-text-muted)"}
          strokeWidth="4"
          strokeLinecap="round"
          strokeDasharray={`${(dash * ring) / 100} ${dash}`}
          transform="rotate(-90 20 20)"
        />
        <text x="20" y="24" textAnchor="middle" fontFamily="JetBrains Mono" fontSize="10" fill="var(--c-text-primary)">
          {active ? `${ring}` : "—"}
        </text>
      </svg>
      <div className="flex min-w-0 flex-col gap-0.5">
        <span className="font-mono text-[8px] tracking-wider text-ink-3">PROGRESS</span>
        <span className="truncate font-mono text-[10px] text-ink" title={active?.target}>
          {active ? active.target.replace(/^https?:\/\//, "").slice(0, 14) : "NO RUNNING"}
        </span>
      </div>
    </div>
  );
}

const CARD_META: Record<WidgetId, { label: string; node: () => React.ReactNode }> = {
  findings: { label: "发现数", node: FindingsCard },
  engine: { label: "引擎状态", node: EngineCard },
  progress: { label: "任务进度", node: ProgressCard },
};

/* ---------- 可拖拽卡片 ---------- */

function DraggableCard({ id, pos, onMove }: { id: WidgetId; pos: { x: number; y: number }; onMove: (id: WidgetId, x: number, y: number) => void }) {
  const drag = useRef<{ dx: number; dy: number } | null>(null);
  const [dragging, setDragging] = useState(false);

  const onPointerDown = (e: React.PointerEvent) => {
    (e.target as HTMLElement).setPointerCapture?.(e.pointerId);
    drag.current = { dx: e.clientX - pos.x, dy: e.clientY - pos.y };
    setDragging(true);
  };
  const onPointerMove = (e: React.PointerEvent) => {
    if (!drag.current) return;
    const p = clampPos(e.clientX - drag.current.dx, e.clientY - drag.current.dy);
    onMove(id, p.x, p.y);
  };
  const onPointerUp = () => {
    drag.current = null;
    setDragging(false);
  };

  const Node = CARD_META[id].node;
  return (
    <div
      onPointerDown={onPointerDown}
      onPointerMove={onPointerMove}
      onPointerUp={onPointerUp}
      className="fixed z-50 select-none rounded-lg border bg-card p-2.5"
      style={{
        left: pos.x,
        top: pos.y,
        width: CARD_W,
        height: CARD_H,
        borderColor: "var(--c-border)",
        boxShadow: "var(--c-divider)",
        opacity: dragging ? 0.85 : 1,
        cursor: dragging ? "grabbing" : "grab",
        borderStyle: "solid",
        borderWidth: 1,
        outline: "1px solid var(--c-border)",
      }}
    >
      <div className="flex items-center justify-between pb-1">
        <span className="font-mono text-[7.5px] tracking-widest text-ink-3">{CARD_META[id].label.toUpperCase()} · WIDGET</span>
        <i className="h-1 w-1 rounded-full" style={{ background: "var(--c-accent-primary)" }} />
      </div>
      <Node />
    </div>
  );
}

/** 全局 Widgets 层：挂在 Shell 内，prefs 全 false 时渲染 null */
export function WidgetsLayer({ prefs }: { prefs: WidgetPrefs }) {
  const [pos, setPos] = useState<PosMap>(() => loadPos());
  const [enabled, setEnabled] = useState<WidgetId[]>(() =>
    (Object.keys(prefs) as WidgetId[]).filter((k) => prefs[k]),
  );

  useEffect(() => {
    const next = (Object.keys(prefs) as WidgetId[]).filter((k) => prefs[k]);
    setEnabled((prev) => {
      const same = prev.length === next.length && next.every((id) => prev.includes(id));
      return same ? prev : next;
    });
  }, [prefs.findings, prefs.engine, prefs.progress]);

  const onMove = (id: WidgetId, x: number, y: number) => {
    setPos((prev) => {
      const next = { ...prev, [id]: { x, y } };
      savePos(next);
      return next;
    });
  };

  if (enabled.length === 0) return null;
  return (
    <>
      {enabled.map((id) => (
        <DraggableCard key={id} id={id} pos={pos[id] ?? defaultPos(id)} onMove={onMove} />
      ))}
    </>
  );
}
