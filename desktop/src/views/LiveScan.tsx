import { useEffect, useMemo, useRef, useState } from "react";
import { Topbar } from "../components/Topbar";
import { StatIcon, StopIcon, PlusIcon } from "../components/icons";
import { SchedulePanel } from "../components/SchedulePanel";
import { useApp } from "../state/AppCtx";
import { usePersona, operatorAvatarSrc, type MeiSay } from "../state/PersonaCtx";
import { useScanConsole, type LogLevel } from "../state/useScanConsole";
import { VerdictChip, SeverityText } from "../components/ui";
import {
  api, fmtClock, fmtDuration, MODE_LABEL, sevToUi,
  type ScanMode, type ScanResultItem, type ScanTask,
} from "../services/backend";

const logColor: Record<LogLevel, string> = {
  info: "#9A9AC0",
  route: "#2EE6E6",
  confirmed: "#FF6B7A",
  safe: "#3DE8A0",
  unknown: "#FFB84D",
  error: "#FF4D5E",
  meiyi: "#FF3EC8",
};

const statusColor: Record<string, string> = {
  pending: "var(--c-sem-amber)",
  running: "var(--c-accent-primary)",
  done: "var(--c-sem-green)",
  failed: "var(--c-sem-red)",
  cancelled: "var(--c-text-muted)",
};

function useNow(ms: number | null) {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    if (ms === null) return;
    setNow(Date.now());
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [ms]);
  return now;
}

/** 水平任务切换条 */
function TaskBar({ activeId, onPick }: { activeId: string | null; onPick: (t: ScanTask) => void }) {
  const { tasks, openDialog } = useApp();
  if (tasks.length === 0) return null;
  return (
    <div className="flex items-center gap-2 px-6 pb-1 pt-1">
      <div className="thin-scroll flex min-w-0 flex-1 items-center gap-2 overflow-x-auto">
        {tasks.map((t) => {
          const sel = t.task_id === activeId;
          const isRun = t.status === "running" || t.status === "pending";
          return (
            <button
              key={t.task_id}
              onClick={() => onPick(t)}
              className="flex h-[28px] shrink-0 items-center gap-2 rounded-sm border px-2.5 font-mono text-[10px] transition-colors"
              style={{
                borderColor: sel ? "var(--c-accent-primary)" : "var(--c-border)",
                background: sel ? "var(--c-bubble-bg)" : "var(--c-card-soft)",
                color: sel ? "var(--c-accent-primary)" : "var(--c-text-secondary)",
              }}
              title={t.target}
            >
              <i className="h-1.5 w-1.5 rounded-full" style={{ background: statusColor[t.status] }} />
              <span>{t.task_id.slice(0, 6)}</span>
              <span className="text-ink-3">{MODE_LABEL[t.mode as ScanMode]?.split(" ")[0]}</span>
              <span className="max-w-[150px] truncate text-ink">{t.target.replace(/^https?:\/\//, "")}</span>
              {isRun ? <i className="h-1 w-1 animate-pulse rounded-full bg-accent" /> : null}
            </button>
          );
        })}
      </div>
      <button
        onClick={openDialog}
        className="flex h-[28px] shrink-0 items-center gap-1.5 rounded-sm border border-edge-ghost px-3 text-[11px] text-ink-2 transition-colors hover:bg-cardsoft"
      >
        <PlusIcon /> 新建
      </button>
    </div>
  );
}

export function LiveScan() {
  const { tasks, online, openDialog, engine, refreshTasks, selectedTaskId, selectTask } = useApp();
  const { operator, lastSay } = usePersona();
  const active = useMemo(
    () => tasks.find((t) => t.task_id === selectedTaskId) ?? tasks[0] ?? null,
    [tasks, selectedTaskId],
  );
  const console = useScanConsole(active, active?.task_id ?? "none");
  const boxRef = useRef<HTMLDivElement>(null);
  const now = useNow(active && active.status === "running" ? active.started_at : null);
  const running = active && (active.status === "running" || active.status === "pending");

  // 到达页面时若从未选过任务，默认聚焦最新一个
  useEffect(() => {
    if (!selectedTaskId && tasks.length > 0) selectTask(tasks[0].task_id);
  }, [selectedTaskId, tasks, selectTask]);

  useEffect(() => {
    boxRef.current?.scrollTo({ top: boxRef.current.scrollHeight });
  }, [console.lines]);

  const elapsed = active
    ? console.status === "done" || console.status === "failed" || console.status === "cancelled"
      ? fmtDuration(active.duration)
      : fmtDuration((now - active.started_at * 1000) / 1000)
    : "00:00:00";

  const stop = async () => {
    if (!active) return;
    if (!window.confirm(`确认停止任务 ${active.task_id.slice(0, 8)}？运行中的插件将在一轮后自行退出。`)) return;
    try {
      await api.cancelScan(active.task_id);
      await refreshTasks();
    } catch {
      /* ignore */
    }
  };

  const pct = running ? console.progress.percent : console.status === "done" ? (console.progress.percent || 100) : console.progress.percent;

  const meiMsg = !online
    ? "引擎掉线了，快回设置页看看连接吧！"
    : !active
      ? "还没有扫描任务，点右上角「新建扫描」吧！"
      : running
        ? console.wsState === "open"
          ? `${console.progress.done}/${console.progress.total} 插件跑完啦，保持这个节奏！`
          : "正在连接任务事件流…"
        : console.tally.CONFIRMED > 0
          ? `扫描完成！发现 ${console.tally.CONFIRMED} 个已确认问题，快看报告吧！`
          : "本轮扫描完成，暂无确认项，安全！";

  const logArea = active ? console.lines : [];

  return (
    <div className="flex h-full flex-col">
      <Topbar
        title="扫描现场 · LIVE SCAN"
        sub={
          active
            ? `TARGET ${active.target} · ${MODE_LABEL[active.mode as ScanMode]} · ${(console.status || active.status).toUpperCase()} · ELAPSED ${elapsed}`
            : "NO TASK · 点击新建扫描开始"
        }
        pulse={!!running}
        right={
          <>
            {active ? (
              <span
                className="flex h-[30px] items-center rounded-sm border bg-bubble px-2.5 font-mono text-[10.5px]"
                style={{ borderColor: statusColor[active.status], color: statusColor[active.status] }}
              >
                {active.status.toUpperCase()}
              </span>
            ) : null}
            {running ? (
              <span className="flex h-[30px] items-center rounded-sm border border-edge bg-bubble px-2.5 font-mono text-[10.5px] text-accent">
                {console.progress.done}/{console.progress.total} POC
              </span>
            ) : null}
            <button
              onClick={openDialog}
              className="flex h-[34px] items-center gap-1.5 rounded-sm bg-accent px-3.5 text-[12px] font-semibold text-btntext"
            >
              <PlusIcon /> 新建扫描
            </button>
            {running ? (
              <button
                onClick={stop}
                className="flex h-[34px] items-center gap-1.5 rounded-sm border border-alertstroke px-3.5 text-[12px] text-red"
              >
                <StopIcon /> 停止
              </button>
            ) : null}
          </>
        }
      />

      <TaskBar activeId={active?.task_id ?? null} onPick={(t) => selectTask(t.task_id)} />

      {tasks.length === 0 ? (
        <div className="flex min-h-0 flex-1 flex-col items-center justify-center gap-4 px-6">
          <div className="rounded border bg-card p-8 text-center" style={{ borderColor: "var(--c-border)" }}>
            <p className="mb-1 font-mono text-[9px] tracking-wider text-ink-3">NO SCAN TASK</p>
            <p className="mb-4 text-[13px] text-ink">
              {online ? "还没有扫描任务。填写目标后提交，实时日志会出现在这里。" : "引擎未连接。请确认本地后端已启动。"}
            </p>
            {online ? (
              <button
                onClick={openDialog}
                className="h-[36px] rounded-sm bg-accent px-5 text-[12px] font-semibold text-btntext"
              >
                新建扫描
              </button>
            ) : (
              <div className="flex items-center gap-2">
                <span className="font-mono text-[10px] text-ink-3">{engine ? `v${engine.version}` : "后端地址 http://127.0.0.1:8123"}</span>
                <button onClick={refreshTasks} className="h-[32px] rounded-sm border border-edge px-4 text-[11px] text-ink-2">
                  重试
                </button>
              </div>
            )}
          </div>
        </div>
      ) : (
        <>
          <div className="flex min-h-0 flex-1 gap-3.5 px-6 pt-1">
            {/* CRT 终端（固定暗色，产品签名） */}
            <div className="crt flex min-w-0 flex-1 flex-col overflow-hidden rounded border border-edge">
              <div className="flex items-center justify-between bg-[#12122a] px-3.5 py-2.5">
                <div className="flex items-center gap-2">
                  <div className="flex gap-1.5">
                    <i className="h-2 w-2 rounded-full bg-[#FF4D5E]/70" />
                    <i className="h-2 w-2 rounded-full bg-[#FFB84D]/70" />
                    <i className="h-2 w-2 rounded-full bg-[#3DE8A0]/70" />
                  </div>
                  <span className="font-mono text-[10px] text-[#5E5E85]">
                    engine.log — ruoyi-scan {engine ? `v${engine.version}` : ""} · {active ? active.task_id : ""}
                  </span>
                </div>
                <span
                  className="font-mono text-[7px] font-bold tracking-wider"
                  style={{ color: console.wsState === "open" ? "#FF3EC8" : "#5E5E85" }}
                >
                  {console.wsState === "open" ? "LIVE" : console.wsState.toUpperCase()}
                </span>
              </div>
              <div
                ref={boxRef}
                className="thin-scroll flex-1 overflow-auto p-3.5 font-mono text-[11px] leading-[17px]"
                style={{ color: "#9A9AC0" }}
              >
                {logArea.map((l) => (
                  <div key={l.id} style={{ color: logColor[l.level] }}>
                    [{l.time}] {l.text}
                  </div>
                ))}
                <div className="mt-1 inline-block h-3.5 w-2 animate-pulse bg-[#2EE6E6]/80" />
              </div>
            </div>

            {/* 右列：空间不足时整列滚动，子卡不再被压碎 */}
            <div className="thin-scroll flex w-[300px] shrink-0 flex-col gap-3.5 overflow-y-auto pb-1">
              <div className="flex shrink-0 flex-col items-center gap-2 rounded border bg-card p-3.5" style={{ borderColor: "var(--c-border)" }}>
                <span className="font-mono text-[8px] tracking-wider text-ink-3">SCAN PROGRESS</span>
                <ProgressRing pct={Math.round(pct)} sub={active ? `${console.progress.done}/${console.progress.total}` : "--"} />
                <span className="font-mono text-[10px] text-ink-2">
                  {active ? `${active.target.replace(/^https?:\/\//, "")} · WS ${console.wsState}` : "无任务"}
                </span>
              </div>

              <div className="flex shrink-0 flex-col gap-2 rounded-lg border border-edge-soft bg-cardsoft p-3">
                <span className="self-start font-mono text-[8px] tracking-wider text-pink">
                  {operator.callsign.toUpperCase()} SUPPORT
                </span>
                <div className="flex justify-center">
                  <img
                    src={operatorAvatarSrc(operator)}
                    alt={operator.callsign}
                    className="mei-glow h-[84px] w-[84px] rounded-full object-cover"
                  />
                </div>
                <div className="w-full rounded-lg bg-bubble p-2">
                  <p className="text-[10.5px] leading-[15px] text-bubble">{meiMsg}</p>
                </div>
                {operator.speak && lastSay ? <MeiToast say={lastSay} /> : null}
              </div>

              <div className="shrink-0">
                <SchedulePanel />
              </div>
            </div>
          </div>

          {/* 三态统计条 */}
          <div className="flex gap-3.5 px-6 pt-3.5">
            <Stat
              label="CONFIRMED 已确认" value={String(console.tally.CONFIRMED)} tone="red" icon="target"
              border="var(--c-alert-stroke)"
            />
            <Stat
              label="SAFE 安全" value={String(console.tally.SAFE)} tone="green" icon="check"
              border="var(--c-sem-green-tint)"
            />
            <Stat
              label="UNKNOWN 待复核" value={String(console.tally.UNKNOWN)} tone="amber" icon="diamond"
              border="var(--c-sem-amber-tint)"
            />
            <Stat
              label="ENGINE 状态" value={online ? "ONLINE" : "DOWN"} tone="purple" icon="bolt"
              border="var(--c-border)"
              small
            />
          </div>

          {/* 结果明细（可折叠，仅终态且有结果时展示） */}
          {active && !running ? <ResultsTable taskId={active.task_id} refreshKey={`${active.task_id}-${console.taskDone}`} /> : null}
        </>
      )}
    </div>
  );
}

/** 任务结果明细表：从 /api/scan/{id}/results 拉取，扫描中实时追加 */
function ResultsTable({ taskId, refreshKey }: { taskId: string; refreshKey: string }) {
  const [open, setOpen] = useState(false);
  const [rows, setRows] = useState<ScanResultItem[]>([]);
  const [filter, setFilter] = useState<"ALL" | "CONFIRMED" | "SAFE" | "UNKNOWN">("ALL");

  useEffect(() => {
    let alive = true;
    api.taskResults(taskId)
      .then((r) => { if (alive) setRows(r); })
      .catch(() => { /* ignore */ });
    return () => { alive = false; };
  }, [taskId, refreshKey]);

  const visible = filter === "ALL" ? rows : rows.filter((r) => r.status === filter);
  const tally = { ALL: rows.length, CONFIRMED: 0, SAFE: 0, UNKNOWN: 0 } as Record<string, number>;
  for (const r of rows) if (r.status in tally) tally[r.status] += 1;

  if (rows.length === 0) return null;

  return (
    <div className="flex min-h-0 flex-1 flex-col px-6 pb-4 pt-3">
      <section className="flex min-h-0 flex-1 flex-col overflow-hidden rounded border bg-card" style={{ borderColor: "var(--c-border)" }}>
        <div className="flex items-center justify-between px-3.5 py-2.5">
          <button onClick={() => setOpen(!open)} className="flex items-center gap-2 text-[12px] font-semibold text-ink">
            <span className="font-mono text-[9px] text-accent">{open ? "▼" : "▶"}</span>
            结果明细 / FINDINGS · {rows.length}
          </button>
          {open ? (
            <div className="flex gap-1.5">
              {(["ALL", "CONFIRMED", "SAFE", "UNKNOWN"] as const).map((k) => (
                <button
                  key={k}
                  onClick={() => setFilter(k)}
                  className={`h-[22px] rounded-sm px-2 font-mono text-[9px] transition-colors ${
                    filter === k ? "bg-accent text-btntext" : "border border-edge bg-cardsoft text-ink-3 hover:text-ink"
                  }`}
                >
                  {k} {tally[k]}
                </button>
              ))}
            </div>
          ) : null}
        </div>
        {open ? (
          <>
            <div className="flex items-center gap-2 bg-cardsoft px-3.5 py-1.5">
              <span className="w-[76px] text-[10px] text-ink-3">判定</span>
              <span className="w-[60px] text-[10px] text-ink-3">严重度</span>
              <span className="flex-1 text-[10px] text-ink-3">漏洞名称</span>
              <span className="w-[240px] text-[10px] text-ink-3">触发 URL</span>
            </div>
            <div className="thin-scroll min-h-0 flex-1 overflow-auto">
              {visible.map((r, i) => (
                <div key={`${r.name}-${r.url}-${i}`} className={`flex items-center gap-2 px-3.5 py-1.5 hover:bg-cardsoft ${i % 2 === 1 ? "bg-zebra" : ""}`}>
                  <span className="w-[76px]"><VerdictChip v={r.status} /></span>
                  <span className="w-[60px]"><SeverityText s={sevToUi(r.severity)} /></span>
                  <span className="flex-1 truncate text-[11px] text-ink" title={r.evidence || r.name}>{r.name}</span>
                  <span className="w-[240px] truncate font-mono text-[10px] text-ink-2" title={r.url}>{r.url || "—"}</span>
                </div>
              ))}
            </div>
          </>
        ) : null}
      </section>
    </div>
  );
}

function Stat({
  label, value, tone, icon, border, small,
}: {
  label: string; value: string; tone: "red" | "green" | "amber" | "purple"; icon: string; border: string; small?: boolean;
}) {
  const color = tone === "red" ? "var(--c-sem-red)" : tone === "green" ? "var(--c-sem-green)" : tone === "amber" ? "var(--c-sem-amber)" : "var(--c-nav-num)";
  return (
    <div className="flex flex-1 items-center gap-2.5 rounded border bg-card p-3.5" style={{ borderColor: border }}>
      <StatIcon kind={icon} />
      <div className="flex flex-col gap-0.5">
        <span className="text-[10px] text-ink-2">{label}</span>
        <span className={`font-mono font-semibold leading-[30px] tracking-tight ${small ? "text-[22px]" : "text-[28px]"}`} style={{ color }}>
          {value}
        </span>
      </div>
    </div>
  );
}

/** 枚依播报浮条：人格事件（扫描完成/确认告警）驱动，4.5s 自动淡出 */
function MeiToast({ say }: { say: MeiSay }) {
  const [show, setShow] = useState(false);
  useEffect(() => {
    setShow(true);
    const t = setTimeout(() => setShow(false), 4500);
    return () => clearTimeout(t);
  }, [say.id]);
  if (!show) return null;
  const toneColor =
    say.tone === "confirm" ? "var(--c-sem-red)" : say.tone === "safe" ? "var(--c-sem-green)" : say.tone === "unknown" ? "var(--c-sem-amber)" : "var(--c-accent-primary)";
  return (
    <div
      className="mei-bubble w-full rounded-lg border p-2"
      style={{ borderColor: toneColor, background: "var(--c-bubble-bg)" }}
    >
      <p className="text-[10.5px] leading-[15px] text-bubble" style={{ color: toneColor }}>
        {say.text}
      </p>
    </div>
  );
}

/** 进度环：真实弧段 */
function ProgressRing({ pct, sub }: { pct: number; sub: string }) {
  const p = Math.max(0, Math.min(100, pct));
  const end = { x: 55 + 45 * Math.cos(((-90 + (p / 100) * 360) * Math.PI) / 180), y: 55 + 45 * Math.sin(((-90 + (p / 100) * 360) * Math.PI) / 180) };
  const largeArc = p > 50 ? 1 : 0;
  return (
    <svg width="110" height="110" viewBox="0 0 110 110" fill="none">
      <circle cx="55" cy="55" r="45" stroke="var(--c-grid-line)" strokeWidth="10" />
      <path
        d={`M55 10 A45 45 0 ${largeArc} 1 ${end.x.toFixed(2)} ${end.y.toFixed(2)}`}
        stroke="var(--c-accent-primary)"
        strokeWidth="10"
        strokeLinecap="round"
        fill="none"
      />
      <text x="55" y="58" textAnchor="middle" fontFamily="JetBrains Mono" fontWeight="600" fontSize="24" fill="var(--c-text-primary)">
        {p}%
      </text>
      <text x="55" y="74" textAnchor="middle" fontFamily="JetBrains Mono" fontSize="7" fill="var(--c-text-muted)">
        {sub}
      </text>
    </svg>
  );
}
