import { useEffect, useState } from "react";
import { api, MODE_LABEL, type ScheduleJob, type ScanMode } from "../services/backend";
import { useApp } from "../state/AppCtx";

const CRON_PRESETS = [
  { label: "每 5 分钟", cron: "*/5 * * * *" },
  { label: "每 30 分钟", cron: "*/30 * * * *" },
  { label: "每小时", cron: "0 * * * *" },
  { label: "每天 09:00", cron: "0 9 * * *" },
  { label: "每 10 分钟", cron: "every:600" },
];

/**
 * 定时扫描面板（E9）：列出/创建/删除调度任务。
 * 调度表达式支持 cron 5 段式 与 every:<秒> 两种语法（lib/scheduler.py）。
 */
export function SchedulePanel() {
  const { online } = useApp();
  const [open, setOpen] = useState(false);
  const [jobs, setJobs] = useState<ScheduleJob[]>([]);
  const [cron, setCron] = useState("*/30 * * * *");
  const [target, setTarget] = useState("");
  const [mode, setMode] = useState<ScanMode>("u");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const load = () => {
    if (!online) return;
    api.listSchedules().then(setJobs).catch(() => setJobs([]));
  };

  useEffect(() => {
    load();
    if (!online) return;
    const t = setInterval(load, 10000);
    return () => clearInterval(t);
  }, [online]);

  const create = async () => {
    const t = target.trim();
    if (!t || !cron.trim()) {
      setErr("cron 与目标必填");
      return;
    }
    setBusy(true);
    setErr("");
    try {
      await api.createSchedule({ cron: cron.trim(), target: t, mode });
      setTarget("");
      load();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const remove = async (jobId: string) => {
    try {
      await api.deleteSchedule(jobId);
      load();
    } catch {
      /* ignore */
    }
  };

  return (
    <div className="flex flex-col rounded-lg border border-edge-soft bg-cardsoft">
      <button
        onClick={() => setOpen(!open)}
        className="flex items-center justify-between px-3 py-2"
      >
        <span className="font-mono text-[8px] tracking-wider text-ink-3">
          SCHEDULED SCANS · {jobs.length}
        </span>
        <span className="font-mono text-[9px] text-accent">{open ? "▲" : "▼"}</span>
      </button>

      {open ? (
        <div className="flex flex-col gap-2 border-t border-edge-soft px-3 pb-3 pt-2.5">
          {/* 现有任务 */}
          {jobs.length > 0 ? (
            <div className="flex flex-col gap-1.5">
              {jobs.map((j) => (
                <div key={j.job_id} className="flex items-center gap-1.5 rounded border border-edge bg-card px-2 py-1.5">
                  <div className="min-w-0 flex-1">
                    <p className="truncate font-mono text-[9.5px] text-ink" title={j.target}>
                      {j.target.replace(/^https?:\/\//, "")}
                    </p>
                    <p className="font-mono text-[8.5px] text-ink-3">
                      {j.cron} · {MODE_LABEL[j.mode as ScanMode]?.split(" ")[0] || j.mode}
                    </p>
                  </div>
                  <button
                    onClick={() => remove(j.job_id)}
                    className="shrink-0 rounded-sm border border-edge px-1.5 py-0.5 font-mono text-[8.5px] text-ink-3 hover:text-red"
                    title="删除调度"
                  >
                    DEL
                  </button>
                </div>
              ))}
            </div>
          ) : (
            <p className="font-mono text-[9.5px] text-ink-3">{online ? "暂无定时任务" : "引擎离线"}</p>
          )}

          {/* 新建表单 */}
          <select
            className="h-[26px] rounded-sm border border-edge bg-card px-2 font-mono text-[10px] text-ink outline-none"
            value={CRON_PRESETS.some((p) => p.cron === cron) ? cron : "custom"}
            onChange={(e) => { if (e.target.value !== "custom") setCron(e.target.value); }}
          >
            {CRON_PRESETS.map((p) => (
              <option key={p.cron} value={p.cron}>{p.label}（{p.cron}）</option>
            ))}
            <option value="custom">自定义…</option>
          </select>
          {!CRON_PRESETS.some((p) => p.cron === cron) ? (
            <input
              className="h-[26px] rounded-sm border border-edge bg-card px-2 font-mono text-[10px] text-ink outline-none placeholder:text-ink-3"
              placeholder="cron 5 段式 或 every:秒"
              value={cron}
              onChange={(e) => setCron(e.target.value)}
            />
          ) : null}
          <input
            className="h-[26px] rounded-sm border border-edge bg-card px-2 font-mono text-[10px] text-ink outline-none placeholder:text-ink-3"
            placeholder="目标 http://host:port/"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            spellCheck={false}
          />
          <div className="flex items-center gap-2">
            <select
              className="h-[26px] flex-1 rounded-sm border border-edge bg-card px-2 font-mono text-[10px] text-ink outline-none"
              value={mode}
              onChange={(e) => setMode(e.target.value as ScanMode)}
            >
              {(["u", "p", "m", "l"] as ScanMode[]).map((m) => (
                <option key={m} value={m}>{MODE_LABEL[m]}</option>
              ))}
            </select>
            <button
              onClick={create}
              disabled={busy || !online}
              className="h-[26px] rounded-sm bg-accent px-3 font-mono text-[10px] font-semibold text-btntext disabled:opacity-50"
            >
              {busy ? "…" : "添加调度"}
            </button>
          </div>
          {err ? <p className="font-mono text-[9px] text-red">{err}</p> : null}
        </div>
      ) : null}
    </div>
  );
}
