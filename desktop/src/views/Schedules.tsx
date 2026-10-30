import { useCallback, useEffect, useState } from "react";
import { Topbar } from "../components/Topbar";
import { useApp } from "../state/AppCtx";
import {
  api, MODE_LABEL, TASK_STATUS_COLOR, TASK_STATUS_LABEL,
  type ScheduleJob, type ScanMode,
} from "../services/backend";
import { validateTarget } from "../services/target";

const POLL_MS = 10_000;

const CRON_PRESETS = [
  { label: "每 5 分钟", cron: "*/5 * * * *" },
  { label: "每 30 分钟", cron: "*/30 * * * *" },
  { label: "每小时", cron: "0 * * * *" },
  { label: "每天 09:00", cron: "0 9 * * *" },
  { label: "每 10 分钟", cron: "every:600" },
];

const inputCls =
  "h-[32px] w-full rounded-sm border border-edge bg-cardsoft px-2.5 font-mono text-[11px] text-ink outline-none placeholder:text-ink-3 focus:border-[var(--c-accent-primary)]";

/**
 * 定时扫描独立页：旧实现在 LiveScan 右侧 300px 窄栏里折叠，展开后表单在
 * 视口外，且删除失败被静默吞掉（测评 P1-8/P2-9）。
 * 页面化后表单、降级警告、暂停原因、删除错误都有完整展示空间。
 */
export function Schedules() {
  const { online } = useApp();
  const [jobs, setJobs] = useState<ScheduleJob[]>([]);
  const [cron, setCron] = useState("*/30 * * * *");
  const [target, setTarget] = useState("");
  const [mode, setMode] = useState<ScanMode>("u");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [notice, setNotice] = useState("");
  const [actionErr, setActionErr] = useState("");
  const [loading, setLoading] = useState(false);

  const load = useCallback(async () => {
    if (!online) {
      setJobs([]);
      return;
    }
    setLoading(true);
    try {
      setJobs(await api.listSchedules());
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [online]);

  useEffect(() => {
    load();
    if (!online) return;
    const t = setInterval(load, POLL_MS);
    return () => clearInterval(t);
  }, [online, load]);

  const create = async () => {
    const check = validateTarget(target);
    if (!check.ok) {
      setErr(check.error);
      return;
    }
    if (!cron.trim()) {
      setErr("调度表达式必填");
      return;
    }
    setBusy(true);
    setErr("");
    setNotice("");
    try {
      const r = await api.createSchedule({ cron: cron.trim(), target: check.url, mode });
      setTarget("");
      if (r.warning || r.degraded) {
        setNotice(r.warning || "当前构建不支持 cron，已降级为每 5 分钟执行");
      } else {
        setNotice(`已创建调度 ${r.job_id}`);
      }
      await load();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const remove = async (jobId: string) => {
    if (!window.confirm(`确认删除调度 ${jobId}？删除后不再自动发起扫描。`)) return;
    setActionErr("");
    try {
      await api.deleteSchedule(jobId);
      await load();
    } catch (e) {
      setActionErr(`删除失败：${e instanceof Error ? e.message : String(e)}`);
    }
  };

  const resume = async (jobId: string) => {
    setActionErr("");
    try {
      await api.resumeSchedule(jobId);
      await load();
    } catch (e) {
      setActionErr(`恢复失败：${e instanceof Error ? e.message : String(e)}`);
    }
  };

  const fmtTs = (ts?: number) => {
    if (!ts) return "—";
    const d = new Date(ts * 1000);
    const p = (n: number) => String(n).padStart(2, "0");
    return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
  };

  const degradedCount = jobs.filter((j) => j.degraded).length;
  const pausedCount = jobs.filter((j) => j.paused).length;

  return (
    <div className="flex h-full flex-col">
      <Topbar
        title="定时任务 · SCHEDULES"
        sub={
          online
            ? `${jobs.length} SCHEDULED · ${degradedCount} DEGRADED · ${pausedCount} PAUSED`
            : "ENGINE OFFLINE"
        }
        right={
          <button
            onClick={load}
            className="h-[34px] rounded-sm border border-edge-ghost px-3.5 text-[12px] text-ink-2 hover:bg-cardsoft"
          >
            刷新
          </button>
        }
      />

      <div className="flex min-h-0 flex-1 flex-col gap-3.5 px-6 pb-5 pt-1">
        {/* 创建表单 */}
        <section className="rounded border bg-card p-4" style={{ borderColor: "var(--c-border)" }}>
          <h2 className="pb-2.5 text-[12px] font-semibold text-ink">新建调度 / NEW SCHEDULE</h2>
          {/* 右侧预留 Widgets 浮窗宽度（默认固定在右上角），避免“添加调度”被浮窗遮住 */}
          <div className="grid grid-cols-[200px_1fr_150px_110px] items-end gap-3 pr-[180px]">
            <label className="flex flex-col gap-1">
              <span className="text-[10px] text-ink-2">调度表达式</span>
              <select
                className={inputCls}
                value={CRON_PRESETS.some((p) => p.cron === cron) ? cron : "custom"}
                onChange={(e) => setCron(e.target.value === "custom" ? "" : e.target.value)}
              >
                {CRON_PRESETS.map((p) => (
                  <option key={p.cron} value={p.cron}>{p.label}（{p.cron}）</option>
                ))}
                <option value="custom">自定义…</option>
              </select>
            </label>
            <label className="flex flex-col gap-1">
              <span className="text-[10px] text-ink-2">目标</span>
              <input
                className={inputCls}
                placeholder="https://demo.example.com/"
                value={target}
                onChange={(e) => { setTarget(e.target.value); setErr(""); }}
                spellCheck={false}
              />
            </label>
            <label className="flex flex-col gap-1">
              <span className="text-[10px] text-ink-2">模式</span>
              <select className={inputCls} value={mode} onChange={(e) => setMode(e.target.value as ScanMode)}>
                {(["u", "p", "m", "l"] as ScanMode[]).map((m) => (
                  <option key={m} value={m}>{MODE_LABEL[m]}</option>
                ))}
              </select>
            </label>
            <button
              onClick={create}
              disabled={busy || !online}
              className="h-[32px] rounded-sm bg-accent px-3 text-[11px] font-semibold text-btntext disabled:opacity-50"
            >
              {busy ? "提交中…" : "添加调度"}
            </button>
          </div>
          {!CRON_PRESETS.some((p) => p.cron === cron) ? (
            <input
              className={`${inputCls} mt-2`}
              placeholder="cron 5 段式（*/30 * * * *）或 every:秒"
              value={cron}
              onChange={(e) => setCron(e.target.value)}
              spellCheck={false}
            />
          ) : null}
          {err ? <p className="mt-2 font-mono text-[10px] text-red">{err}</p> : null}
          {notice ? (
            <p className="mt-2 rounded border border-edge bg-cardsoft px-2.5 py-1.5 font-mono text-[10px] text-ink-2">
              {notice}
            </p>
          ) : null}
          <p className="mt-2 text-[9.5px] text-ink-3">
            cron 依赖 APScheduler；当前构建缺失时会降级为每 5 分钟并在下方标注。目标连续 3 次不可达会自动暂停。
          </p>
        </section>

        {actionErr ? (
          <div className="rounded border px-3 py-2 font-mono text-[10.5px] text-red" style={{ borderColor: "var(--c-alert-stroke)" }}>
            {actionErr}
          </div>
        ) : null}

        {/* 任务列表 */}
        <section className="flex min-h-0 flex-1 flex-col overflow-hidden rounded border bg-card" style={{ borderColor: "var(--c-border)" }}>
          <div className="flex items-center justify-between px-3.5 py-3">
            <h2 className="text-[12px] font-semibold text-ink">调度列表 / SCHEDULE LIST</h2>
            <span className="font-mono text-[10px] text-ink-3">{loading ? "LOADING…" : `${jobs.length} JOBS`}</span>
          </div>
          <div className="flex items-center gap-2 bg-cardsoft px-3.5 py-1.5">
            <span className="flex-1 text-[10px] text-ink-3">目标</span>
            <span className="w-[150px] text-[10px] text-ink-3">调度</span>
            <span className="w-[120px] text-[10px] text-ink-3">实际节奏</span>
            <span className="w-[70px] text-[10px] text-ink-3">模式</span>
            <span className="w-[150px] text-[10px] text-ink-3">最近状态</span>
            <span className="w-[100px] text-[10px] text-ink-3">最近触发</span>
            <span className="w-[150px] text-[10px] text-ink-3">操作</span>
          </div>
          <div className="thin-scroll min-h-0 flex-1 overflow-auto">
            {!online ? (
              <Center text="引擎离线 —— 无法加载调度" />
            ) : jobs.length === 0 ? (
              <Center text="暂无定时任务" />
            ) : (
              jobs.map((j, i) => {
                const status = j.paused ? "PAUSED" : j.degraded ? "DEGRADED" : "ACTIVE";
                const statusColor = j.paused
                  ? "var(--c-sem-amber)"
                  : j.degraded
                    ? "var(--c-sem-amber)"
                    : "var(--c-sem-green)";
                return (
                  <div
                    key={j.job_id}
                    className={`flex items-center gap-2 px-3.5 py-2 ${i % 2 === 1 ? "bg-zebra" : ""}`}
                  >
                    <span className="min-w-0 flex-1 truncate font-mono text-[11px] text-ink" title={j.target}>
                      {j.target.replace(/^https?:\/\//, "")}
                    </span>
                    <span className="w-[150px] truncate font-mono text-[10px] text-ink-2">{j.cron}</span>
                    <span className="w-[120px] truncate font-mono text-[10px]" style={{ color: j.degraded ? "var(--c-sem-amber)" : "var(--c-text-secondary)" }}>
                      {j.effective_cron || j.cron}
                    </span>
                    <span className="w-[70px] text-[10px] text-ink-2">{MODE_LABEL[j.mode as ScanMode]?.split(" ")[0] || j.mode}</span>
                    <span className="flex w-[150px] flex-col gap-0.5">
                      <span className="font-mono text-[9px] font-semibold" style={{ color: statusColor }}>{status}</span>
                      {j.last_status ? (
                        <span className="font-mono text-[9px]" style={{ color: TASK_STATUS_COLOR[j.last_status] || "var(--c-text-muted)" }}>
                          {TASK_STATUS_LABEL[j.last_status] || j.last_status}
                        </span>
                      ) : null}
                      {j.paused && j.paused_reason ? (
                        <span className="truncate text-[8.5px] text-ink-3" title={j.paused_reason}>{j.paused_reason}</span>
                      ) : null}
                    </span>
                    <span className="w-[100px] font-mono text-[9.5px] text-ink-3">{fmtTs(j.last_run_at)}</span>
                    <span className="flex w-[150px] gap-1.5">
                      {j.paused ? (
                        <button
                          onClick={() => resume(j.job_id)}
                          className="rounded-sm border px-1.5 py-0.5 font-mono text-[9px]"
                          style={{ borderColor: "var(--c-sem-green)", color: "var(--c-sem-green)" }}
                        >
                          恢复
                        </button>
                      ) : null}
                      <button
                        onClick={() => remove(j.job_id)}
                        className="rounded-sm border border-edge px-1.5 py-0.5 font-mono text-[9px] text-ink-3 hover:text-red"
                      >
                        删除
                      </button>
                    </span>
                  </div>
                );
              })
            )}
          </div>
          {degradedCount > 0 ? (
            <div className="border-t border-edge bg-cardsoft px-3.5 py-2 font-mono text-[9.5px]" style={{ color: "var(--c-sem-amber)" }}>
              {degradedCount} 个 cron 任务已降级为每 5 分钟：当前构建未包含 APScheduler。
            </div>
          ) : null}
        </section>
      </div>
    </div>
  );
}

function Center({ text }: { text: string }) {
  return (
    <div className="flex h-full items-center justify-center">
      <span className="font-mono text-[11px] text-ink-3">{text}</span>
    </div>
  );
}
