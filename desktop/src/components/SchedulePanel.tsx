import { useEffect, useState } from "react";
import { api, type ScheduleJob } from "../services/backend";
import { useApp } from "../state/AppCtx";

/**
 * LiveScan 右栏的定时任务摘要卡。
 *
 * 旧实现在 300px 窄栏里做“列表 + 新建表单”的折叠面板：展开后表单落在视口外，
 * 用户只看到 ▲ 变了；删除失败还被静默吞掉。现在完整管理能力移到独立页面，
 * 这里只保留状态摘要与入口。
 */
export function SchedulePanel() {
  const { online, setView } = useApp();
  const [jobs, setJobs] = useState<ScheduleJob[]>([]);

  useEffect(() => {
    if (!online) {
      setJobs([]);
      return;
    }
    let alive = true;
    const load = () =>
      api.listSchedules()
        .then((list) => { if (alive) setJobs(list); })
        .catch(() => { if (alive) setJobs([]); });
    load();
    const t = setInterval(load, 15_000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, [online]);

  const degraded = jobs.filter((j) => j.degraded).length;
  const paused = jobs.filter((j) => j.paused).length;

  return (
    <button
      onClick={() => setView("schedules")}
      className="flex w-full flex-col gap-1.5 rounded-lg border border-edge-soft bg-cardsoft p-3 text-left transition-colors hover:bg-card"
      title="打开定时任务管理页"
    >
      <span className="flex items-center justify-between">
        <span className="font-mono text-[8px] tracking-wider text-ink-3">SCHEDULED SCANS</span>
        <span className="font-mono text-[9px] text-accent">管理 →</span>
      </span>
      <span className="flex items-baseline gap-2">
        <span className="font-mono text-[20px] font-semibold text-ink">{jobs.length}</span>
        <span className="text-[10px] text-ink-2">个定时任务</span>
      </span>
      {!online ? (
        <span className="font-mono text-[9px] text-ink-3">引擎离线</span>
      ) : degraded > 0 || paused > 0 ? (
        <span className="font-mono text-[9px]" style={{ color: "var(--c-sem-amber)" }}>
          {degraded > 0 ? `${degraded} 个降级` : ""}
          {degraded > 0 && paused > 0 ? " · " : ""}
          {paused > 0 ? `${paused} 个已暂停` : ""}
        </span>
      ) : (
        <span className="font-mono text-[9px] text-ink-3">全部按计划执行</span>
      )}
    </button>
  );
}
