import { useMemo, useState } from "react";
import { Topbar } from "../components/Topbar";
import { KpiCard } from "../components/ui";
import { useApp } from "../state/AppCtx";
import { api, MODE_LABEL, type ScanMode, type ScanTask } from "../services/backend";

interface AssetRow {
  target: string;
  scans: number;
  lastScanAt: number;
  lastStatus: string;
  cms: string;
  waf: string;
  lastTaskId: string;
}

const statusLabel: Record<string, string> = {
  done: "DONE",
  failed: "FAILED",
  cancelled: "STOPPED",
  running: "RUNNING",
  pending: "QUEUED",
};

function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

export function Assets() {
  const { tasks, online, setView, selectTask } = useApp();
  const [groupMode, setGroupMode] = useState<"host" | "status" | "cms">("host");
  const [selectedGroup, setSelectedGroup] = useState<string>("all");

  // 按目标聚合任务历史 → 资产清单
  const assets = useMemo<AssetRow[]>(() => {
    const map = new Map<string, AssetRow>();
    for (const t of tasks) {
      const host = hostOf(t.target);
      const key = t.target.replace(/\/+$/, "");
      const prev = map.get(key);
      const cms = t.fingerprint?.cms ? `${t.fingerprint.cms}${t.fingerprint.version ? " " + t.fingerprint.version : ""}` : "";
      if (!prev) {
        map.set(key, {
          target: key,
          scans: 1,
          lastScanAt: t.started_at,
          lastStatus: t.status,
          cms,
          waf: "",
          lastTaskId: t.task_id,
        });
      } else {
        prev.scans += 1;
        if (t.started_at > prev.lastScanAt) {
          prev.lastScanAt = t.started_at;
          prev.lastStatus = t.status;
          prev.cms = cms || prev.cms;
          prev.lastTaskId = t.task_id;
        }
      }
    }
    return [...map.values()].sort((a, b) => b.lastScanAt - a.lastScanAt);
  }, [tasks]);

  // 分组
  const groups = useMemo(() => {
    const tally = new Map<string, number>();
    for (const a of assets) {
      const key =
        groupMode === "host" ? hostOf(a.target)
          : groupMode === "status" ? statusLabel[a.lastStatus] || a.lastStatus
            : a.cms || "未识别";
      tally.set(key, (tally.get(key) || 0) + 1);
    }
    const list = [...tally.entries()].sort((a, b) => b[1] - a[1]);
    return [{ key: "all", label: "全部资产", count: assets.length }, ...list.map(([key, count]) => ({ key, label: key, count }))];
  }, [assets, groupMode]);

  const visible = useMemo(() => {
    if (selectedGroup === "all") return assets;
    return assets.filter((a) => {
      if (groupMode === "host") return hostOf(a.target) === selectedGroup;
      if (groupMode === "status") return (statusLabel[a.lastStatus] || a.lastStatus) === selectedGroup;
      return (a.cms || "未识别") === selectedGroup;
    });
  }, [assets, selectedGroup, groupMode]);

  const kpis = useMemo(() => {
    const hosts = new Set(assets.map((a) => hostOf(a.target))).size;
    const identified = assets.filter((a) => a.cms).length;
    const confirmedTasks = tasks.reduce((s, t) => s + (t.confirmed_count || 0), 0);
    return { hosts, assets: assets.length, identified, confirmedTasks };
  }, [assets, tasks]);

  const fmtTime = (ts: number) => {
    if (!ts) return "—";
    const d = new Date(ts * 1000);
    const p = (n: number) => String(n).padStart(2, "0");
    return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
  };

  const openTask = (a: AssetRow) => {
    selectTask(a.lastTaskId);
    setView("livescan");
  };

  const rescan = async (a: AssetRow) => {
    try {
      const r = await api.submitScan({ target: a.target, mode: "u", threads: 8, timeout: 10, report_format: "json,html,csv" });
      selectTask(r.task_id);
      setView("livescan");
    } catch {
      /* 后端异常静默，任务页可见 */
    }
  };

  return (
    <div className="flex h-full flex-col">
      <Topbar
        title="资产管理 · ASSETS"
        sub={online ? `${kpis.assets} TARGETS · ${kpis.hosts} HOSTS · AGGREGATED FROM SCAN HISTORY` : "ENGINE OFFLINE"}
        right={
          <div className="flex items-center gap-1 rounded border border-edge bg-cardsoft p-1">
            {([["host", "按主机"], ["status", "按状态"], ["cms", "按指纹"]] as const).map(([k, label]) => (
              <button
                key={k}
                onClick={() => { setGroupMode(k); setSelectedGroup("all"); }}
                className={`h-[26px] rounded px-2.5 text-[10.5px] transition-colors ${
                  groupMode === k ? "bg-accent text-btntext" : "text-ink-2 hover:bg-card"
                }`}
              >
                {label}
              </button>
            ))}
          </div>
        }
      />

      <div className="flex gap-3.5 px-6 pt-1">
        <KpiCard en="TARGETS" value={String(kpis.assets)} delta="FROM TASKS" up={null} tone="green" zh="历史扫描目标" />
        <KpiCard en="HOSTS" value={String(kpis.hosts)} delta="UNIQUE" up={null} tone="accent" zh="去重主机数" />
        <KpiCard en="IDENTIFIED" value={String(kpis.identified)} delta={`${assets.length ? Math.round((kpis.identified / assets.length) * 100) : 0}% RATE`} up={null} tone="purple" zh="已识别指纹" />
        <KpiCard en="CONFIRMED" value={String(kpis.confirmedTasks)} delta="ALL TASKS" up={kpis.confirmedTasks > 0} tone="red" zh="累计确认漏洞" alert={kpis.confirmedTasks > 0} />
      </div>

      {/* 分组树 + 资产表 */}
      <div className="flex min-h-0 flex-1 gap-3.5 px-6 pb-5 pt-4">
        <aside className="thin-scroll flex w-[220px] shrink-0 flex-col overflow-auto rounded border bg-card p-3" style={{ borderColor: "var(--c-border)" }}>
          <h2 className="px-1 pb-2 text-[12px] font-semibold text-ink">资产分组 / GROUPS</h2>
          {groups.map((g) => (
            <button
              key={g.key}
              onClick={() => setSelectedGroup(g.key)}
              className={`flex cursor-pointer items-center justify-between rounded p-2 px-2.5 text-left transition-colors ${
                selectedGroup === g.key ? "bg-activetab" : "hover:bg-cardsoft"
              }`}
            >
              <span className={`truncate text-[12px] ${selectedGroup === g.key ? "text-ink" : "text-ink-2"}`} title={g.label}>
                {g.label}
              </span>
              <span className={`ml-2 shrink-0 font-mono text-[10px] ${selectedGroup === g.key ? "text-navnum" : "text-ink-3"}`}>{g.count}</span>
            </button>
          ))}
          {assets.length === 0 ? <p className="px-1 pt-2 font-mono text-[10px] text-ink-3">暂无数据</p> : null}
        </aside>

        <section className="flex min-h-0 flex-1 flex-col overflow-hidden rounded border bg-card" style={{ borderColor: "var(--c-border)" }}>
          <div className="flex items-center justify-between px-3.5 py-3">
            <h2 className="text-[12px] font-semibold text-ink">资产清单 / ASSET INVENTORY</h2>
            <span className="font-mono text-[10px] text-ink-3">{visible.length} ROWS</span>
          </div>
          <div className="flex items-center gap-2 bg-cardsoft px-3.5 py-1.5">
            <span className="flex-1 text-[10px] text-ink-3">目标地址</span>
            <span className="w-[64px] text-[10px] text-ink-3">次数</span>
            <span className="w-[170px] text-[10px] text-ink-3">框架指纹</span>
            <span className="w-[80px] text-[10px] text-ink-3">最近状态</span>
            <span className="w-[100px] text-[10px] text-ink-3">最近扫描</span>
            <span className="w-[128px] text-[10px] text-ink-3">操作</span>
          </div>
          <div className="thin-scroll min-h-0 flex-1 overflow-auto">
            {visible.length === 0 ? (
              <div className="flex h-full items-center justify-center">
                <span className="font-mono text-[11px] text-ink-3">
                  {online ? "暂无资产 —— 完成一次扫描后自动从任务历史聚合" : "引擎离线"}
                </span>
              </div>
            ) : (
              visible.map((a, i) => (
                <div key={a.target} className={`flex items-center gap-2 px-3.5 py-2 hover:bg-cardsoft ${i % 2 === 1 ? "bg-zebra" : ""}`}>
                  <span className="flex-1 truncate font-mono text-[11px] text-ink" title={a.target}>{a.target}</span>
                  <span className="w-[64px] font-mono text-[10.5px] text-ink-2">{a.scans}</span>
                  <span className="w-[170px] truncate text-[10.5px] text-ink-2">{a.cms || "—"}</span>
                  <span
                    className="w-[80px] font-mono text-[9.5px]"
                    style={{
                      color:
                        a.lastStatus === "done" ? "var(--c-sem-green)"
                          : a.lastStatus === "failed" ? "var(--c-sem-red)"
                            : a.lastStatus === "running" || a.lastStatus === "pending" ? "var(--c-accent-primary)"
                              : "var(--c-text-muted)",
                    }}
                  >
                    {statusLabel[a.lastStatus] || a.lastStatus}
                  </span>
                  <span className="w-[100px] font-mono text-[10.5px] text-ink-3">{fmtTime(a.lastScanAt)}</span>
                  <span className="flex w-[128px] gap-1.5">
                    <button
                      onClick={() => openTask(a)}
                      className="rounded-sm border border-edge px-1.5 py-0.5 font-mono text-[9px] text-ink-2 hover:bg-cardsoft"
                    >
                      查看
                    </button>
                    <button
                      onClick={() => rescan(a)}
                      disabled={!online}
                      className="rounded-sm border px-1.5 py-0.5 font-mono text-[9px] disabled:opacity-40"
                      style={{ borderColor: "var(--c-accent-primary)", color: "var(--c-accent-primary)" }}
                    >
                      重扫
                    </button>
                  </span>
                </div>
              ))
            )}
          </div>
        </section>
      </div>
    </div>
  );
}
