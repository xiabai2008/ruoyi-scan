import { useEffect, useMemo, useState } from "react";
import { KpiCard, SeverityText, VerdictChip } from "../components/ui";
import { Topbar } from "../components/Topbar";
import { MixDonut, TrendChart } from "../components/charts";
import { PlusIcon } from "../components/icons";
import { useApp } from "../state/AppCtx";
import { api, fmtClock, sevToUi, type ScanResultItem, type ScanTask, type Verdict } from "../services/backend";
import type { Severity, Verdict as MockVerdict } from "../data/mock";

const todayStr = () => {
  const d = new Date();
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
};

export function Overview() {
  const { tasks, online, engine, openDialog, apiBase } = useApp();
  const [pluginCount, setPluginCount] = useState<number | null>(null);

  useEffect(() => {
    if (!online) {
      setPluginCount(null);
      return;
    }
    let alive = true;
    api.listPlugins().then((p) => { if (alive) setPluginCount(p.length); }).catch(() => { /* ignore */ });
    return () => { alive = false; };
  }, [online]);

  /* KPI：全部由任务列表聚合 */
  const kpis = useMemo(() => {
    const targets = new Set(tasks.map((t) => t.target.replace(/\/+$/, ""))).size;
    const today = tasks.filter((t) => {
      const d = new Date(t.started_at * 1000);
      const dd = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
      return dd === todayStr();
    }).length;
    const confirmed = tasks.reduce((s, t) => s + (t.confirmed_count || 0), 0);
    const unknown = tasks.reduce((s, t) => s + (t.result_count || 0) - (t.confirmed_count || 0), 0);
    const safe = tasks.reduce((s, t) => s + (t.result_count || 0), 0) - confirmed - unknown;
    return {
      targets,
      today,
      confirmed,
      findings: tasks.reduce((s, t) => s + (t.result_count || 0), 0),
      verdictMix: [
        { label: "CONFIRMED 已确认", value: confirmed, pct: "" },
        { label: "SAFE 安全", value: Math.max(0, safe), pct: "" },
        { label: "UNKNOWN 待定", value: Math.max(0, unknown), pct: "" },
      ],
    };
  }, [tasks]);

  const latest: ScanTask | null = useMemo(
    () => tasks.find((t) => t.status === "done" || t.status === "running") ?? null,
    [tasks],
  );

  return (
    <div className="flex h-full flex-col">
      <Topbar
        title="总览 · OVERVIEW"
        sub={
          online
            ? `ENGINE v${engine?.version ?? "?"} · ${tasks.length} TASKS · LAST ${latest ? latest.task_id.slice(0, 8) : "—"}`
            : `ENGINE OFFLINE · ${apiBase}`
        }
        right={
          <>
            <div className="flex h-[34px] w-[220px] items-center gap-2 rounded border border-edge bg-cardsoft px-3">
              <input
                placeholder="搜索目标 / POC"
                className="w-full bg-transparent text-[11px] text-ink outline-none placeholder:text-ink-3"
              />
            </div>
            <button
              onClick={openDialog}
              className="flex h-[34px] items-center gap-1.5 rounded-sm bg-accent px-3.5 text-[12px] font-semibold text-btntext"
            >
              <PlusIcon /> 新建扫描
            </button>
          </>
        }
      />

      {/* KPI 行 */}
      <div className="flex gap-3.5 px-6 pt-1">
        <KpiCard en="TARGETS" value={String(kpis.targets)} delta={online ? "DB: TASKS" : "OFFLINE"} up={online} tone="green" zh="历史扫描目标" />
        <KpiCard en="SCANS TODAY" value={String(kpis.today)} delta={online ? "+ TODAY" : "—"} up={online} tone="accent" zh="今日任务" />
        <KpiCard en="CONFIRMED" value={String(kpis.confirmed)} delta={`${kpis.findings} FINDINGS`} up={kpis.confirmed > 0} tone="red" zh="已确认漏洞" alert={kpis.confirmed > 0} />
        <KpiCard en="PLUGINS" value={pluginCount !== null ? String(pluginCount) : "—"} delta={pluginCount !== null ? "4 PACKAGES" : online ? "LOADING…" : "OFFLINE"} up={null} tone="purple" zh="内置 POC" />
      </div>

      {/* 图表行 */}
      <div className="flex gap-3.5 px-6 pt-4" style={{ height: 268 }}>
        <div className="flex min-w-0 flex-1 flex-col gap-2.5 rounded border bg-card p-3.5" style={{ borderColor: "var(--c-border)" }}>
          <div className="flex items-center justify-between">
            <h2 className="text-[12px] font-semibold text-ink">任务分布 / TASK MIX</h2>
            <div className="flex items-center gap-3.5">
              <span className="flex items-center gap-1.5 text-[10px] text-ink-2">
                <i className="h-1.5 w-1.5 rounded-full bg-accent" />运行/待运行
              </span>
              <span className="flex items-center gap-1.5 text-[10px] text-ink-2">
                <i className="h-1.5 w-1.5 rounded-full bg-accent2" />已完成
              </span>
            </div>
          </div>
          <div className="min-h-0 flex-1">
            <TrendChart
              theme="bluewhite"
              dates={trendDates(tasks)}
              found={taskTrend(tasks, "running")}
              total={taskTrend(tasks, "done")}
              foundLabel="RUN"
              totalLabel="DONE"
            />
          </div>
        </div>

        <div className="flex w-[360px] shrink-0 flex-col gap-2.5 rounded border bg-card p-3.5" style={{ borderColor: "var(--c-border)" }}>
          <h2 className="text-[12px] font-semibold text-ink">三态判定 / VERDICT MIX</h2>
          <div className="flex min-h-0 flex-1 items-center gap-4">
            <div className="h-full w-[170px] shrink-0">
              <MixDonut theme="bluewhite" data={verdictMixToChart(kpis.verdictMix)} centerValue={String(kpis.findings)} centerLabel="FINDINGS" />
            </div>
            <div className="flex min-w-0 flex-1 flex-col gap-2">
              {kpis.verdictMix.map((v) => (
                <div key={v.label} className="flex flex-col gap-1">
                  <div className="flex items-center justify-between">
                    <span className="text-[10.5px] text-ink-2">{v.label}</span>
                    <span className="font-mono text-[11px] text-ink">{v.value}</span>
                  </div>
                  <div className="h-[6px] overflow-hidden rounded-full bg-cardsoft" style={{ background: "var(--c-zebra)" }}>
                    <div
                      className="h-full rounded-full"
                      style={{
                        width: kpis.findings ? `${Math.max(4, (v.value / Math.max(1, kpis.findings)) * 100)}%` : "0%",
                        background:
                          v.label.startsWith("CONFIRMED") ? "var(--c-sem-red)"
                            : v.label.startsWith("SAFE") ? "var(--c-sem-green)"
                              : "var(--c-sem-amber)",
                      }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      <RecentFindings tasks={tasks} online={online} />
    </div>
  );
}

function RecentFindings({ tasks, online }: { tasks: ScanTask[]; online: boolean }) {
  const [rows, setRows] = useState<{ sev: Severity; name: string; tag: string; verdict: MockVerdict; time: string; url: string }[]>([]);

  useEffect(() => {
    if (!online) {
      setRows([]);
      return;
    }
    let alive = true;
    // 最多聚合最近 3 个有结果的终态任务
    const candidates = tasks.filter((t) => t.status === "done" && (t.result_count || 0) > 0).slice(0, 3);
    Promise.all(
      candidates.map(async (t) => {
        let items: ScanResultItem[] = [];
        try {
          items = await api.taskResults(t.task_id);
        } catch {
          items = [];
        }
        return { t, items };
      }),
    ).then((groups) => {
      if (!alive) return;
      const all = groups
        .flatMap(({ t, items }) =>
          items.map((r) => ({
            sev: sevToUi(r.severity) as Severity,
            name: r.name || "(unnamed)",
            tag: r.url ? hostOf(r.url) : t.mode + ":" + t.task_id.slice(0, 4),
            verdict: (["CONFIRMED", "SAFE", "UNKNOWN"].includes(r.status) ? r.status : "UNKNOWN") as MockVerdict,
            time: t.finished_at ? fmtClock(t.finished_at) : "",
            url: r.url,
          })),
        )
        .slice(-12)
        .reverse();
      setRows(all);
    });
    return () => { alive = false; };
  }, [tasks, online]);

  return (
    <div className="flex min-h-0 flex-1 flex-col px-6 pb-5 pt-4">
      <section className="flex min-h-0 flex-1 flex-col overflow-hidden rounded border bg-card" style={{ borderColor: "var(--c-border)" }}>
        <div className="flex items-center justify-between px-3.5 py-3">
          <h2 className="text-[12px] font-semibold text-ink">最新发现 / RECENT FINDINGS</h2>
          <span className="font-mono text-[10px] text-ink-3">{rows.length > 0 ? `${rows.length} ROWS` : online ? "无结果" : "后端离线"}</span>
        </div>
        <div className="flex items-center gap-2 bg-cardsoft px-3.5 py-1.5">
          {["严重度", "漏洞名称", "触发 URL / 任务", "三态判定", "时间"].map((h, i) => (
            <span key={h} className={i === 1 ? "flex-1 text-[10px] text-ink-3" : `${colW[i]} text-[10px] text-ink-3`}>
              {h}
            </span>
          ))}
        </div>
        <div className="thin-scroll min-h-0 flex-1 overflow-auto">
          {rows.length === 0 ? (
            <div className="flex h-full items-center justify-center">
              <span className="font-mono text-[11px] text-ink-3">{online ? "暂无扫描结果 —— 发起一次扫描后这里会实时出现发现项" : "引擎离线 —— 无法加载结果"}</span>
            </div>
          ) : (
            rows.map((f, i) => (
              <div key={`${f.name}-${i}`} className={`flex items-center gap-2 px-3.5 py-2 ${i % 2 === 1 ? "bg-zebra" : ""}`}>
                <span className="w-[84px]"><SeverityText s={f.sev} /></span>
                <span className="flex-1 truncate text-[11.5px] text-ink" title={f.url || f.name}>{f.name}</span>
                <span className="w-[200px] truncate font-mono text-[10.5px] text-ink-2">{f.tag}</span>
                <span className="w-[108px]"><VerdictChip v={f.verdict} /></span>
                <span className="w-[96px] font-mono text-[10.5px] text-ink-3">{f.time}</span>
              </div>
            ))
          )}
        </div>
      </section>
    </div>
  );
}

/* ---------- 图表辅助（空数据时输出静态演示波形，避免 ECharts 空白突兀） ---------- */
function trendDates(tasks: ScanTask[]) {
  const now = new Date();
  return Array.from({ length: 7 }, (_, i) => {
    const d = new Date(now.getTime() - (6 - i) * 86400000);
    return `${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
  });
}

function taskTrend(tasks: ScanTask[], wanted: "running" | "done") {
  const now = Date.now();
  const out: number[] = [];
  for (let i = 6; i >= 0; i--) {
    const from = now - (i + 1) * 86400000;
    const to = now - i * 86400000;
    out.push(tasks.filter((t) => {
      const s = t.started_at * 1000;
      const match = wanted === "running" ? (t.status === "running" || t.status === "pending") : t.status === "done";
      return match && s >= from && s < to;
    }).length);
  }
  // 数据不足时叠加演示基线，保证图表可读
  return out.map((n, i) => n + (tasks.length > 0 ? 0 : [2, 3, 2, 5, 4, 6, 3][i] || 0));
}

function verdictMixToChart(mix: { label: string; value: number; pct: string }[]) {
  return mix.map((m) => ({ label: m.label, value: m.value, pct: m.value ? `${Math.round((m.value / Math.max(1, mix.reduce((s, x) => s + x.value, 0))) * 100)}%` : "0%" }));
}

function hostOf(url: string) {
  try {
    return new URL(url).host;
  } catch {
    return url.length > 40 ? url.slice(0, 40) + "…" : url;
  }
}

const colW: Record<number, string> = { 0: "w-[84px]", 2: "w-[200px]", 3: "w-[108px]", 4: "w-[96px]" };
