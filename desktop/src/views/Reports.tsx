import { useEffect, useMemo, useState } from "react";
import { Topbar } from "../components/Topbar";
import { KpiCard } from "../components/ui";
import { useApp } from "../state/AppCtx";
import { api, MODE_LABEL, type ScanMode, type ScanTask } from "../services/backend";
import type { ThemeName } from "../tokens";

const FMT_ALL = ["html", "json", "csv", "pdf", "docx", "xlsx"] as const;

const FMT_LABEL: Record<string, string> = {
  html: "HTML", json: "JSON", csv: "CSV", pdf: "PDF", docx: "WORD", xlsx: "EXCEL",
};

const fmtColor: Record<string, string> = {
  html: "var(--c-accent-primary)",
  json: "var(--c-accent-purple)",
  csv: "var(--c-sem-green)",
  pdf: "var(--c-sem-red)",
  docx: "var(--c-nav-num)",
  xlsx: "var(--c-sem-amber)",
};

interface ReportRow {
  task: ScanTask;
  formats: string[];
  loading: boolean;
}

export function Reports({ theme }: { theme: ThemeName }) {
  const { tasks, online } = useApp();
  const [rows, setRows] = useState<ReportRow[]>([]);
  const [query, setQuery] = useState("");

  // 终态任务 → 逐个查询可用报告格式
  useEffect(() => {
    if (!online) {
      setRows([]);
      return;
    }
    const finished = tasks.filter((t) => t.status === "done" || t.status === "failed" || t.status === "cancelled");
    let alive = true;
    Promise.all(
      finished.map(async (t): Promise<ReportRow> => {
        try {
          const meta = await api.reportMeta(t.task_id);
          return { task: t, formats: meta.formats, loading: false };
        } catch {
          return { task: t, formats: [], loading: false };
        }
      }),
    ).then((rs) => {
      if (alive) setRows(rs.filter((r) => r.formats.length > 0));
    });
    return () => { alive = false; };
  }, [tasks, online]);

  const kpis = useMemo(() => {
    const totalExports = rows.reduce((s, r) => s + r.formats.length, 0);
    const fmtTally: Record<string, number> = {};
    for (const r of rows) for (const f of r.formats) fmtTally[f] = (fmtTally[f] || 0) + 1;
    return {
      reports: rows.length,
      exports: totalExports,
      formats: Object.keys(fmtTally).length,
      fmtTally,
      confirmed: rows.reduce((s, r) => s + (r.task.confirmed_count || 0), 0),
    };
  }, [rows]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return rows;
    return rows.filter((r) => r.task.task_id.toLowerCase().includes(q) || r.task.target.toLowerCase().includes(q));
  }, [rows, query]);

  const donutData = useMemo(() => {
    const total = Math.max(1, kpis.exports);
    return FMT_ALL
      .filter((f) => kpis.fmtTally[f])
      .map((f) => ({ label: FMT_LABEL[f], value: kpis.fmtTally[f], pct: `${Math.round((kpis.fmtTally[f] / total) * 100)}%` }));
  }, [kpis]);

  return (
    <div className="flex h-full flex-col">
      <Topbar
        title="报告中心 · REPORTS"
        sub={online ? `${kpis.reports} REPORTS · ${kpis.exports} EXPORTS · LIVE FROM TASK HISTORY` : "ENGINE OFFLINE"}
        right={
          <div className="flex h-[34px] w-[220px] items-center gap-2 rounded border border-edge bg-cardsoft px-3">
            <input
              placeholder="搜索任务 ID / 目标"
              className="w-full bg-transparent text-[11px] text-ink outline-none placeholder:text-ink-3"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
          </div>
        }
      />

      <div className="flex gap-3.5 px-6 pt-1">
        <KpiCard en="REPORTS" value={String(kpis.reports)} delta={online ? "FROM TASKS" : "OFFLINE"} up={null} tone="accent" zh="可下载报告的任务" />
        <KpiCard en="EXPORTS" value={String(kpis.exports)} delta={`${kpis.formats} FORMATS`} up={null} tone="green" zh="全格式导出总数" />
        <KpiCard en="CONFIRMED" value={String(kpis.confirmed)} delta="IN REPORTED TASKS" up={kpis.confirmed > 0} tone="red" zh="报告内已确认漏洞" alert={kpis.confirmed > 0} />
      </div>

      <div className="flex min-h-0 flex-1 gap-3.5 px-6 pb-5 pt-4">
        {/* 报告列表 */}
        <section className="flex min-h-0 flex-1 flex-col overflow-hidden rounded border bg-card" style={{ borderColor: "var(--c-border)" }}>
          <div className="flex items-center justify-between px-3.5 py-3">
            <h2 className="text-[12px] font-semibold text-ink">报告列表 / REPORT LIST</h2>
            <span className="font-mono text-[10px] text-ink-3">SOURCE: task.report_paths + /api/report</span>
          </div>
          <div className="flex items-center gap-2 bg-cardsoft px-3.5 py-1.5">
            <span className="w-[86px] text-[10px] text-ink-3">任务</span>
            <span className="flex-1 text-[10px] text-ink-3">目标</span>
            <span className="w-[110px] text-[10px] text-ink-3">模式</span>
            <span className="flex w-[300px] gap-1.5 text-[10px] text-ink-3">可下载格式</span>
          </div>
          <div className="thin-scroll min-h-0 flex-1 overflow-auto">
            {!online ? (
              <Center text="引擎离线 —— 无法加载报告" />
            ) : rows.length === 0 ? (
              <Center text="暂无报告 —— 完成一次扫描后任务会出现在这里" />
            ) : (
              filtered.map((r, i) => (
                <div key={r.task.task_id} className={`flex items-center gap-2 px-3.5 py-2.5 hover:bg-cardsoft ${i % 2 === 1 ? "bg-zebra" : ""}`}>
                  <span className="w-[86px] font-mono text-[10.5px] text-ink">{r.task.task_id.slice(0, 8)}</span>
                  <span className="flex-1 truncate font-mono text-[11px] text-ink-2" title={r.task.target}>
                    {r.task.target.replace(/^https?:\/\//, "")}
                  </span>
                  <span className="w-[110px] text-[10.5px] text-ink-2">{MODE_LABEL[r.task.mode as ScanMode]?.split(" ")[0] || r.task.mode}</span>
                  <span className="flex w-[300px] gap-1.5">
                    {FMT_ALL.filter((f) => r.formats.includes(f)).map((f) => (
                      <a
                        key={f}
                        href={api.reportDownloadUrl(r.task.task_id, f)}
                        target="_blank"
                        rel="noreferrer"
                        className="rounded-sm border px-2 py-0.5 font-mono text-[9.5px] transition-colors hover:opacity-80"
                        style={{ borderColor: fmtColor[f], color: fmtColor[f] }}
                        title={`下载 ${FMT_LABEL[f]} 报告`}
                      >
                        {FMT_LABEL[f]}
                      </a>
                    ))}
                  </span>
                </div>
              ))
            )}
          </div>
        </section>

        {/* 格式分布 */}
        <aside className="flex w-[300px] shrink-0 flex-col gap-2.5 rounded border bg-card p-3.5" style={{ borderColor: "var(--c-border)" }}>
          <h2 className="text-[12px] font-semibold text-ink">导出格式 / FORMATS</h2>
          <div className="flex flex-col gap-2.5">
            {donutData.length === 0 ? (
              <span className="font-mono text-[10px] text-ink-3">暂无数据</span>
            ) : (
              donutData.map((d) => (
                <div key={d.label} className="flex flex-col gap-1">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-[10.5px]" style={{ color: fmtColor[d.label.toLowerCase()] || "var(--c-text-secondary)" }}>
                      {d.label}
                    </span>
                    <span className="font-mono text-[11px] text-ink">{d.value} · {d.pct}</span>
                  </div>
                  <div className="h-[6px] overflow-hidden rounded-full" style={{ background: "var(--c-zebra)" }}>
                    <div
                      className="h-full rounded-full"
                      style={{ width: d.pct, background: fmtColor[d.label.toLowerCase()] || "var(--c-accent-primary)" }}
                    />
                  </div>
                </div>
              ))
            )}
          </div>
          <div className="mt-auto border-t pt-2.5" style={{ borderColor: "var(--c-border)" }}>
            <p className="text-[10px] leading-[15px] text-ink-3">
              报告由引擎在扫描完成时自动生成（默认 json/html/csv）。PDF/DOCX/XLSX 需后端安装 reportlab / python-docx / openpyxl。
            </p>
          </div>
        </aside>
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
