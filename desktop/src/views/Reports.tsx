import { useEffect, useMemo, useState } from "react";
import { Topbar } from "../components/Topbar";
import { KpiCard } from "../components/ui";
import { useApp } from "../state/AppCtx";
import { api, MODE_LABEL, type ScanMode, type ScanTask } from "../services/backend";
import { saveReport, revealPath } from "../services/export";
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
  const [busyKey, setBusyKey] = useState("");
  const [toast, setToast] = useState("");
  const [savedPath, setSavedPath] = useState("");
  const [actionErr, setActionErr] = useState("");
  const [preview, setPreview] = useState<ScanTask | null>(null);

  // 终态任务 → 逐个查询可用报告格式
  useEffect(() => {
    if (!online) {
      setRows([]);
      return;
    }
    const finished = tasks.filter(
      (t) => t.status === "done" || t.status === "failed" || t.status === "cancelled" || t.status === "interrupted",
    );
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
      // 有报告的任务 + 有结果但报告缺失的历史任务（可重建），其余不展示
      if (alive) setRows(rs.filter((r) => r.formats.length > 0 || (r.task.result_count || 0) > 0));
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

  const flash = (msg: string) => {
    setToast(msg);
    window.setTimeout(() => setToast((cur) => (cur === msg ? "" : cur)), 4000);
  };

  const save = async (task: ScanTask, fmt: string) => {
    const key = `${task.task_id}:${fmt}`;
    setBusyKey(key);
    setActionErr("");
    setSavedPath("");
    try {
      const path = await saveReport(task.task_id, fmt);
      if (!path) return; // 用户取消保存
      setSavedPath(path);
      flash(`已保存 ${task.task_id.slice(0, 8)} · ${fmt.toUpperCase()} → ${path}`);
    } catch (e) {
      setActionErr(`下载失败：${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setBusyKey("");
    }
  };

  const rebuild = async (task: ScanTask) => {
    setBusyKey(`${task.task_id}:rebuild`);
    setActionErr("");
    try {
      const r = await api.rebuildReport(task.task_id);
      const meta = await api.reportMeta(task.task_id);
      setRows((prev) =>
        prev.map((row) => (row.task.task_id === task.task_id ? { ...row, formats: meta.formats } : row)),
      );
      flash(`已重建 ${r.paths.length} 个报告文件`);
    } catch (e) {
      setActionErr(`重建失败：${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setBusyKey("");
    }
  };

  const donutData = useMemo(() => {
    const total = Math.max(1, kpis.exports);
    return FMT_ALL
      .filter((f) => kpis.fmtTally[f])
      .map((f) => ({ fmt: f, label: FMT_LABEL[f], value: kpis.fmtTally[f], pct: `${Math.round((kpis.fmtTally[f] / total) * 100)}%` }));
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

      {toast ? (
        <div
          className="mx-6 mt-1 flex items-center gap-2 rounded border px-3 py-1.5"
          style={{ borderColor: "var(--c-sem-green-tint)", background: "var(--c-sem-green-tint)" }}
        >
          <span className="min-w-0 flex-1 break-all font-mono text-[10px] text-ink">{toast}</span>
          {savedPath ? (
            <button
              onClick={() => revealPath(savedPath)}
              className="shrink-0 rounded-sm border border-edge bg-card px-1.5 py-0.5 font-mono text-[9px] text-ink-2 hover:bg-cardsoft"
            >
              定位
            </button>
          ) : null}
          <button onClick={() => setToast("")} className="shrink-0 font-mono text-[10px] text-ink-3 hover:text-ink">✕</button>
        </div>
      ) : null}
      {actionErr ? (
        <div className="mx-6 mt-1 rounded border px-3 py-1.5 font-mono text-[10px] text-red" style={{ borderColor: "var(--c-alert-stroke)" }}>
          {actionErr}
        </div>
      ) : null}

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
            <span className="flex w-[350px] gap-1.5 text-[10px] text-ink-3">可下载格式</span>
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
                  <span className="flex w-[350px] flex-wrap items-center gap-1.5">
                    {r.formats.length === 0 ? (
                      <button
                        onClick={() => rebuild(r.task)}
                        disabled={busyKey !== ""}
                        className="rounded-sm border px-2 py-0.5 font-mono text-[9.5px] disabled:opacity-40"
                        style={{ borderColor: "var(--c-sem-amber)", color: "var(--c-sem-amber)" }}
                        title="用持久化的结果明细重新生成该任务的报告"
                      >
                        {busyKey === `${r.task.task_id}:rebuild` ? "重建中…" : "重建报告"}
                      </button>
                    ) : (
                      FMT_ALL.filter((f) => r.formats.includes(f)).map((f) => {
                        const key = `${r.task.task_id}:${f}`;
                        return (
                          <button
                            key={f}
                            onClick={() => save(r.task, f)}
                            disabled={busyKey !== ""}
                            className="rounded-sm border px-2 py-0.5 font-mono text-[9.5px] transition-colors hover:opacity-80 disabled:opacity-40"
                            style={{ borderColor: fmtColor[f], color: fmtColor[f] }}
                            title={`保存 ${FMT_LABEL[f]} 报告到本机`}
                          >
                            {busyKey === key ? "…" : FMT_LABEL[f]}
                          </button>
                        );
                      })
                    )}
                    {r.formats.includes("html") ? (
                      <button
                        onClick={() => setPreview(r.task)}
                        className="rounded-sm border border-edge px-2 py-0.5 font-mono text-[9.5px] text-ink-2 hover:bg-card"
                        title="在应用内预览 HTML 报告"
                      >
                        预览
                      </button>
                    ) : null}
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
                <div key={d.fmt} className="flex flex-col gap-1">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-[10.5px]" style={{ color: fmtColor[d.fmt] || "var(--c-text-secondary)" }}>
                      {d.label}
                    </span>
                    <span className="font-mono text-[11px] text-ink">{d.value} · {d.pct}</span>
                  </div>
                  <div className="h-[6px] overflow-hidden rounded-full" style={{ background: "var(--c-zebra)" }}>
                    <div
                      className="h-full rounded-full"
                      style={{ width: d.pct, background: fmtColor[d.fmt] || "var(--c-accent-primary)" }}
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

      {preview ? <ReportPreview task={preview} onClose={() => setPreview(null)} /> : null}
    </div>
  );
}

/** 应用内 HTML 报告预览：iframe 指向引擎的 inline 下载端点（sandbox 隔离脚本） */
function ReportPreview({ task, onClose }: { task: ScanTask; onClose: () => void }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div className="absolute inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/60" onClick={onClose} />
      <div
        className="relative flex h-[86%] w-[86%] flex-col overflow-hidden rounded-lg border shadow-2xl"
        style={{ borderColor: "var(--c-border)", background: "var(--c-bg-page)" }}
      >
        <div className="flex items-center justify-between border-b px-4 py-2.5" style={{ borderColor: "var(--c-border)" }}>
          <span className="font-mono text-[11px] text-ink">
            报告预览 · {task.task_id} · {task.target}
          </span>
          <button onClick={onClose} className="font-mono text-[12px] text-ink-3 hover:text-ink">✕</button>
        </div>
        <iframe
          title="扫描报告预览"
          src={api.reportPreviewUrl(task.task_id)}
          sandbox="allow-scripts"
          className="h-full w-full flex-1 border-0 bg-white"
        />
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
