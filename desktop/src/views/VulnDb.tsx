import { useEffect, useMemo, useState } from "react";
import { Topbar } from "../components/Topbar";
import { SearchIcon, PlusIcon } from "../components/icons";
import { SeverityText } from "../components/ui";
import { useApp } from "../state/AppCtx";
import { api, sevToUi, type PluginMeta } from "../services/backend";

const SEV_ORDER: Record<string, number> = { high: 0, medium: 1, low: 2 };

const VULN_TYPE_LABEL: Record<string, string> = {
  brute: "爆破",
  recon: "信息收集",
  vuln: "漏洞利用",
};

export function VulnDb() {
  const { online, openDialog, setView } = useApp();
  const [plugins, setPlugins] = useState<PluginMeta[]>([]);
  const [loading, setLoading] = useState(false);
  const [query, setQuery] = useState("");
  const [sevFilter, setSevFilter] = useState("all");
  const [detail, setDetail] = useState<PluginMeta | null>(null);

  useEffect(() => {
    if (!online) return;
    setLoading(true);
    api.listPlugins()
      .then((list) => setPlugins([...list].sort((a, b) => (SEV_ORDER[a.severity] ?? 3) - (SEV_ORDER[b.severity] ?? 3) || a.name.localeCompare(b.name))))
      .catch(() => setPlugins([]))
      .finally(() => setLoading(false));
  }, [online]);

  const counts = useMemo(() => ({
    all: plugins.length,
    high: plugins.filter((p) => p.severity === "high").length,
    medium: plugins.filter((p) => p.severity === "medium").length,
    low: plugins.filter((p) => p.severity === "low").length,
    waf: plugins.filter((p) => p.supports_waf_bypass).length,
    cve: plugins.filter((p) => p.cve).length,
  }), [plugins]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return plugins.filter((p) => {
      if (sevFilter === "waf") {
        if (!p.supports_waf_bypass) return false;
      } else if (sevFilter === "cve") {
        if (!p.cve) return false;
      } else if (sevFilter !== "all" && p.severity !== sevFilter) {
        return false;
      }
      if (!q) return true;
      return [p.name, p.description, p.cve, p.vuln_type, p.category, p.affected_versions]
        .some((f) => (f || "").toLowerCase().includes(q));
    });
  }, [plugins, query, sevFilter]);

  const filters: { key: string; label: string; count: number }[] = [
    { key: "all", label: "全部", count: counts.all },
    { key: "high", label: "HIGH", count: counts.high },
    { key: "medium", label: "MED", count: counts.medium },
    { key: "low", label: "LOW", count: counts.low },
    { key: "waf", label: "WAF 绕过", count: counts.waf },
    { key: "cve", label: "CVE", count: counts.cve },
  ];

  return (
    <div className="flex h-full flex-col">
      <Topbar
        title="漏洞库 · VULN DB"
        sub={online ? `${counts.all} POC LOADED · ${counts.cve} CVE · LIVE FROM ENGINE` : "ENGINE OFFLINE"}
        right={
          <>
            <div className="flex h-[34px] w-[240px] items-center gap-2 rounded border border-edge bg-cardsoft px-3">
              <SearchIcon />
              <input
                placeholder="搜索 POC / CVE / 漏洞类型"
                className="w-full bg-transparent text-[11px] text-ink outline-none placeholder:text-ink-3"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
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

      {/* 筛选 chips */}
      <div className="flex items-center gap-2 px-6">
        {filters.map((f) => (
          <button
            key={f.key}
            onClick={() => setSevFilter(f.key)}
            className={`flex h-[28px] items-center gap-1.5 rounded-sm px-2.5 transition-colors ${
              sevFilter === f.key ? "bg-accent" : "border border-edge bg-cardsoft hover:bg-card"
            }`}
          >
            <span className={`text-[11px] ${sevFilter === f.key ? "text-btntext" : "text-ink-2"}`}>{f.label}</span>
            <span className={`font-mono text-[10px] ${sevFilter === f.key ? "text-btntext" : "text-ink-3"}`}>{f.count}</span>
          </button>
        ))}
        <span className="mx-1 h-4 w-px bg-line" />
        <button
          onClick={() => setView("livescan")}
          className="flex h-[28px] items-center rounded-sm border border-edge bg-cardsoft px-2.5 text-[11px] text-ink-2 hover:bg-card"
        >
          用这些 POC 扫描 →
        </button>
      </div>

      {/* 插件表 */}
      <div className="flex min-h-0 flex-1 flex-col px-6 pb-5 pt-4">
        <section className="flex min-h-0 flex-1 flex-col overflow-hidden rounded border bg-card" style={{ borderColor: "var(--c-border)" }}>
          <div className="flex items-center justify-between px-3.5 py-3">
            <h2 className="text-[12px] font-semibold text-ink">POC 插件库 / PLUGIN LIBRARY</h2>
            <span className="font-mono text-[10px] text-ink-3">
              {loading ? "LOADING…" : `${filtered.length} / ${counts.all} · SORT: SEVERITY`}
            </span>
          </div>
          <div className="flex items-center gap-2 bg-cardsoft px-3.5 py-1.5">
            <span className="w-[64px] text-[10px] text-ink-3">严重度</span>
            <span className="flex-1 text-[10px] text-ink-3">POC 名称</span>
            <span className="w-[150px] text-[10px] text-ink-3">CVE / 类型</span>
            <span className="w-[170px] text-[10px] text-ink-3">影响版本</span>
            <span className="w-[80px] text-[10px] text-ink-3">WAF</span>
          </div>
          <div className="thin-scroll min-h-0 flex-1 overflow-auto">
            {!online ? (
              <Empty text="引擎离线 —— 连接后端后加载插件库" />
            ) : loading ? (
              <Empty text="加载插件元数据中…" />
            ) : filtered.length === 0 ? (
              <Empty text="无匹配插件" />
            ) : (
              filtered.map((p, i) => (
                <div
                  key={p.name}
                  onClick={() => setDetail(p)}
                  className={`flex cursor-pointer items-center gap-2 px-3.5 py-2 hover:bg-cardsoft ${i % 2 === 1 ? "bg-zebra" : ""}`}
                >
                  <span className="w-[64px]"><SeverityText s={sevToUi(p.severity)} /></span>
                  <span className="flex-1 truncate text-[11.5px] text-ink" title={p.description}>{p.name}</span>
                  <span className="w-[150px] truncate font-mono text-[10.5px] text-ink-2">
                    {p.cve ? <span style={{ color: "var(--c-accent-primary)" }}>{p.cve}</span> : VULN_TYPE_LABEL[p.category] || p.category}
                    {p.vuln_type ? <span className="ml-1.5 text-ink-3">{p.vuln_type}</span> : null}
                  </span>
                  <span className="w-[170px] truncate font-mono text-[10px] text-ink-3">{p.affected_versions || "—"}</span>
                  <span className="w-[80px] font-mono text-[10px]" style={{ color: p.supports_waf_bypass ? "var(--c-sem-green)" : "var(--c-text-muted)" }}>
                    {p.supports_waf_bypass ? "BYPASS" : "—"}
                  </span>
                </div>
              ))
            )}
          </div>
          <div className="flex items-center justify-between bg-cardsoft px-3.5 py-2.5">
            <span className="font-mono text-[10px] text-ink-3">共 {counts.all} 个插件 · 4 包自动发现</span>
            <span className="font-mono text-[10px] text-ink-3">DATA: /api/plugins</span>
          </div>
        </section>
      </div>

      {detail ? <PluginDetail p={detail} onClose={() => setDetail(null)} /> : null}
    </div>
  );
}

function Empty({ text }: { text: string }) {
  return (
    <div className="flex h-full items-center justify-center">
      <span className="font-mono text-[11px] text-ink-3">{text}</span>
    </div>
  );
}

function PluginDetail({ p, onClose }: { p: PluginMeta; onClose: () => void }) {
  const rows: [string, string][] = [
    ["名称", p.name],
    ["严重度", p.severity],
    ["分类", `${p.category}${p.vuln_type ? " · " + p.vuln_type : ""}`],
    ["CVE", p.cve || "—"],
    ["影响版本", p.affected_versions || "—"],
    ["WAF 绕过", p.supports_waf_bypass ? "支持" : "不支持"],
    ["描述", p.description || "—"],
  ];
  return (
    <div className="absolute inset-0 z-40 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/50" onClick={onClose} />
      <div
        className="relative flex w-[480px] flex-col gap-3 rounded-lg border p-5 shadow-2xl"
        style={{ borderColor: "var(--c-border)", background: "var(--c-bg-page)" }}
      >
        <div className="flex items-center justify-between">
          <h2 className="flex items-center gap-2.5 text-[13px] font-semibold text-ink">
            <SeverityText s={sevToUi(p.severity)} /> {p.name}
          </h2>
          <button onClick={onClose} className="font-mono text-[12px] text-ink-3 hover:text-ink">✕</button>
        </div>
        <div className="flex flex-col gap-1.5">
          {rows.map(([k, v]) => (
            <div key={k} className="flex items-start gap-3">
              <span className="w-[72px] shrink-0 text-[10.5px] text-ink-3">{k}</span>
              <span className="min-w-0 flex-1 text-[11.5px] leading-[17px] text-ink">{v}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
