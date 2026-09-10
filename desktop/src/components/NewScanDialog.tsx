import { useEffect, useState } from "react";
import { useApp } from "../state/AppCtx";
import { api, MODE_LABEL, type PluginMeta, type ScanMode, type ScanSubmitPayload } from "../services/backend";
import { Toggle } from "./ui";

const inputCls =
  "h-[30px] w-full rounded-sm border border-edge bg-cardsoft px-2.5 font-mono text-[11px] text-ink outline-none placeholder:text-ink-3 focus:border-[var(--c-accent-primary)]";

function Field({ label, children, hint }: { label: string; children: React.ReactNode; hint?: string }) {
  return (
    <label className="flex flex-col gap-1">
      <span className="text-[10px] text-ink-2">
        {label}
        {hint ? <span className="ml-1 text-ink-3">· {hint}</span> : null}
      </span>
      {children}
    </label>
  );
}

const MODES: ScanMode[] = ["u", "p", "m", "l"];
const REPORT_FORMATS = ["html", "json", "csv", "pdf", "docx", "xlsx"] as const;

export function NewScanDialog() {
  const { dialogOpen, closeDialog, submitting, submitScan, online } = useApp();
  const [target, setTarget] = useState("");
  const [mode, setMode] = useState<ScanMode>("u");
  const [cms, setCms] = useState<"" | "ruoyi" | "spring">("");
  const [threads, setThreads] = useState(8);
  const [rate, setRate] = useState(0);
  const [timeout, setTimeoutV] = useState(10);
  const [passLevel, setPassLevel] = useState<"top100" | "top1000" | "full">("full");
  const [bypassWaf, setBypassWaf] = useState<"auto" | "on" | "off">("auto");
  const [portscan, setPortscan] = useState(false);
  const [ports, setPorts] = useState("");
  const [proxy, setProxy] = useState("");
  const [noDedup, setNoDedup] = useState(false);
  const [formats, setFormats] = useState<Set<string>>(new Set(["json", "html", "csv"]));
  const [plugins, setPlugins] = useState<PluginMeta[]>([]);
  const [picked, setPicked] = useState<Set<string>>(new Set()); // 空 = 全部插件
  const [showPlugins, setShowPlugins] = useState(false);
  const [err, setErr] = useState("");

  // 弹窗打开时拉一次插件列表（供选择）
  useEffect(() => {
    if (!dialogOpen || !online || plugins.length > 0) return;
    api.listPlugins().then((list) => setPlugins(list)).catch(() => { /* 静默 */ });
  }, [dialogOpen, online, plugins.length]);

  if (!dialogOpen) return null;

  const toggleFormat = (f: string) => {
    const next = new Set(formats);
    if (next.has(f)) {
      if (next.size > 1) next.delete(f); // 至少保留一个
    } else {
      next.add(f);
    }
    setFormats(next);
  };

  const togglePlugin = (name: string) => {
    const next = new Set(picked);
    if (next.has(name)) next.delete(name);
    else next.add(name);
    setPicked(next);
  };

  const doSubmit = async () => {
    const t = target.trim();
    if (!t) {
      setErr("目标 URL 不能为空");
      return;
    }
    setErr("");
    const payload: ScanSubmitPayload = {
      target: t,
      mode,
      threads,
      rate,
      timeout,
      pass_level: passLevel,
      bypass_waf: bypassWaf,
      portscan,
      report_format: [...formats].join(","),
    };
    if (cms) payload.cms = cms;
    if (proxy.trim()) payload.proxy = proxy.trim();
    if (ports.trim()) payload.ports = ports.trim();
    if (noDedup) payload.no_dedup = true;
    if (picked.size > 0) payload.plugins = [...picked];
    try {
      await submitScan(payload);
      setTarget("");
      setShowPlugins(false);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  };

  const field = (e: React.KeyboardEvent) => {
    if (e.key === "Escape") closeDialog();
    if (e.key === "Enter" && e.ctrlKey) doSubmit();
  };

  return (
    <div className="absolute inset-0 z-40 flex items-center justify-center" onKeyDown={field}>
      {/* 遮罩 */}
      <div className="absolute inset-0 bg-black/60" onClick={closeDialog} />
      <div
        className="relative flex max-h-[92%] w-[640px] flex-col gap-3.5 overflow-auto rounded-lg border bg-card p-5 shadow-2xl thin-scroll"
        style={{ borderColor: "var(--c-border)", background: "var(--c-bg-page)" }}
      >
        <div className="flex items-center justify-between">
          <h2 className="text-[13px] font-semibold text-ink">
            新建扫描 · <span className="font-mono text-accent">NEW SCAN</span>
          </h2>
          <button onClick={closeDialog} className="font-mono text-[12px] text-ink-3 hover:text-ink">
            ✕
          </button>
        </div>

        {/* 目标 */}
        <Field label="扫描目标" hint="http(s)://host:port/">
          <input
            autoFocus
            className={inputCls}
            placeholder="http://10.211.55.3:8080/"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            spellCheck={false}
          />
        </Field>

        {/* 模式 + CMS */}
        <div className="flex flex-col gap-1">
          <span className="text-[10px] text-ink-2">扫描模式</span>
          <div className="grid grid-cols-4 gap-2">
            {MODES.map((m) => (
              <button
                key={m}
                onClick={() => setMode(m)}
                className="h-[30px] rounded-sm border font-mono text-[10.5px] transition-colors"
                style={{
                  borderColor: mode === m ? "var(--c-accent-primary)" : "var(--c-border)",
                  background: mode === m ? "var(--c-bubble-bg)" : "var(--c-card-soft)",
                  color: mode === m ? "var(--c-accent-primary)" : "var(--c-text-secondary)",
                }}
              >
                {MODE_LABEL[m]}
              </button>
            ))}
          </div>
        </div>

        <div className="grid grid-cols-2 gap-3">
          <Field label="CMS 指定" hint="留空自动识别">
            <select className={inputCls} value={cms} onChange={(e) => setCms(e.target.value as never)}>
              <option value="">自动识别</option>
              <option value="ruoyi">ruoyi</option>
              <option value="spring">spring</option>
            </select>
          </Field>
          <Field label="口令字典">
            <select className={inputCls} value={passLevel} onChange={(e) => setPassLevel(e.target.value as never)}>
              <option value="top100">top100</option>
              <option value="top1000">top1000</option>
              <option value="full">full</option>
            </select>
          </Field>
        </div>

        {/* 引擎参数 */}
        <div className="grid grid-cols-3 gap-2.5">
          <Field label="线程" hint="1-50">
            <input type="number" min={1} max={50} className={inputCls} value={threads} onChange={(e) => setThreads(Math.max(1, Math.min(50, Number(e.target.value) || 1)))} />
          </Field>
          <Field label="限速 RPS" hint="0=不限">
            <input type="number" min={0} className={inputCls} value={rate} onChange={(e) => setRate(Math.max(0, Number(e.target.value) || 0))} />
          </Field>
          <Field label="超时 s">
            <input type="number" min={1} max={120} className={inputCls} value={timeout} onChange={(e) => setTimeoutV(Math.max(1, Math.min(120, Number(e.target.value) || 10)))} />
          </Field>
        </div>

        {/* 高级选项 */}
        <div className="flex items-center gap-5">
          <label className="flex items-center gap-2 text-[11px] text-ink">
            <Toggle on={portscan} onChange={setPortscan} /> 端口预扫描
          </label>
          <label className="flex items-center gap-2 text-[11px] text-ink">
            <Toggle on={!noDedup} onChange={(v) => setNoDedup(!v)} /> 结果去重
          </label>
          <label className="flex flex-1 items-center gap-2">
            <span className="text-[11px] text-ink">WAF 绕过</span>
            <select className="h-[26px] flex-1 rounded-sm border border-edge bg-cardsoft px-2 font-mono text-[10.5px] text-ink outline-none" value={bypassWaf} onChange={(e) => setBypassWaf(e.target.value as never)}>
              <option value="auto">auto 自动</option>
              <option value="on">on 强制</option>
              <option value="off">off 禁用</option>
            </select>
          </label>
        </div>

        <div className="grid grid-cols-2 gap-3">
          <Field label="自定义端口" hint="逗号分隔，留空用默认">
            <input className={inputCls} placeholder="80,443,8080" value={ports} onChange={(e) => setPorts(e.target.value)} spellCheck={false} />
          </Field>
          <Field label="代理（可选）" hint="http://127.0.0.1:7890">
            <input className={inputCls} placeholder="留空=直连" value={proxy} onChange={(e) => setProxy(e.target.value)} spellCheck={false} />
          </Field>
        </div>

        {/* 报告格式 */}
        <div className="flex flex-col gap-1.5">
          <span className="text-[10px] text-ink-2">报告格式 · 至少选一个（PDF/DOCX/XLSX 需后端依赖）</span>
          <div className="flex gap-1.5">
            {REPORT_FORMATS.map((f) => {
              const on = formats.has(f);
              return (
                <button
                  key={f}
                  onClick={() => toggleFormat(f)}
                  className="h-[26px] rounded-sm border px-2.5 font-mono text-[10px] uppercase transition-colors"
                  style={{
                    borderColor: on ? "var(--c-accent-primary)" : "var(--c-border)",
                    background: on ? "var(--c-bubble-bg)" : "var(--c-card-soft)",
                    color: on ? "var(--c-accent-primary)" : "var(--c-text-muted)",
                  }}
                >
                  {f}
                </button>
              );
            })}
          </div>
        </div>

        {/* 插件选择 */}
        <div className="flex flex-col gap-1.5">
          <button
            onClick={() => setShowPlugins(!showPlugins)}
            className="flex items-center justify-between text-[10px] text-ink-2"
          >
            <span>
              插件选择 · {picked.size === 0 ? "全部插件" : `已选 ${picked.size} / ${plugins.length}`}
            </span>
            <span className="font-mono text-accent">{showPlugins ? "收起 ▲" : "展开 ▼"}</span>
          </button>
          {showPlugins ? (
            <div className="thin-scroll flex max-h-[150px] flex-wrap gap-1.5 overflow-auto rounded border border-edge bg-cardsoft p-2.5">
              {plugins.length === 0 ? (
                <span className="font-mono text-[10px] text-ink-3">{online ? "插件加载中…" : "引擎离线，无法加载插件列表"}</span>
              ) : (
                <>
                  {picked.size > 0 ? (
                    <button
                      onClick={() => setPicked(new Set())}
                      className="h-[22px] rounded-sm border border-edge-ghost px-2 font-mono text-[9.5px] text-ink-3 hover:text-ink"
                    >
                      ✕ 清空（用全部）
                    </button>
                  ) : null}
                  {plugins.map((p) => {
                    const on = picked.has(p.name);
                    return (
                      <button
                        key={p.name}
                        onClick={() => togglePlugin(p.name)}
                        className="h-[22px] max-w-[240px] truncate rounded-sm border px-2 font-mono text-[9.5px] transition-colors"
                        style={{
                          borderColor: on ? "var(--c-accent-primary)" : "var(--c-border)",
                          background: on ? "var(--c-bubble-bg)" : "var(--c-card)",
                          color: on ? "var(--c-accent-primary)" : "var(--c-text-secondary)",
                        }}
                        title={`${p.name} · ${p.severity}${p.cve ? " · " + p.cve : ""}`}
                      >
                        {p.name}
                      </button>
                    );
                  })}
                </>
              )}
            </div>
          ) : null}
        </div>

        {err ? <div className="font-mono text-[10.5px] text-red">{err}</div> : null}

        <div className="flex items-center justify-between border-t pt-3.5" style={{ borderColor: "var(--c-border)" }}>
          <span className="font-mono text-[9.5px] text-ink-3">Ctrl+Enter 提交 · Esc 关闭</span>
          <div className="flex gap-2.5">
            <button
              onClick={closeDialog}
              className="h-[34px] rounded-sm border border-edge px-4 text-[12px] text-ink-2 hover:bg-cardsoft"
            >
              取消
            </button>
            <button
              onClick={doSubmit}
              disabled={submitting}
              className="flex h-[34px] items-center gap-2 rounded-sm bg-accent px-4 text-[12px] font-semibold text-btntext disabled:opacity-50"
            >
              {submitting ? <span className="font-mono text-[11px]">提交中…</span> : "开始扫描"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
