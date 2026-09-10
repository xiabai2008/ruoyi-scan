import { useEffect, useState, type ReactNode } from "react";
import { Topbar } from "../components/Topbar";
import { Toggle } from "../components/ui";
import {
  THEME_META, THEME_ORDER, THEMES,
  CUSTOM_DRAFT_FIELDS, deriveCustomTheme, hasCustomTheme, loadCustomTheme, saveCustomTheme,
  normalizeHex, type CustomThemeDraft, type ThemeName,
} from "../tokens";
import { OPERATORS } from "../persona";
import { assetFor } from "../assets/avatars";
import { usePersona, presetConfig, operatorAvatarSrc } from "../state/PersonaCtx";
import { useApp } from "../state/AppCtx";
import { playThemeTick } from "../state/personalize";
import { getVisual, setVisual, type FontMode } from "../state/visual";
import { loadWidgetPrefs, saveWidgetPrefs, DEFAULT_WIDGETS, type WidgetPrefs } from "../state/widgets";
import { api, fetchMetrics, setApiBase, type MetricsSnapshot } from "../services/backend";

const SHORTCUTS: { keys: string; desc: string }[] = [
  { keys: "Ctrl + Enter", desc: "提交扫描" },
  { keys: "Ctrl + K", desc: "快速搜索目标 / POC" },
  { keys: "Esc", desc: "关闭弹窗 / 取消" },
  { keys: "Enter", desc: "查看选中任务详情" },
];

const FONT_MODES: { id: FontMode; label: string; hint: string }[] = [
  { id: "mono", label: "等宽", hint: "JetBrains Mono · 默认" },
  { id: "retro", label: "复古终端", hint: "VT323 · CRT 味" },
  { id: "pixel", label: "像素街机", hint: "Silkscreen · Y2K" },
];

const emptyDraft = (): CustomThemeDraft => ({
  bgPage: "#F2F7FD",
  accentPrimary: "#2F6FED",
  accentPink: "#F25CA2",
  semRed: "#E5484D",
  semGreen: "#1FA971",
  semAmber: "#C77414",
});

export function Settings({ theme, onTheme }: { theme: ThemeName; onTheme: (t: ThemeName) => void }) {
  const { engine, online, apiBase, refreshHealth, lastError } = useApp();
  const { operator, setOperator, resetOperator, chooseCustomAvatar } = usePersona();
  const [baseInput, setBaseInput] = useState(apiBase);
  const [metrics, setMetrics] = useState<MetricsSnapshot | null>(null);
  const [fpTarget, setFpTarget] = useState("");
  const [fpResult, setFpResult] = useState<string>("");
  const [fpBusy, setFpBusy] = useState(false);
  const [fpErr, setFpErr] = useState("");
  const [callsignDraft, setCallsignDraft] = useState(operator.callsign);
  const [greetDraft, setGreetDraft] = useState(operator.greet);
  const [customHint, setCustomHint] = useState("");

  /* 主题编辑器 */
  const [draft, setDraft] = useState<CustomThemeDraft>(emptyDraft);
  const customReady = hasCustomTheme();

  /* 视觉签名 */
  const [visual, setVisualState] = useState(getVisual());

  /* Widgets */
  const [widgets, setWidgetsState] = useState<WidgetPrefs>(() => loadWidgetPrefs());

  useEffect(() => {
    setCallsignDraft(operator.callsign);
    setGreetDraft(operator.greet);
  }, [operator.id, operator.callsign, operator.greet]);

  // Prometheus 指标（在线时拉取）
  useEffect(() => {
    if (!online) {
      setMetrics(null);
      return;
    }
    let alive = true;
    const load = () => fetchMetrics().then((m) => { if (alive) setMetrics(m); }).catch(() => { /* ignore */ });
    load();
    const t = setInterval(load, 5000);
    return () => { alive = false; clearInterval(t); };
  }, [online]);

  const applyBase = async () => {
    const v = baseInput.trim().replace(/\/+$/, "");
    if (!v) return;
    setApiBase(v);
    await refreshHealth();
  };

  const probeFingerprint = async () => {
    const t = fpTarget.trim();
    if (!t) return;
    setFpBusy(true);
    setFpErr("");
    setFpResult("");
    try {
      const r = await api.fingerprint(t);
      const parts = [
        r.cms ? `CMS ${r.cms}${r.version ? " " + r.version : ""} (置信度 ${r.confidence})` : "CMS 未识别",
        r.waf_display || r.waf ? `WAF ${r.waf_display || r.waf}` : "WAF 未检出",
        r.matched?.length ? `特征: ${r.matched.join(", ")}` : "",
      ].filter(Boolean);
      setFpResult(parts.join(" · "));
    } catch (e) {
      setFpErr(e instanceof Error ? e.message : String(e));
    } finally {
      setFpBusy(false);
    }
  };

  const fmtUptime = (sec: number) => {
    const h = Math.floor(sec / 3600);
    const m = Math.floor((sec % 3600) / 60);
    return h > 0 ? `${h}h ${m}m` : `${m}m ${Math.floor(sec % 60)}s`;
  };

  const derived = deriveCustomTheme(draft);

  const applyCustom = () => {
    if (!derived) return;
    saveCustomTheme(derived);
    onTheme("custom");
    playThemeTick();
  };

  const exportTheme = () => {
    const t = loadCustomTheme() ?? derived;
    if (!t) return;
    const blob = new Blob([JSON.stringify(t, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "ruoyi-scan-theme.json";
    a.click();
    URL.revokeObjectURL(url);
  };

  const importTheme = async () => {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = ".json,application/json";
    input.onchange = () => {
      const file = input.files?.[0];
      if (!file) return;
      file.text().then((txt) => {
        try {
          const parsed = JSON.parse(txt) as Record<string, string>;
          const checked: Record<string, string> = {};
          for (const [k, v] of Object.entries(parsed)) {
            if (typeof v === "string" && normalizeHex(v)) checked[k] = v;
          }
          if (Object.keys(checked).length < 20) {
            setCustomHint("主题文件不完整（需 30 个 token），导入失败");
            return;
          }
          saveCustomTheme(checked as never);
          onTheme("custom");
          playThemeTick();
          setCustomHint("主题已导入并启用");
        } catch {
          setCustomHint("JSON 解析失败，导入未生效");
        }
      });
    };
    input.click();
  };

  const patchWidget = (k: keyof WidgetPrefs, v: boolean) => {
    const next = { ...widgets, [k]: v };
    setWidgetsState(next);
    saveWidgetPrefs(next);
  };

  return (
    <div className="flex h-full flex-col">
      <Topbar
        title="设置 · SETTINGS"
        sub={`ENGINE ${engine ? "v" + engine.version : "—"} · ${online ? "ONLINE" : "OFFLINE"} · ${apiBase}`}
        right={
          <button
            onClick={refreshHealth}
            className="h-[34px] rounded-sm border border-edge-ghost px-3.5 text-[12px] text-ink-2 transition-colors hover:bg-cardsoft"
          >
            重新探测
          </button>
        }
      />

      {/* 中部可滚动区 */}
      <div className="thin-scroll flex-1 overflow-auto px-6 py-4">
        {/* 操作员人格 */}
        <Section title="操作员人格 / OPERATOR PERSONA">
          {/* 头像墙：11 预设 + 1 自定义 */}
          <div className="flex flex-wrap items-start gap-2.5">
            {OPERATORS.map((m) => {
              const active = operator.id === m.id;
              const meta = THEME_META[m.theme as Exclude<ThemeName, "custom">];
              return (
                <button
                  key={m.id}
                  onClick={() => setOperator(presetConfig(m.id, operator))}
                  title={`${m.name} · 适配主题「${meta ? meta.label : m.theme}」 · ${m.greet}`}
                  className="group relative flex w-[72px] flex-col items-center gap-1 rounded-lg border p-1.5 transition-all"
                  style={{
                    borderColor: active ? "var(--c-accent-primary)" : "var(--c-border)",
                    background: active ? "var(--c-bubble-bg)" : "var(--c-card-soft)",
                  }}
                >
                  <img
                    src={assetFor(m.file)}
                    alt={m.name}
                    className={`h-12 w-12 rounded-full object-cover transition-transform group-hover:scale-105 ${active ? "ring-2" : ""}`}
                    style={active ? { boxShadow: "0 0 0 2px var(--c-accent-primary)" } : undefined}
                  />
                  <span className="w-full truncate text-center text-[9px] text-ink-2">{m.name.split("·")[1] ?? m.name}</span>
                </button>
              );
            })}
            {/* 自定义头像格 */}
            <button
              onClick={async () => {
                const url = await chooseCustomAvatar();
                setCustomHint(url ? "自定义头像已生效（仅本机保存，不上传）" : "");
              }}
              className="group relative flex w-[72px] flex-col items-center gap-1 rounded-lg border border-dashed p-1.5 transition-all"
              style={{
                borderColor: operator.id === "custom" ? "var(--c-accent-primary)" : "var(--c-border)",
                background: operator.id === "custom" ? "var(--c-bubble-bg)" : "transparent",
              }}
              title="从本机选择一张图片作为头像"
            >
              {operator.id === "custom" && operator.avatar ? (
                <img src={operator.avatar} alt="自定义" className="h-12 w-12 rounded-full object-cover" />
              ) : (
                <span
                  className="flex h-12 w-12 items-center justify-center rounded-full border border-dashed text-[16px] text-ink-3 transition-colors group-hover:text-accent"
                  style={{ borderColor: "var(--c-border)" }}
                >
                  +
                </span>
              )}
              <span className="w-full truncate text-center text-[9px] text-ink-2">自定义</span>
            </button>
          </div>
          {customHint ? <p className="mt-1 text-[9.5px] text-ink-3">{customHint}</p> : null}

          {/* 代号 / 称呼 */}
          <div className="mt-3 grid grid-cols-2 gap-3">
            <div className="flex flex-col gap-1">
              <span className="text-[10.5px] text-ink-2">代号（侧边栏 / 通知称呼）</span>
              <div className="flex gap-2">
                <input
                  className="h-[32px] flex-1 rounded border border-edge bg-cardsoft px-3 text-[11px] text-ink outline-none focus:border-[var(--c-accent-primary)]"
                  maxLength={12}
                  value={callsignDraft}
                  onChange={(e) => setCallsignDraft(e.target.value)}
                  placeholder="枚依"
                  spellCheck={false}
                />
                <button
                  onClick={() => setOperator({ ...operator, callsign: callsignDraft.trim() || "枚依" })}
                  className="h-[32px] rounded-sm bg-accent px-3 text-[11px] font-semibold text-btntext"
                >
                  保存
                </button>
              </div>
            </div>
            <div className="flex flex-col gap-1">
              <span className="text-[10.5px] text-ink-2">口头禅（侧边栏问候语）</span>
              <div className="flex gap-2">
                <input
                  className="h-[32px] flex-1 rounded border border-edge bg-cardsoft px-3 text-[11px] text-ink outline-none focus:border-[var(--c-accent-primary)]"
                  maxLength={24}
                  value={greetDraft}
                  onChange={(e) => setGreetDraft(e.target.value)}
                  placeholder="随时可以开工！"
                  spellCheck={false}
                />
                <button
                  onClick={() => setOperator({ ...operator, greet: greetDraft.trim() })}
                  className="h-[32px] rounded-sm bg-accent px-3 text-[11px] font-semibold text-btntext"
                >
                  保存
                </button>
              </div>
            </div>
          </div>

          {/* 播报 / 音效 开关 */}
          <div className="mt-3 grid grid-cols-3 items-center gap-3 border-t pt-3" style={{ borderColor: "var(--c-border)" }}>
            <label className="flex items-center justify-between gap-2">
              <span className="flex flex-col">
                <span className="text-[11px] text-ink">完成播报 &amp; 系统通知</span>
                <span className="text-[9px] text-ink-3">扫描结束后 Windows 右下角通知</span>
              </span>
              <Toggle
                on={operator.speak}
                onChange={(v) => setOperator({ ...operator, speak: v })}
              />
            </label>
            <label className="flex items-center justify-between gap-2">
              <span className="flex flex-col">
                <span className="text-[11px] text-ink">提示音效</span>
                <span className="text-[9px] text-ink-3">完成双音 / 确认告警低音</span>
              </span>
              <Toggle
                on={operator.sound}
                onChange={(v) => setOperator({ ...operator, sound: v })}
              />
            </label>
            <div className="flex items-center justify-between gap-2">
              <span className="flex flex-col">
                <span className="text-[11px] text-ink">试听音效</span>
                <span className="text-[9px] text-ink-3">不落库，点了就响</span>
              </span>
              <button
                onClick={() => playThemeTick()}
                className="h-[28px] shrink-0 rounded-sm border border-edge px-2.5 text-[10px] text-ink-2 hover:bg-cardsoft"
              >
                叮一声
              </button>
            </div>
          </div>
        </Section>

        {/* 主题包 + 自定义 */}
        <Section title="主题包 / THEME PACKS" contentClass="gap-3">
          <div className="grid grid-cols-5 gap-3">
            {THEME_ORDER.map((id) => {
              const meta = THEME_META[id as Exclude<ThemeName, "custom">];
              const active = id === theme;
              const swatch: string[] = meta.swatch;
              return (
                <button
                  key={id}
                  onClick={() => { onTheme(id); playThemeTick(); }}
                  className="flex flex-col items-start gap-2 rounded border p-3 text-left transition-colors"
                  style={{
                    borderColor: active ? "var(--c-accent-primary)" : "var(--c-border)",
                    borderWidth: active ? 1.5 : 1,
                    background: "var(--c-card)",
                  }}
                >
                  <span className="flex gap-1">
                    {swatch.map((c: string, i: number) => (
                      <i key={i} className="h-3 w-3 rounded-[3px]" style={{ background: c }} />
                    ))}
                  </span>
                  <span className="text-[11px] font-semibold text-ink">{meta.label}</span>
                  <span
                    className="font-mono text-[9px]"
                    style={{ color: active ? "var(--c-sem-green)" : "var(--c-text-muted)" }}
                  >
                    {active ? "使用中" : "一键切换"}
                  </span>
                </button>
              );
            })}
            {/* 自定义主题卡 */}
            <button
              onClick={() => { if (customReady) { onTheme("custom"); playThemeTick(); } }}
              disabled={!customReady}
              title={customReady ? "切换到自定义主题" : "先用下方编辑器生成一套配色"}
              className="flex flex-col items-start gap-2 rounded border p-3 text-left transition-colors disabled:opacity-55"
              style={{
                borderColor: theme === "custom" ? "var(--c-accent-primary)" : "var(--c-border)",
                borderWidth: theme === "custom" ? 1.5 : 1,
                background: theme === "custom" ? "var(--c-bubble-bg)" : "var(--c-card)",
              }}
            >
              <span className="flex gap-1">
                {(() => {
                  const ct = loadCustomTheme();
                  return (ct ? [ct.bgPage, ct.accentPrimary, ct.accentPink] : ["var(--c-zebra)", "var(--c-zebra)", "var(--c-zebra)"]) as string[];
                })().map((c, i) => (
                  <i key={i} className="h-3 w-3 rounded-[3px]" style={{ background: c }} />
                ))}
              </span>
              <span className="text-[11px] font-semibold text-ink">D 自定义</span>
              <span
                className="font-mono text-[9px]"
                style={{ color: theme === "custom" ? "var(--c-sem-green)" : "var(--c-text-muted)" }}
              >
                {theme === "custom" ? "使用中" : customReady ? "一键切换" : "未生成"}
              </span>
            </button>
          </div>

          {/* 主题编辑器 */}
          <div className="rounded border bg-cardsoft p-3" style={{ borderColor: "var(--c-border)" }}>
            <div className="flex items-center justify-between pb-2">
              <span className="text-[11.5px] font-semibold text-ink">主题编辑器 / THEME EDITOR</span>
              <span className="font-mono text-[9px] text-ink-3">6 个核心色 → 派生 30 token</span>
            </div>
            <div className="grid grid-cols-6 gap-2.5">
              {CUSTOM_DRAFT_FIELDS.map((f) => (
                <label key={f.key} className="flex flex-col gap-1">
                  <span className="text-[10px] text-ink-2">{f.label}</span>
                  <span className="flex items-center gap-1.5 rounded border border-edge bg-card px-1.5 py-1">
                    <input
                      type="color"
                      value={normalizeHex(draft[f.key]) ?? "#000000"}
                      onChange={(e) => setDraft({ ...draft, [f.key]: e.target.value })}
                      className="h-6 w-6 shrink-0 cursor-pointer rounded-sm border-0 bg-transparent p-0"
                      title={f.hint}
                    />
                    <input
                      value={draft[f.key]}
                      onChange={(e) => setDraft({ ...draft, [f.key]: e.target.value })}
                      className="w-full min-w-0 bg-transparent font-mono text-[10px] text-ink outline-none"
                      spellCheck={false}
                    />
                  </span>
                  <span className="font-mono text-[8.5px] text-ink-3">{f.hint}</span>
                </label>
              ))}
            </div>
            <div className="mt-3 flex items-center gap-2">
              <button
                onClick={applyCustom}
                disabled={!derived}
                className="h-[30px] rounded-sm bg-accent px-3.5 text-[11px] font-semibold text-btntext disabled:opacity-50"
              >
                应用自定义主题
              </button>
              <button
                onClick={exportTheme}
                disabled={!derived && !customReady}
                className="h-[30px] rounded-sm border border-edge px-3 text-[11px] text-ink-2 hover:bg-card"
              >
                导出 JSON
              </button>
              <button
                onClick={importTheme}
                className="h-[30px] rounded-sm border border-edge px-3 text-[11px] text-ink-2 hover:bg-card"
              >
                导入 JSON
              </button>
              <button
                onClick={() => setDraft(emptyDraft())}
                className="h-[30px] rounded-sm border border-edge px-3 text-[11px] text-ink-2 hover:bg-card"
              >
                重置
              </button>
              <span className="ml-auto font-mono text-[9px]" style={{ color: derived ? "var(--c-sem-green)" : "var(--c-sem-red)" }}>
                {derived ? "配色合法 · 可应用" : "存在非法色值（需 #RRGGBB）"}
              </span>
            </div>
          </div>
        </Section>

        {/* 视觉签名 */}
        <Section title="视觉签名 / VISUAL SIGNATURE" contentClass="gap-3">
          <div className="grid grid-cols-2 gap-4">
            <div className="flex items-center justify-between gap-2">
              <span className="flex flex-col">
                <span className="text-[11px] text-ink">CRT 扫描线</span>
                <span className="text-[9px] text-ink-3">终端面板叠加复古扫描纹理</span>
              </span>
              <Toggle
                on={visual.crt}
                onChange={(v) => { const next = { ...visual, crt: v }; setVisual({ crt: v }); setVisualState(next); }}
              />
            </div>
            <div className="flex flex-col gap-1.5">
              <span className="text-[11px] text-ink">字体模式</span>
              <div className="flex gap-1.5">
                {FONT_MODES.map((m) => (
                  <button
                    key={m.id}
                    onClick={() => { setVisual({ fontMode: m.id }); setVisualState({ ...visual, fontMode: m.id }); }}
                    title={m.hint}
                    className="flex h-[30px] flex-1 items-center justify-center rounded-sm border text-[10.5px] transition-colors"
                    style={{
                      borderColor: visual.fontMode === m.id ? "var(--c-accent-primary)" : "var(--c-border)",
                      background: visual.fontMode === m.id ? "var(--c-bubble-bg)" : "var(--c-card)",
                      color: visual.fontMode === m.id ? "var(--c-accent-primary)" : "var(--c-text-secondary)",
                      fontWeight: visual.fontMode === m.id ? 600 : 400,
                    }}
                  >
                    {m.label}
                  </button>
                ))}
              </div>
            </div>
          </div>
        </Section>

        {/* 桌面 Widgets */}
        <Section title="桌面 Widgets / FLOATING CARDS" contentClass="gap-2">
          <div className="grid grid-cols-3 gap-3">
            {(
              [
                { k: "findings", label: "发现数", hint: "CONFIRMED 总数 + 任务量" },
                { k: "engine", label: "引擎状态", hint: "在线/离线 + 运行数" },
                { k: "progress", label: "任务进度", hint: "当前 running 任务环" },
              ] as { k: keyof WidgetPrefs; label: string; hint: string }[]
            ).map((w) => (
              <div
                key={w.k}
                className="flex items-center justify-between gap-2 rounded border p-2.5"
                style={{ borderColor: "var(--c-border)", background: "var(--c-cardsoft)" }}
              >
                <span className="flex flex-col">
                  <span className="text-[11px] text-ink">{w.label}</span>
                  <span className="text-[9px] text-ink-3">{w.hint}</span>
                </span>
                <Toggle on={widgets[w.k]} onChange={(v) => patchWidget(w.k, v)} />
              </div>
            ))}
          </div>
          <p className="text-[9.5px] text-ink-3">
            开启后浮窗显示在窗口右上角，按住拖到任意位置；位置自动记忆，随窗口边缘自动回弹。
          </p>
        </Section>

        {/* 引擎信息 + 实时指标 双列 */}
        <div className="mt-4 grid grid-cols-2 gap-4">
          <Section title="扫描引擎 / ENGINE" contentClass="gap-1">
            <Row label="版本" value={engine ? `v${engine.version}` : "—"} />
            <Row label="作者" value={engine?.author || "—"} />
            <Row label="Python" value={engine ? `PY ${engine.python_version}` : "—"} />
            <Row label="服务地址" value={apiBase} mono />
            <Row
              label="运行状态"
              value={metrics ? `UP ${fmtUptime(metrics.uptime)}` : online ? "ONLINE" : "OFFLINE"}
            />
            <Row
              label="活跃任务"
              value={metrics ? `${metrics.active} RUNNING` : "—"}
              highlight={!!metrics && metrics.active > 0}
            />
            <div className="mt-1 flex items-center justify-between border-t pt-2" style={{ borderColor: "var(--c-border)" }}>
              <span className="font-mono text-[9.5px] text-ink-3">
                {metrics
                  ? `tasks: ${Object.entries(metrics.tasks).map(([k, v]) => `${k} ${v}`).join(" · ") || "0"}`
                  : lastError || "等待后端连接"}
              </span>
              <button
                onClick={() => { if (engine?.github) window.open(engine.github, "_blank"); }}
                className="shrink-0 rounded-sm border border-edge px-2 py-0.5 text-[10px] text-ink-2 hover:bg-cardsoft"
              >
                项目主页
              </button>
            </div>
          </Section>

          <Section title="实时指标 / METRICS (PROMETHEUS)" contentClass="gap-1">
            {metrics ? (
              <>
                <Row label="任务统计" value={Object.entries(metrics.tasks).map(([k, v]) => `${k}:${v}`).join("  ") || "0"} mono />
                <Row label="结果统计" value={Object.entries(metrics.results).map(([k, v]) => `${k}:${v}`).join("  ") || "0"} mono />
                <Row label="持久化任务" value={metrics.storageTasks !== null ? String(metrics.storageTasks) : "不可用"} />
                <Row label="指标端点" value={`${apiBase}/api/system/metrics`} mono />
              </>
            ) : (
              <div className="flex h-[120px] items-center justify-center">
                <span className="font-mono text-[10.5px] text-ink-3">{online ? "指标加载中…" : "引擎离线 —— 指标不可用"}</span>
              </div>
            )}
          </Section>
        </div>

        {/* 后端连接 + 指纹探测 双列 */}
        <div className="mt-4 grid grid-cols-2 gap-4">
          <Section title="后端连接 / BACKEND" contentClass="gap-2">
            <div className="flex gap-2">
              <input
                className="h-[32px] flex-1 rounded border border-edge bg-cardsoft px-3 font-mono text-[11px] text-ink outline-none focus:border-[var(--c-accent-primary)]"
                placeholder="http://127.0.0.1:8123"
                value={baseInput}
                onChange={(e) => setBaseInput(e.target.value)}
                spellCheck={false}
              />
              <button
                onClick={applyBase}
                className="h-[32px] rounded-sm bg-accent px-3.5 text-[11px] font-semibold text-btntext"
              >
                保存并连接
              </button>
            </div>
            <p className="text-[9.5px] leading-[14px] text-ink-3">
              Tauri 模式下后端由应用自动拉起（127.0.0.1:8123）。仅当 sidecar 部署在远程主机时才需要修改此地址，配置持久化到本地。
            </p>
          </Section>

          <Section title="指纹探测 / FINGERPRINT PROBE" contentClass="gap-2">
            <div className="flex gap-2">
              <input
                className="h-[32px] flex-1 rounded border border-edge bg-cardsoft px-3 font-mono text-[11px] text-ink outline-none placeholder:text-ink-3 focus:border-[var(--c-accent-primary)]"
                placeholder="http://target:8080/"
                value={fpTarget}
                onChange={(e) => setFpTarget(e.target.value)}
                onKeyDown={(e) => { if (e.key === "Enter") probeFingerprint(); }}
                spellCheck={false}
              />
              <button
                onClick={probeFingerprint}
                disabled={fpBusy || !online}
                className="h-[32px] rounded-sm bg-accent px-3.5 text-[11px] font-semibold text-btntext disabled:opacity-50"
              >
                {fpBusy ? "探测中…" : "探测"}
              </button>
            </div>
            {fpResult ? (
              <div className="rounded border bg-cardsoft px-3 py-2" style={{ borderColor: "var(--c-sem-green-tint)" }}>
                <span className="font-mono text-[10.5px] leading-[16px]" style={{ color: "var(--c-sem-green)" }}>{fpResult}</span>
              </div>
            ) : null}
            {fpErr ? <div className="font-mono text-[10.5px] text-red">{fpErr}</div> : null}
            <p className="text-[9.5px] text-ink-3">调用 GET /api/system/fingerprint，轻量探测不入任务表。</p>
          </Section>
        </div>

        {/* 快捷键 */}
        <div className="mt-4">
          <Section title="操作快捷键 / SHORTCUTS">
            <div className="grid grid-cols-2 gap-x-6 gap-y-1.5">
              {SHORTCUTS.map((s) => (
                <div key={s.keys} className="flex items-center justify-between py-1">
                  <span className="text-[11px] text-ink-2">{s.desc}</span>
                  <span className="rounded border border-edge bg-cardsoft px-2 py-0.5 font-mono text-[10px] text-ink">
                    {s.keys}
                  </span>
                </div>
              ))}
            </div>
          </Section>
        </div>
      </div>

      {/* 底部操作栏 */}
      <div
        className="flex items-center justify-between border-t px-6 py-3"
        style={{ borderColor: "var(--c-border)", background: "var(--c-card-soft)" }}
      >
        <div className="flex items-center gap-2">
          <i className="h-1.5 w-1.5 rounded-full" style={{ background: online ? "var(--c-sem-green)" : "var(--c-sem-red)" }} />
          <span className="font-mono text-[10px] text-ink-2">
            {online ? `已连接 ${apiBase} · 配置自动保存到本地` : "未连接 —— 检查后端或修改服务地址"}
          </span>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => { setBaseInput("http://127.0.0.1:8123"); }}
            className="h-[32px] rounded-sm border border-edge px-3 text-[11px] text-ink-2 hover:bg-card"
          >
            恢复默认地址
          </button>
          <button
            onClick={resetOperator}
            className="h-[32px] rounded-sm border border-edge px-3 text-[11px] text-ink-2 hover:bg-card"
          >
            重置操作员人格
          </button>
        </div>
      </div>
    </div>
  );
}

function Section({
  title,
  children,
  contentClass = "",
}: {
  title: string;
  children: ReactNode;
  contentClass?: string;
}) {
  return (
    <section
      className="mt-4 flex flex-col rounded border bg-card p-4"
      style={{ borderColor: "var(--c-border)" }}
    >
      <h2 className="pb-2 text-[12px] font-semibold text-ink">{title}</h2>
      <div className={`flex flex-col ${contentClass}`}>{children}</div>
    </section>
  );
}

function Row({
  label,
  value,
  mono = false,
  highlight = false,
}: {
  label: string;
  value?: string;
  mono?: boolean;
  highlight?: boolean;
}) {
  return (
    <div className="flex items-center justify-between py-1">
      <span className="text-[11.5px] text-ink">{label}</span>
      <span
        className={`max-w-[65%] truncate rounded-sm border border-edge bg-cardsoft px-2 py-0.5 font-mono text-[10px] ${mono ? "font-mono" : ""}`}
        style={{ color: highlight ? "var(--c-accent-primary)" : "var(--c-text-secondary)" }}
        title={value}
      >
        {value}
      </span>
    </div>
  );
}
