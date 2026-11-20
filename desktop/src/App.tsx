import { useEffect, useState } from "react";
import { Sidebar } from "./components/Sidebar";
import { NewScanDialog } from "./components/NewScanDialog";
import { Overview } from "./views/Overview";
import { LiveScan } from "./views/LiveScan";
import { VulnDb } from "./views/VulnDb";
import { Assets } from "./views/Assets";
import { Reports } from "./views/Reports";
import { Schedules } from "./views/Schedules";
import { Settings } from "./views/Settings";
import { applyTheme } from "./tokens";
import { checkForUpdate, isTauriRuntime, type UpdateInfo } from "./services/updater";
import { AppProvider, useApp } from "./state/AppCtx";
import { PersonaProvider } from "./state/PersonaCtx";
import { useVisualBoot } from "./state/visual";
import { WidgetsLayer, loadWidgetPrefs, type WidgetPrefs } from "./state/widgets";
import "./persona.css";

/** rs.widgets 反序列化收敛：脏数据/缺字段一律视为 false，避免盲断言把非法形状带进 UI */
function sanitizeWidgetPrefs(raw: unknown): WidgetPrefs {
  const o = (raw && typeof raw === "object" ? raw : {}) as Partial<Record<keyof WidgetPrefs, unknown>>;
  return { findings: !!o.findings, engine: !!o.engine, progress: !!o.progress };
}

/** 主体直接铺满 Tauri 窗口（不再做 1440×900 画布缩放） */
function Shell() {
  const { theme, setTheme, customRev, view, setView, dialogOpen } = useApp();
  useVisualBoot();
  // customRev 参与依赖：theme 已是 "custom" 时再改调色板，theme 值没变
  // （React 会 bail out），只有计数变化能让这里重新 applyTheme。
  // 缺少它会导致「应用自定义主题 / 导入 JSON 后界面毫无变化」。
  useEffect(() => applyTheme(theme), [theme, customRev]);

  // Ctrl+K：聚焦总览搜索（旧设置页把 Ctrl+K 列成快捷键，但全前端没有 handler）
  // 弹窗打开时不抢焦点：否则焦点被移到遮罩背后的搜索框，弹窗内 Esc / Ctrl+Enter
  // 依赖的 keydown 再也冒不上来，用户按 Esc 关不掉弹窗、输入还会静默落进搜索框。
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (!((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k")) return;
      if (dialogOpen) return;
      e.preventDefault();
      setView("overview");
      requestAnimationFrame(() => {
        document.getElementById("rs-global-search")?.focus();
      });
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [setView, dialogOpen]);
  // Widgets 偏好做成 state：Settings 里开关 → 立即驱动 WidgetsLayer 重渲染
  const [widgetPrefs, setWidgetPrefs] = useState<WidgetPrefs>(() => loadWidgetPrefs());
  const [updateAvailable, setUpdateAvailable] = useState<UpdateInfo | null>(null);

  // 桌面端启动后静默检查一次新版本；有更新时用右下角浮条提示，点击进入设置页。
  // 浏览器/vitest 下 isTauriRuntime=false，不触发任何 Tauri 调用。
  useEffect(() => {
    if (!isTauriRuntime()) return;
    let alive = true;
    const timer = window.setTimeout(() => {
      checkForUpdate()
        .then((info) => { if (alive && info) setUpdateAvailable(info); })
        .catch((err) => console.warn("[app] 在线更新检查失败，已忽略", err));
    }, 2500);
    return () => { alive = false; window.clearTimeout(timer); };
  }, []);
  useEffect(() => {
    let last = localStorage.getItem("rs.widgets") || "";
    const onStorage = (e: StorageEvent) => {
      if (e.key === "rs.widgets" && e.newValue) {
        last = e.newValue;
        try {
          setWidgetPrefs(sanitizeWidgetPrefs(JSON.parse(e.newValue)));
        } catch (err) {
          console.warn("[app] rs.widgets 存储事件数据无法解析，已忽略", err);
        }
      }
    };
    window.addEventListener("storage", onStorage);
    // 同页签不走 storage 事件 —— 用轻轮询兜底（500ms，先比对原始字符串，未变化直接跳过）
    const t = setInterval(() => {
      const raw = localStorage.getItem("rs.widgets") || "";
      if (raw === last) return;
      last = raw;
      try {
        setWidgetPrefs(sanitizeWidgetPrefs(JSON.parse(raw || "{}")));
      } catch (err) {
        console.warn("[app] rs.widgets 轮询数据无法解析，已忽略", err);
      }
    }, 500);
    return () => {
      window.removeEventListener("storage", onStorage);
      clearInterval(t);
    };
  }, []);

  return (
    <div className="theme-fade relative flex h-full w-full overflow-hidden bg-page">
      <Sidebar />
      <main className="flex min-w-0 flex-1 flex-col overflow-hidden">
        {view === "overview" && <Overview />}
        {view === "livescan" && <LiveScan />}
        {view === "vulndb" && <VulnDb />}
        {view === "assets" && <Assets />}
        {view === "reports" && <Reports theme={theme} />}
        {view === "schedules" && <Schedules />}
        {view === "settings" && <Settings theme={theme} onTheme={setTheme} />}
      </main>

      {updateAvailable ? (
        <button
          onClick={() => { setUpdateAvailable(null); setView("settings"); }}
          className="fixed bottom-4 right-4 z-50 rounded-md border border-[var(--c-accent-primary)] bg-page px-3 py-2 text-left shadow-lg hover:bg-cardsoft"
          title="打开设置页安装更新"
        >
          <span className="block font-mono text-[10px] text-ink-3">UPDATE AVAILABLE</span>
          <span className="block text-[11px] font-semibold text-ink">发现新版本 v{updateAvailable.version} · 点击升级</span>
        </button>
      ) : null}

      <NewScanDialog />
      <WidgetsLayer prefs={widgetPrefs} />
    </div>
  );
}

export default function App() {
  return (
    <AppProvider>
      <PersonaProvider>
        <Shell />
      </PersonaProvider>
    </AppProvider>
  );
}
