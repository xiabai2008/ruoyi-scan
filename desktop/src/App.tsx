import { useEffect, useState } from "react";
import { Sidebar } from "./components/Sidebar";
import { NewScanDialog } from "./components/NewScanDialog";
import { Overview } from "./views/Overview";
import { LiveScan } from "./views/LiveScan";
import { VulnDb } from "./views/VulnDb";
import { Assets } from "./views/Assets";
import { Reports } from "./views/Reports";
import { Settings } from "./views/Settings";
import { applyTheme } from "./tokens";
import { AppProvider, useApp } from "./state/AppCtx";
import { PersonaProvider } from "./state/PersonaCtx";
import { useVisualBoot } from "./state/visual";
import { WidgetsLayer, loadWidgetPrefs, saveWidgetPrefs, type WidgetPrefs } from "./state/widgets";
import "./persona.css";

/** 主体直接铺满 Tauri 窗口（不再做 1440×900 画布缩放） */
function Shell() {
  const { theme, setTheme, view } = useApp();
  useVisualBoot();
  useEffect(() => applyTheme(theme), [theme]);
  // Widgets 偏好做成 state：Settings 里开关 → 立即驱动 WidgetsLayer 重渲染
  const [widgetPrefs, setWidgetPrefs] = useState<WidgetPrefs>(() => loadWidgetPrefs());
  useEffect(() => {
    const onStorage = (e: StorageEvent) => {
      if (e.key === "rs.widgets" && e.newValue) {
        try {
          setWidgetPrefs(JSON.parse(e.newValue) as WidgetPrefs);
        } catch {
          /* ignore */
        }
      }
    };
    window.addEventListener("storage", onStorage);
    // 同页签不走 storage 事件 —— 用轻轮询兜底（500ms，仅在字符串变化时 setState）
    const t = setInterval(() => {
      try {
        const raw = localStorage.getItem("rs.widgets") || "";
        setWidgetPrefs((prev) => {
          const s = JSON.stringify(prev);
          return s === raw ? prev : (JSON.parse(raw || "{}") as WidgetPrefs);
        });
      } catch {
        /* ignore */
      }
    }, 500);
    return () => {
      window.removeEventListener("storage", onStorage);
      clearInterval(t);
    };
  }, []);
  const updateWidgets = (p: WidgetPrefs) => {
    setWidgetPrefs(p);
    saveWidgetPrefs(p);
  };
  void updateWidgets;

  return (
    <div
      className="theme-fade relative flex h-full w-full overflow-hidden"
      style={{ background: "var(--c-bg-page)" }}
    >
      <Sidebar />
      <main className="flex min-w-0 flex-1 flex-col overflow-hidden">
        {view === "overview" && <Overview />}
        {view === "livescan" && <LiveScan />}
        {view === "vulndb" && <VulnDb />}
        {view === "assets" && <Assets />}
        {view === "reports" && <Reports theme={theme} />}
        {view === "settings" && <Settings theme={theme} onTheme={setTheme} />}
      </main>

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
