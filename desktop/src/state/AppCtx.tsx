/**
 * 全局应用状态：后端连接 / 版本 / 任务列表轮询 / 视图导航 / 新建扫描流程。
 * 主题切换原本在 App.tsx，一并收编到这里，保证跨页面共享（LiveScan 停止后回列表等）。
 */
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { api, getApiBase, type EngineInfo, type ScanSubmitPayload, type ScanTask } from "../services/backend";
import type { ThemeName } from "../tokens";
import type { ViewId } from "../data/mock";
const POLL_MS = 2500;

interface AppCtx {
  /* 主题与导航 */
  theme: ThemeName;
  setTheme: (t: ThemeName) => void;
  view: ViewId;
  setView: (v: ViewId) => void;

  /* 后端连接 */
  online: boolean;
  apiBase: string;
  engine: EngineInfo | null;
  lastError: string;
  refreshHealth: () => Promise<void>;

  /* 任务 */
  tasks: ScanTask[];
  refreshing: boolean;
  refreshTasks: () => Promise<void>;

  /* 新建扫描 */
  dialogOpen: boolean;
  openDialog: () => void;
  closeDialog: () => void;
  submitting: boolean;
  submitScan: (p: ScanSubmitPayload) => Promise<string>;

  /* 当前聚焦任务（LiveScan 展示） */
  selectedTaskId: string | null;
  selectTask: (id: string | null) => void;
}

const Ctx = createContext<AppCtx | null>(null);

export function AppProvider({ children }: { children: ReactNode }) {
  const [theme, setThemeState] = useState<ThemeName>(() => {
    try {
      const saved = localStorage.getItem("rs.theme") as ThemeName | null;
      if (saved === "darkneon" || saved === "bluewhite" || saved === "creampop" || saved === "mintfresh" || saved === "custom") return saved;
    } catch {
      /* ignore */
    }
    return "bluewhite";
  });
  const [view, setView] = useState<ViewId>("overview");
  const [online, setOnline] = useState(false);
  const [engine, setEngine] = useState<EngineInfo | null>(null);
  const [lastError, setLastError] = useState("");
  const [tasks, setTasks] = useState<ScanTask[]>([]);
  const [refreshing, setRefreshing] = useState(false);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [selectedTaskId, setSelectedTaskId] = useState<string | null>(null);
  const apiBase = useMemo(getApiBase, []);
  const healthTimer = useRef<ReturnType<typeof setInterval> | null>(null);

  const refreshHealth = useCallback(async () => {
    try {
      const h = await api.health();
      setOnline(h.status === "ok");
      const v = await api.version();
      setEngine(v);
      setLastError("");
    } catch (e) {
      setOnline(false);
      setLastError(e instanceof Error ? e.message : String(e));
    }
  }, []);

  const refreshTasks = useCallback(async () => {
    setRefreshing(true);
    try {
      const list = await api.listTasks();
      // 新任务在前
      setTasks([...list].sort((a, b) => b.started_at - a.started_at));
    } catch {
      /* 后端离线时保留旧列表 */
    } finally {
      setRefreshing(false);
    }
  }, []);

  // 健康检查：立即一次 + 4s 周期
  useEffect(() => {
    refreshHealth();
    healthTimer.current = setInterval(refreshHealth, 4000);
    return () => {
      if (healthTimer.current) clearInterval(healthTimer.current);
    };
  }, [refreshHealth]);

  // 在线后轮询任务列表；离线时停止
  useEffect(() => {
    if (!online) return;
    refreshTasks();
    const t = setInterval(refreshTasks, POLL_MS);
    return () => clearInterval(t);
  }, [online, refreshTasks]);

  const setTheme = useCallback((t: ThemeName) => {
    setThemeState(t);
    try {
      localStorage.setItem("rs.theme", t);
    } catch {
      /* ignore */
    }
  }, []);

  const submitScan = useCallback(async (p: ScanSubmitPayload): Promise<string> => {
    setSubmitting(true);
    try {
      const r = await api.submitScan(p);
      setDialogOpen(false);
      setSelectedTaskId(r.task_id);
      setView("livescan");
      await refreshTasks();
      return r.task_id;
    } finally {
      setSubmitting(false);
    }
  }, [refreshTasks]);

  const value: AppCtx = {
    theme, setTheme, view, setView,
    online, apiBase, engine, lastError, refreshHealth,
    tasks, refreshing, refreshTasks,
    dialogOpen, openDialog: () => setDialogOpen(true), closeDialog: () => setDialogOpen(false),
    submitting, submitScan,
    selectedTaskId, selectTask: (id: string | null) => setSelectedTaskId(id),
  };

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
export function useApp(): AppCtx {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useApp 必须在 AppProvider 内使用");
  return ctx;
}
