/**
 * 全局应用状态：后端连接 / 版本 / 任务列表轮询 / 视图导航 / 新建扫描流程。
 * 主题切换原本在 App.tsx，一并收编到这里，保证跨页面共享（LiveScan 停止后回列表等）。
 */
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { api, getApiBase, type EngineInfo, type ScanMode, type ScanSubmitPayload, type ScanTask } from "../services/backend";
import type { ThemeName } from "../tokens";
import type { ViewId } from "../data/mock";
const POLL_MS = 2500;

/** 新建扫描预置：VulnDb“用筛选结果扫描”把选中的插件带进弹窗 */
export interface ScanDialogPreset {
  plugins?: string[];
  mode?: ScanMode;
}

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
  /** 已从任务栏关闭的任务 id（只在前端隐藏，不删后端记录；持久化到 localStorage） */
  dismissed: Set<string>;
  /** 关闭任务栏标签：无法删除后端记录，做隐藏处理 */
  dismissTask: (id: string) => void;

  /* 新建扫描 */
  dialogOpen: boolean;
  /** 弹窗预置（插件子集/模式）；关闭后清空 */
  dialogPreset: ScanDialogPreset | null;
  openDialog: (preset?: ScanDialogPreset) => void;
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
  const [dialogPreset, setDialogPreset] = useState<ScanDialogPreset | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [selectedTaskId, setSelectedTaskId] = useState<string | null>(null);
  // 任务栏里被用户关掉的标签。后端没有删除任务的接口，这里做前端隐藏，
  // 并持久化到 localStorage，避免刷新后「关掉的任务又冒出来」。
  const [dismissed, setDismissed] = useState<Set<string>>(() => {
    try {
      const raw = localStorage.getItem("ruoyi-scan.dismissedTasks");
      const arr = raw ? (JSON.parse(raw) as string[]) : [];
      return new Set(Array.isArray(arr) ? arr : []);
    } catch {
      return new Set();
    }
  });
  const apiBase = useMemo(getApiBase, []);
  const healthTimer = useRef<ReturnType<typeof setInterval> | null>(null);
  // 健康检查序号：4s 轮询可能重叠，过期响应直接丢弃，避免乱序结果互相覆盖
  const healthSeq = useRef(0);

  const refreshHealth = useCallback(async () => {
    const seq = ++healthSeq.current;
    try {
      // health 与 version 一起取，避免 health 成功而 version 失败时 online 状态自相矛盾
      const [h, v] = await Promise.all([api.health(), api.version()]);
      if (seq !== healthSeq.current) return;
      setOnline(h.status === "ok");
      setEngine(v);
      setLastError("");
    } catch (e) {
      if (seq !== healthSeq.current) return;
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
      setDialogPreset(null);
      setSelectedTaskId(r.task_id);
      setView("livescan");
      await refreshTasks();
      return r.task_id;
    } finally {
      setSubmitting(false);
    }
  }, [refreshTasks]);

  const dismissTask = useCallback((id: string) => {
    setDismissed((prev) => {
      const next = new Set(prev).add(id);
      try {
        localStorage.setItem("ruoyi-scan.dismissedTasks", JSON.stringify([...next]));
      } catch {
        /* 隐私模式下 localStorage 可能不可写，忽略 */
      }
      return next;
    });
    // 关掉的正好是当前聚焦任务时，把选中态让出来（调用方会回落到 tasks[0]）
    setSelectedTaskId((cur) => (cur === id ? null : cur));
  }, []);

  const value: AppCtx = {
    theme, setTheme, view, setView,
    online, apiBase, engine, lastError, refreshHealth,
    tasks, refreshing, refreshTasks, dismissed, dismissTask,
    dialogOpen,
    dialogPreset,
    openDialog: (preset?: ScanDialogPreset) => {
      setDialogPreset(preset ?? null);
      setDialogOpen(true);
    },
    closeDialog: () => {
      setDialogOpen(false);
      setDialogPreset(null);
    },
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
