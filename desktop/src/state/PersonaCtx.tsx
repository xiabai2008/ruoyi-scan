/**
 * 操作员配置持久化（localStorage 单键）+ 全局枚依播报事件。
 * 挂载于 AppProvider 内，为全应用提供 persona 状态。
 */
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import {
  OPERATORS,
  customAvatarPath,
  defaultOperator,
  operatorById,
  personaUrl,
  setCustomAvatarPath,
  type OperatorConfig,
  type OperatorId,
} from "../persona";
import { assetFor } from "../assets/avatars";
import { installPersonaProtocol } from "./personalize";
import { bindPersonaEvents } from "./personaHooks";

const KEY = "rs.operator";

function loadConfig(): OperatorConfig {
  const def = defaultOperator();
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return { ...def, avatar: assetFor(OPERATORS[0].file) };
    const o = JSON.parse(raw) as Partial<OperatorConfig>;
    const id: OperatorId = (o.id as OperatorId) ?? def.id;
    let avatar = "";
    let callsign = def.callsign;
    let greet = def.greet;
    if (id === "custom") {
      const p = customAvatarPath();
      if (!p) {
        // 自定义图被清理过 → 回退默认
        return { ...def, avatar: assetFor(OPERATORS[0].file) };
      }
      avatar = personaUrl(p);
      callsign = o.callsign || "ME";
      greet = o.greet || "自定义操作员已就位";
    } else {
      const m = OPERATORS.find((x) => x.id === id) ?? OPERATORS[0];
      avatar = assetFor(m.file);
      callsign = o.callsign || m.name.split("·")[0];
      greet = o.greet || m.greet;
    }
    return {
      id,
      callsign,
      greet,
      avatar,
      speak: o.speak ?? true,
      sound: o.sound ?? true,
    };
  } catch {
    return { ...def, avatar: assetFor(OPERATORS[0].file) };
  }
}

function saveConfig(c: OperatorConfig) {
  try {
    localStorage.setItem(KEY, JSON.stringify(c));
  } catch {
    /* ignore */
  }
}

/** 枚依播报事件 —— LiveScan 右栏浮层订阅展示 */
export interface MeiSay {
  id: number;
  text: string;
  tone: "confirm" | "safe" | "unknown" | "info";
}

interface PersonaCtx {
  operator: OperatorConfig;
  setOperator: (c: OperatorConfig) => void;
  resetOperator: () => void;
  /** 选择自定义头像文件（Tauri dialog → 持久化路径 → 返回展示 URL） */
  chooseCustomAvatar: () => Promise<string | null>;
  /** 清除自定义头像并回到默认 */
  clearCustomAvatar: () => void;
  /** 枚依播报（供各处调用，LiveScan 浮层渲染） */
  say: (text: string, tone?: MeiSay["tone"]) => void;
  lastSay: MeiSay | null;
}

const Ctx = createContext<PersonaCtx | null>(null);

export function PersonaProvider({ children }: { children: ReactNode }) {
  const [operator, setOperatorState] = useState<OperatorConfig>(loadConfig);
  const [lastSay, setLastSay] = useState<MeiSay | null>(null);
  const operatorRef = useRef(operator);
  operatorRef.current = operator;

  const setOperator = useCallback((c: OperatorConfig) => {
    setOperatorState(c);
    saveConfig(c);
  }, []);

  const resetOperator = useCallback(() => {
    const def = defaultOperator();
    const c = { ...def, avatar: assetFor(OPERATORS[0].file) };
    setOperatorState(c);
    saveConfig(c);
  }, []);

  const chooseCustomAvatar = useCallback(async (): Promise<string | null> => {
    try {
      const mod = await import("@tauri-apps/plugin-dialog");
      const picked = await mod.open({
        multiple: false,
        title: "选择自定义头像图片",
        filters: [{ name: "图片", extensions: ["png", "jpg", "jpeg", "webp", "gif", "bmp"] }],
      });
      if (typeof picked !== "string" || !picked) return null;
      setCustomAvatarPath(picked);
      const url = personaUrl(picked);
      setOperatorState((prev) => {
        const c: OperatorConfig = {
          ...prev,
          id: "custom",
          callsign: prev.callsign || "ME",
          greet: prev.greet || "自定义操作员已就位",
          avatar: url,
        };
        saveConfig(c);
        return c;
      });
      return url;
    } catch {
      // 浏览器 dev 模式 / 插件不可用：静默降级
      return null;
    }
  }, []);

  const clearCustomAvatar = useCallback(() => {
    setCustomAvatarPath(null);
    const m = OPERATORS[0];
    const c: OperatorConfig = {
      ...defaultOperator(),
      avatar: assetFor(m.file),
    };
    setOperatorState(c);
    saveConfig(c);
  }, []);

  const say = useCallback((text: string, tone: MeiSay["tone"] = "info") => {
    setLastSay({ id: Date.now() + Math.random(), text, tone });
  }, []);

  // persona:// → asset:// 一次性安装（Tauri 环境才生效）
  useEffect(() => {
    void installPersonaProtocol();
  }, []);

  // 人格事件桥：扫描完成 / 确认告警 → 播报 + 音效 + 系统通知
  useEffect(
    () =>
      bindPersonaEvents(say, () => ({
        speak: operatorRef.current.speak,
        sound: operatorRef.current.sound,
        callsign: operatorRef.current.callsign,
      })),
    [say],
  );

  const value = useMemo<PersonaCtx>(
    () => ({ operator, setOperator, resetOperator, chooseCustomAvatar, clearCustomAvatar, say, lastSay }),
    [operator, setOperator, resetOperator, chooseCustomAvatar, clearCustomAvatar, say, lastSay],
  );

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function usePersona(): PersonaCtx {
  const c = useContext(Ctx);
  if (!c) throw new Error("usePersona 必须在 PersonaProvider 内使用");
  return c;
}

/** 兼容旧调用点：仅取当前头像 src */
export function operatorAvatarSrc(op: OperatorConfig): string {
  if (op.avatar) return op.avatar;
  return assetFor(OPERATORS[0].file);
}

/** 根据 id 取预设完整配置（设置页切换预设用） */
export function presetConfig(id: OperatorId, prev: OperatorConfig): OperatorConfig {
  const m = OPERATORS.find((o) => o.id === id);
  if (!m) return prev;
  return {
    ...prev,
    id: m.id,
    callsign: m.name.split("·")[0],
    greet: m.greet,
    avatar: assetFor(m.file),
  };
}

export { operatorById };
