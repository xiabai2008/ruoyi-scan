/**
 * 视觉签名偏好：CRT 扫描线开关 + 字体模式（等宽 / 复古终端 / 像素街机）。
 * localStorage rs.visual 持久化；applyVisual() 写 <html data-crt> + 切换字体 CSS 变量。
 * 复古字体包已在 dependencies（vt323 / silkscreen / press-start-2p），按需动态 import。
 */
import { useEffect, useState } from "react";

export type FontMode = "mono" | "retro" | "pixel";

export interface VisualPrefs {
  crt: boolean;
  fontMode: FontMode;
}

const KEY = "rs.visual";

const DEFAULTS: VisualPrefs = { crt: false, fontMode: "mono" };

export function loadVisual(): VisualPrefs {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return { ...DEFAULTS };
    const o = JSON.parse(raw) as Partial<VisualPrefs>;
    return {
      crt: !!o.crt,
      fontMode: o.fontMode === "retro" || o.fontMode === "pixel" ? o.fontMode : "mono",
    };
  } catch {
    return { ...DEFAULTS };
  }
}

export function saveVisual(p: VisualPrefs) {
  try {
    localStorage.setItem(KEY, JSON.stringify(p));
  } catch {
    /* ignore */
  }
}

/** 全局偏好单例（不走 context，Settings 与根组件直接读写）。
 *  懒加载：模块导入不触碰 localStorage（SSR/测试环境 import 安全），首次访问才读取。 */
let current: VisualPrefs | null = null;
const listeners = new Set<(p: VisualPrefs) => void>();

function snapshot(): VisualPrefs {
  if (!current) current = loadVisual();
  return current;
}

export function getVisual(): VisualPrefs {
  return snapshot();
}

export function setVisual(patch: Partial<VisualPrefs>) {
  const next = { ...snapshot(), ...patch };
  current = next;
  saveVisual(next);
  applyVisual(next);
  for (const fn of listeners) {
    // 单个订阅者异常不应饿死后续订阅者（状态已更新，观察方必须保持一致）
    try {
      fn(next);
    } catch (e) {
      console.error("[visual] 订阅者回调异常", e);
    }
  }
}

export function subscribeVisual(fn: (p: VisualPrefs) => void): () => void {
  listeners.add(fn);
  return () => {
    listeners.delete(fn);
  };
}

/** 复古字体按需加载（mono 模式零开销） */
const fontLoaded: Partial<Record<FontMode, boolean>> = {};
async function ensureFont(mode: FontMode) {
  if (fontLoaded[mode]) return;
  try {
    if (mode === "retro") await import("@fontsource/vt323");
    if (mode === "pixel") {
      await import("@fontsource/press-start-2p");
      await import("@fontsource/silkscreen");
    }
    fontLoaded[mode] = true;
  } catch {
    /* 字体包缺失静默降级 */
  }
}

const FONT_STACKS: Record<FontMode, string> = {
  mono: `"JetBrains Mono", "Cascadia Code", Consolas, monospace`,
  retro: `"VT323", "JetBrains Mono", monospace`,
  pixel: `"Silkscreen", "Press Start 2P", "JetBrains Mono", monospace`,
};

/** 应用到 <html>：data-crt 开扫描线；--font-mono/pixel/crt/chip 换栈 */
export function applyVisual(p: VisualPrefs) {
  const root = document.documentElement;
  root.dataset.crt = p.crt ? "on" : "off";
  if (p.fontMode !== "mono") void ensureFont(p.fontMode);
  const stack = FONT_STACKS[p.fontMode] ?? FONT_STACKS.mono;
  root.style.setProperty("--font-mono", stack);
  root.style.setProperty("--font-pixel", stack);
  root.style.setProperty("--font-crt", stack);
  root.style.setProperty("--font-chip", stack);
}

/** 根组件挂载时调用一次：读偏好 + 监听后续变化 */
export function useVisualBoot(): VisualPrefs {
  const [prefs, setPrefs] = useState<VisualPrefs>(snapshot);
  useEffect(() => {
    applyVisual(snapshot());
    return subscribeVisual(setPrefs);
  }, []);
  return prefs;
}
