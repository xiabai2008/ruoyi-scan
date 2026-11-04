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

/** 复古字体按需加载（mono 模式零开销）。
 *  返回 Promise：调用方可等加载完再应用，避免「切了没变化」看起来像没生效 ——
 *  字体文件从磁盘加载有几十到几百毫秒，期间浏览器只能回退到备用字体。 */
const fontLoaded: Partial<Record<FontMode, boolean>> = {};
async function ensureFont(mode: FontMode): Promise<void> {
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

/** 等宽类字体（终端、代码、指标数字）跟随切换的变量。
 *  这些是 @theme 里 --font-* 的转发目标（见 styles/theme.css 的注释）。 */
const MONO_VARS = ["--f-mono", "--f-pixel", "--f-crt", "--f-chip"];

/** 应用到 <html>：data-crt 开扫描线；--f-* 换字体栈。
 *
 *  历史坑（2026-11-04）：旧实现改的是 --font-mono 等变量，但 Tailwind v4 的
 *  @theme inline 会把字面值直接烧进 `.font-mono` 工具类，产物里是
 *  `font-family:JetBrains Mono,...` 而非 var()，运行时改变量自然无效 ——
 *  表现就是「点切换字体没有任何变化」。现在改为改 --f-*，由 CSS 里的
 *  `--font-mono: var(--f-mono)` 转发，工具类才会跟着变。
 *
 *  正文字体（body 的 --f-sans）也要一起换：用户期望的是"整站字体变了"，
 *  只改等宽部分的话，中文字多的页面看着几乎没变化。 */
export function applyVisual(p: VisualPrefs) {
  const root = document.documentElement;
  root.dataset.crt = p.crt ? "on" : "off";

  const setVars = () => {
    const stack = FONT_STACKS[p.fontMode] ?? FONT_STACKS.mono;
    for (const v of MONO_VARS) root.style.setProperty(v, stack);
    const sans =
      p.fontMode === "mono"
        ? `"Noto Sans SC Variable", "Noto Sans SC", "Microsoft YaHei", system-ui, sans-serif`
        : `${stack}, "Noto Sans SC Variable", "Noto Sans SC", "Microsoft YaHei", system-ui, sans-serif`;
    root.style.setProperty("--f-sans", sans);
  };

  // 先立刻应用（缓存命中时字体已在，视觉即时生效）；
  // 若字体是首次加载，加载完成后再应用一次，确保不出现「第一下没反应」。
  setVars();
  if (p.fontMode !== "mono") {
    void ensureFont(p.fontMode).then(() => {
      // 期间用户可能又切走了，只在仍是同一模式时才重设
      if (snapshot().fontMode === p.fontMode) setVars();
    });
  }
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
