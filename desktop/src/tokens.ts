/**
 * RuoYiTheme —— 与 Ardot 画布变量系统一一对应的主题 token（30 × 4 + 自定义）。
 * 单一数据源：CSS 变量与 ECharts 配色都从这里出，保证设计稿/代码零漂移。
 */

export type ThemeName = "darkneon" | "bluewhite" | "creampop" | "mintfresh" | "custom";

export type TokenKey =
  | "bgPage" | "bgSidebar" | "card" | "cardSoft" | "zebra" | "deep"
  | "bubbleBg" | "activeNav" | "divider" | "border" | "borderSoft" | "ghostBorder"
  | "textPrimary" | "textSecondary" | "textMuted" | "bubbleText" | "legendText"
  | "accentPrimary" | "btnText" | "accentPurple" | "accentPink" | "navNum"
  | "semRed" | "semRedTint" | "semGreen" | "semGreenTint" | "semAmber" | "semAmberTint"
  | "alertStroke" | "gridLine";

export type Theme = Record<TokenKey, string>;

export const THEME_ORDER: ThemeName[] = ["darkneon", "bluewhite", "creampop", "mintfresh"];

export const THEME_META: Record<Exclude<ThemeName, "custom">, { label: string; en: string; swatch: [string, string, string] }> = {
  darkneon:  { label: "V0 暗夜霓虹",  en: "DARK NEON",  swatch: ["#0A0A14", "#2EE6E6", "#FF3EC8"] },
  bluewhite: { label: "A 天选蓝白",   en: "BLUE WHITE", swatch: ["#F2F7FD", "#2F6FED", "#F25CA2"] },
  creampop:  { label: "B 蜜桃CityPop", en: "CREAM POP",  swatch: ["#FBF4EA", "#9B7BE8", "#FF8A70"] },
  mintfresh: { label: "C 白瓷薄荷",   en: "MINT FRESH", swatch: ["#F3FAF7", "#12A38A", "#F0708A"] },
};

export const THEMES: Record<Exclude<ThemeName, "custom">, Theme> = {
  darkneon: {
    bgPage: "#0A0A14", bgSidebar: "#0D0D1C", card: "#0F0F1F", cardSoft: "#12122A", zebra: "#0C0C1A", deep: "#1A1A33",
    bubbleBg: "#1A0E33", activeNav: "#1A0E33", divider: "#1E1E3C", border: "#23234A", borderSoft: "#2A2A55", ghostBorder: "#2E2E5A",
    textPrimary: "#E8E8F5", textSecondary: "#9A9AC0", textMuted: "#5E5E85", bubbleText: "#C9BFFF", legendText: "#C9C9E0",
    accentPrimary: "#2EE6E6", btnText: "#061018", accentPurple: "#8B7BE8", accentPink: "#FF3EC8", navNum: "#B9A8FF",
    semRed: "#FF4D5E", semRedTint: "#2E1420", semGreen: "#3DE8A0", semGreenTint: "#12281F", semAmber: "#FFB84D", semAmberTint: "#2E2415",
    alertStroke: "#4A1F2E", gridLine: "#1A1A38",
  },
  bluewhite: {
    bgPage: "#F2F7FD", bgSidebar: "#FFFFFF", card: "#FFFFFF", cardSoft: "#EDF4FC", zebra: "#F6FAFE", deep: "#DCE9F8",
    bubbleBg: "#E4EEFC", activeNav: "#DCE9F8", divider: "#E2ECF6", border: "#D5E3F2", borderSoft: "#C4D7EC", ghostBorder: "#AFC7E2",
    textPrimary: "#17264E", textSecondary: "#5B6C8F", textMuted: "#93A3BD", bubbleText: "#44619E", legendText: "#4A5C80",
    accentPrimary: "#2F6FED", btnText: "#FFFFFF", accentPurple: "#6C5CE0", accentPink: "#F25CA2", navNum: "#6E96F0",
    semRed: "#E5484D", semRedTint: "#FCE5E7", semGreen: "#1FA971", semGreenTint: "#E0F5EB", semAmber: "#C77414", semAmberTint: "#FBF0DC",
    alertStroke: "#F2B8BD", gridLine: "#E4EEF8",
  },
  creampop: {
    bgPage: "#FBF4EA", bgSidebar: "#FFFBF5", card: "#FFFFFF", cardSoft: "#F6EDDE", zebra: "#FBF5EB", deep: "#F0E4D2",
    bubbleBg: "#F1E7F8", activeNav: "#EFE4F8", divider: "#EADFCB", border: "#E4D6BF", borderSoft: "#D9C8AC", ghostBorder: "#C9B48E",
    textPrimary: "#443655", textSecondary: "#7A6B8C", textMuted: "#AC9FAE", bubbleText: "#7A63B8", legendText: "#6E5F85",
    accentPrimary: "#9B7BE8", btnText: "#FFFFFF", accentPurple: "#6C4FD8", accentPink: "#FF8A70", navNum: "#B49AF0",
    semRed: "#E05656", semRedTint: "#FBE7E3", semGreen: "#3AA26B", semGreenTint: "#E4F3E7", semAmber: "#C0801F", semAmberTint: "#FAF0DA",
    alertStroke: "#F3C6BB", gridLine: "#EFE4D2",
  },
  mintfresh: {
    bgPage: "#F3FAF7", bgSidebar: "#FFFFFF", card: "#FFFFFF", cardSoft: "#E9F5F0", zebra: "#F4FAF7", deep: "#DBEFE7",
    bubbleBg: "#DFF2EC", activeNav: "#D8F0E7", divider: "#DCEBE4", border: "#CDE4DA", borderSoft: "#BAD9CC", ghostBorder: "#A2CBB8",
    textPrimary: "#12382E", textSecondary: "#4F7266", textMuted: "#8AA89D", bubbleText: "#2F6E5C", legendText: "#47695E",
    accentPrimary: "#12A38A", btnText: "#FFFFFF", accentPurple: "#4A7DD6", accentPink: "#F0708A", navNum: "#3FBFA4",
    semRed: "#DD4B55", semRedTint: "#FBE6E5", semGreen: "#22A56B", semGreenTint: "#DFF4E7", semAmber: "#BC7A12", semAmberTint: "#F8F0DA",
    alertStroke: "#F1C3C3", gridLine: "#E2EFE9",
  },
};

const kebab = (k: string) => k.replace(/[A-Z]/g, (m) => "-" + m.toLowerCase());

/* ================= 自定义主题 ================= */

const CUSTOM_KEY = "rs.customTheme";

/** 十六进制色 → #RRGGBB 规范化（容忍 3 位缩写） */
export function normalizeHex(input: string): string | null {
  const v = input.trim().replace(/^#/, "");
  if (/^[0-9a-fA-F]{6}$/.test(v)) return "#" + v.toLowerCase();
  if (/^[0-9a-fA-F]{3}$/.test(v)) return "#" + v.split("").map((c) => c + c).join("").toLowerCase();
  return null;
}

/** hex → [r,g,b] 0-255 */
function rgbOf(hex: string): [number, number, number] {
  const v = hex.replace("#", "");
  return [parseInt(v.slice(0, 2), 16), parseInt(v.slice(2, 4), 16), parseInt(v.slice(4, 6), 16)];
}

const clamp = (n: number, lo: number, hi: number) => Math.max(lo, Math.min(hi, n));
const toHex = (rgb: [number, number, number]) =>
  "#" + rgb.map((c) => clamp(Math.round(c), 0, 255).toString(16).padStart(2, "0")).join("");

/** 明度（0-1，YIQ 近似） */
export function luminance(hex: string): number {
  const [r, g, b] = rgbOf(hex);
  return (r * 299 + g * 587 + b * 114) / 255000;
}

/** 颜色混合：t=0 → base，t=1 → overlay */
function mix(base: string, overlay: string, t: number): string {
  const a = rgbOf(base);
  const b = rgbOf(overlay);
  return toHex([a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t, a[2] + (b[2] - a[2]) * t]);
}

/** 半透明叠加（用于 tint 类 token：把前景色以低透明度铺在页面底色上） */
function tintOf(fg: string, bg: string, alpha: number): string {
  return mix(bg, fg, alpha);
}

export interface CustomThemeDraft {
  /** 页面底色（决定整套明暗气质） */
  bgPage: string;
  /** 强调色（按钮/激活态/图表主线） */
  accentPrimary: string;
  /** 品红点缀（OPERATOR 标签/次要点缀） */
  accentPink: string;
  /** 危险红（CONFIRMED 语义色） */
  semRed: string;
  /** 安全绿（SAFE 语义色） */
  semGreen: string;
  /** 待定黄（UNKNOWN 语义色） */
  semAmber: string;
}

export const CUSTOM_DRAFT_FIELDS: { key: keyof CustomThemeDraft; label: string; hint: string }[] = [
  { key: "bgPage", label: "页面底色", hint: "浅色=清爽 / 深色=霓虹" },
  { key: "accentPrimary", label: "强调色", hint: "按钮 / 图表主线" },
  { key: "accentPink", label: "点缀色", hint: "OPERATOR 标签" },
  { key: "semRed", label: "告警红", hint: "CONFIRMED" },
  { key: "semGreen", label: "安全绿", hint: "SAFE" },
  { key: "semAmber", label: "待定黄", hint: "UNKNOWN" },
];

/** 从 6 个核心色派生完整 30 token（参考四套预设的配色关系） */
/* ---------- 派生阈值 / 基色（调参集中在此，注释说明意图） ---------- */
/** 底色明度低于此值 → 走深色系派生（浅色文字 + 加暗卡片） */
const DARK_BG_LUMINANCE = 0.42;
/** 强调色明度高于此值 → 按钮文字用深色，否则用白色 */
const BTN_TEXT_CONTRAST = 0.62;
/** 深色底语义 tint 透明度：红色稍强，绿/黄稍弱；浅色底统一 0.12 */
const TINT_ALPHA_RED_DARK = 0.28;
const TINT_ALPHA_WARM_DARK = 0.26;
const TINT_ALPHA_LIGHT = 0.12;
/** 告警描边透明度：深色底更实、浅色底更淡 */
const ALERT_STROKE_ALPHA_DARK = 0.4;
const ALERT_STROKE_ALPHA_LIGHT = 0.72;
/** 主文字基色（不随 draft 变化）：浅色底深墨蓝 / 深色底浅灰紫 */
const INK_LIGHT_BG = "#17264E";
const INK_DARK_BG = "#E8E8F5";
/** accentPurple 的混色基准（紫色点缀） */
const ACCENT_PURPLE_BASE = "#7B5CE0";

export function deriveCustomTheme(draft: CustomThemeDraft): Theme | null {
  const bg = normalizeHex(draft.bgPage);
  const accent = normalizeHex(draft.accentPrimary);
  const pink = normalizeHex(draft.accentPink);
  const red = normalizeHex(draft.semRed);
  const green = normalizeHex(draft.semGreen);
  const amber = normalizeHex(draft.semAmber);
  if (!bg || !accent || !pink || !red || !green || !amber) return null;

  const dark = luminance(bg) < DARK_BG_LUMINANCE;
  const textPrimary = dark ? INK_DARK_BG : INK_LIGHT_BG;
  const textSecondary = dark ? mix(bg, textPrimary, 0.55) : mix(bg, textPrimary, 0.62);
  const textMuted = dark ? mix(bg, textPrimary, 0.34) : mix(bg, textPrimary, 0.42);
  const card = dark ? mix(bg, "#000000", 0.18) : "#FFFFFF";
  const cardSoft = dark ? mix(bg, "#FFFFFF", 0.045) : mix(bg, "#FFFFFF", 0.55);
  const zebra = dark ? mix(bg, "#000000", 0.1) : mix(bg, "#FFFFFF", 0.3);
  const deep = dark ? mix(bg, accent, 0.09) : mix(bg, accent, 0.16);
  const sidebar = dark ? mix(card, "#000000", 0.12) : "#FFFFFF";
  const bubbleBg = dark ? mix(bg, accent, 0.16) : mix(bg, accent, 0.14);
  const border = dark ? mix(bg, "#FFFFFF", 0.11) : mix(bg, "#5B6C8F", 0.26);
  const divider = dark ? mix(border, bg, 0.25) : mix(border, "#FFFFFF", 0.45);
  const btnText = luminance(accent) > BTN_TEXT_CONTRAST ? "#061018" : "#FFFFFF";
  // 语义 tint 的衬底：深色底稍压暗，避免色块直接铺在页面上过亮
  const tintBase = dark ? mix(bg, "#000000", 0.1) : bg;

  return {
    bgPage: bg,
    bgSidebar: sidebar,
    card,
    cardSoft,
    zebra,
    deep,
    bubbleBg,
    activeNav: deep,
    divider,
    border,
    borderSoft: mix(border, textPrimary, 0.15),
    ghostBorder: mix(border, textPrimary, 0.3),
    textPrimary,
    textSecondary,
    textMuted,
    bubbleText: dark ? mix(bubbleBg, textPrimary, 0.55) : mix(bubbleBg, accent, 0.55),
    legendText: mix(bg, textPrimary, 0.72),
    accentPrimary: accent,
    btnText,
    accentPurple: mix(accent, ACCENT_PURPLE_BASE, 0.55),
    accentPink: pink,
    navNum: mix(accent, textPrimary, 0.18),
    semRed: red,
    semRedTint: tintOf(red, tintBase, dark ? TINT_ALPHA_RED_DARK : TINT_ALPHA_LIGHT),
    semGreen: green,
    semGreenTint: tintOf(green, tintBase, dark ? TINT_ALPHA_WARM_DARK : TINT_ALPHA_LIGHT),
    semAmber: amber,
    semAmberTint: tintOf(amber, tintBase, dark ? TINT_ALPHA_WARM_DARK : TINT_ALPHA_LIGHT),
    alertStroke: tintOf(red, dark ? card : "#FFFFFF", dark ? ALERT_STROKE_ALPHA_DARK : ALERT_STROKE_ALPHA_LIGHT),
    gridLine: mix(bg, textPrimary, dark ? 0.09 : 0.1),
  };
}

export function saveCustomTheme(t: Theme) {
  try {
    localStorage.setItem(CUSTOM_KEY, JSON.stringify(t));
  } catch {
    /* ignore */
  }
}

export function loadCustomTheme(): Theme | null {
  try {
    const raw = localStorage.getItem(CUSTOM_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Partial<Theme>;
    const base = THEMES.bluewhite;
    const out = {} as Theme;
    for (const k of Object.keys(base) as TokenKey[]) {
      const v = parsed[k];
      // 存归一化后的 #RRGGBB：容忍手改/导入的 3 位缩写，避免下游 rgbOf 解出 NaN
      const normalized = typeof v === "string" ? normalizeHex(v) : null;
      if (normalized) out[k] = normalized;
      else return null;
    }
    return out;
  } catch {
    return null;
  }
}

/** 自定义主题是否存在（决定主题栅格是否亮起 custom 卡） */
export function hasCustomTheme(): boolean {
  return loadCustomTheme() !== null;
}

/** 解析主题名 → 实际生效的主题（custom 不存在时回退 bluewhite），applyTheme 与 themeOf 共用 */
function resolveTheme(name: ThemeName): { applied: ThemeName; theme: Theme } {
  if (name === "custom") {
    const custom = loadCustomTheme();
    if (custom) return { applied: "custom", theme: custom };
    return { applied: "bluewhite", theme: THEMES.bluewhite };
  }
  return { applied: name, theme: THEMES[name] };
}

/** 把当前主题写到 <html data-theme> + --c-* CSS 变量上（custom 读 localStorage） */
export function applyTheme(name: ThemeName) {
  const root = document.documentElement;
  const { applied, theme } = resolveTheme(name);
  // data-theme 反映真正生效的调色板：custom 缺失时是 bluewhite，而不是留下无法解析的 "custom"
  root.dataset.theme = applied;
  for (const [k, v] of Object.entries(theme)) {
    root.style.setProperty(`--c-${kebab(k)}`, v);
  }
}

/** ECharts 等需要具体色值的场景直接取 token */
export function themeOf(name: ThemeName): Theme {
  return resolveTheme(name).theme;
}
