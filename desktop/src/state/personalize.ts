/**
 * 桌面个性化通知层：
 *  - 扫描完成音效（WebAudio 合成，零资源文件）
 *  - Windows 系统通知（Tauri notification 插件）
 *  - persona:// 协议 → asset:// 转换（自定义头像展示）
 *  全部 Tauri API 动态 import，浏览器 dev 模式静默降级。
 */
import type { OperatorConfig } from "../persona";

const IS_TAURI = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

/* ---------- 音效（WebAudio 合成，无音频文件） ---------- */

let audioCtx: AudioContext | null = null;
function getAudioCtx(): AudioContext | null {
  if (typeof window === "undefined") return null;
  const AC = window.AudioContext ?? (window as unknown as { webkitAudioContext?: typeof AudioContext }).webkitAudioContext;
  if (!AC) return null;
  if (!audioCtx) audioCtx = new AC();
  if (audioCtx.state === "suspended") void audioCtx.resume();
  return audioCtx;
}

function beep(ctx: AudioContext, freq: number, startMs: number, durMs: number, gain = 0.06) {
  const osc = ctx.createOscillator();
  const g = ctx.createGain();
  osc.type = "triangle";
  osc.frequency.value = freq;
  g.gain.setValueAtTime(0, ctx.currentTime + startMs / 1000);
  g.gain.linearRampToValueAtTime(gain, ctx.currentTime + startMs / 1000 + 0.012);
  g.gain.exponentialRampToValueAtTime(0.0008, ctx.currentTime + (startMs + durMs) / 1000);
  osc.connect(g);
  g.connect(ctx.destination);
  osc.start(ctx.currentTime + startMs / 1000);
  osc.stop(ctx.currentTime + (startMs + durMs) / 1000 + 0.02);
}

/** 扫描完成：C→G 高八度双音（C 大三和弦内，明亮） */
export function playScanDoneSound() {
  const ctx = getAudioCtx();
  if (!ctx) return;
  beep(ctx, 523.25, 0, 110);
  beep(ctx, 1046.5, 130, 300);
}

/** 发现 CONFIRMED：低音警示 */
export function playConfirmAlertSound() {
  const ctx = getAudioCtx();
  if (!ctx) return;
  beep(ctx, 311.13, 0, 140, 0.08);
  beep(ctx, 233.08, 150, 260, 0.08);
}

/** 主题切换轻提示音 */
export function playThemeTick() {
  const ctx = getAudioCtx();
  if (!ctx) return;
  beep(ctx, 1318.5, 0, 55, 0.03);
}

/* ---------- Windows 系统通知 ---------- */

async function ensurePermission(): Promise<boolean> {
  if (!IS_TAURI) return false;
  try {
    const mod = await import("@tauri-apps/plugin-notification");
    let perm = await mod.isPermissionGranted();
    if (!perm) {
      perm = (await mod.requestPermission()) === "granted";
    }
    return perm;
  } catch {
    return false;
  }
}

export async function notifyScanDone(
  op: OperatorConfig,
  info: { target: string; confirmed: number; safe: number; unknown: number; total: number },
) {
  if (!(IS_TAURI && op.speak)) return;
  if (!(await ensurePermission())) return;
  try {
    const mod = await import("@tauri-apps/plugin-notification");
    const who = op.callsign || "枚依";
    await mod.sendNotification({
      title: `${who} · 扫描完成`,
      body: `${info.target} —— CONFIRMED ${info.confirmed} / SAFE ${info.safe} / UNKNOWN ${info.unknown}（共 ${info.total} 条）`,
    });
  } catch {
    /* 通知失败不影响主流程 */
  }
}

/* ---------- 窗口图标重绘（预留：当前沿用打包图标） ---------- */

export async function refreshAppIcon(_op: OperatorConfig) {
  /* 图标重绘需要 canvas 对打包 PNG 的重着色管线，暂留空位；后续主题联动再启用 */
  void _op;
}

/* ---------- persona:// → asset:// 转换（自定义头像展示） ---------- */

export async function installPersonaProtocol() {
  if (!IS_TAURI) return;
  try {
    const { convertFileSrc } = await import("@tauri-apps/api/core");
    const w = window as unknown as { __rsPersonaConvert?: (p: string) => string };
    w.__rsPersonaConvert = (p: string) => convertFileSrc(p);
    // persona:// 前缀在 <img src> 上无法直接触发 JS —— MutationObserver 把它改写成 asset://
    const observer = new MutationObserver(() => {
      document.querySelectorAll('img[src^="persona://"]').forEach((el) => {
        const raw = (el as HTMLImageElement).src.replace(/^.*persona:\/\//, "");
        el.setAttribute("src", convertFileSrc(decodeURIComponent(raw)));
      });
    });
    observer.observe(document.documentElement, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ["src"],
    });
  } catch {
    /* noop */
  }
}
