/**
 * 桌面个性化通知层：
 *  - 扫描完成音效（WebAudio 合成，零资源文件）
 *  - Windows 系统通知（Tauri notification 插件）
 *  - persona:// 协议 → asset:// 转换（自定义头像展示）
 *  全部 Tauri API 动态 import，浏览器 dev 模式静默降级。
 */
import { assetFor } from "../assets/avatars";
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
  } catch (e) {
    // 权限申请失败可见化：插件缺失/权限配置错误时不再无声无息
    console.warn("[persona] 系统通知权限查询/申请失败", e);
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
  } catch (e) {
    // 通知发送失败不影响主流程，但必须留下诊断线索
    console.warn("[persona] 系统通知发送失败", e);
  }
}

/* ---------- 窗口图标重绘（预留：当前沿用打包图标） ---------- */

export async function refreshAppIcon(_op: OperatorConfig) {
  /* 图标重绘需要 canvas 对打包 PNG 的重着色管线，暂留空位；后续主题联动再启用 */
  void _op;
}

/* ---------- persona:// → asset:// 转换（自定义头像展示） ---------- */

/** 默认形象（内置资源，离线可用）：自定义头像加载失败时回退，避免碎图 */
const DEFAULT_PERSONA_AVATAR = assetFor("avatar_v01_lookback_smile.jpg");

/** 为转换后的自定义头像挂一次性错误回退（重启后 asset 作用域不含原路径时会加载失败） */
function attachPersonaAvatarFallback(el: HTMLImageElement) {
  if (el.dataset.rsFallback === "1") return;
  el.dataset.rsFallback = "1";
  el.addEventListener(
    "error",
    () => {
      if (DEFAULT_PERSONA_AVATAR && el.src !== DEFAULT_PERSONA_AVATAR) {
        console.warn("[persona] 头像加载失败，已回退默认形象:", el.src);
        el.src = DEFAULT_PERSONA_AVATAR;
      }
    },
    { once: true },
  );
}

/** 单个 persona:// img → asset://；非法 percent 编码（如 persona://%）跳过该图 */
function rewritePersonaImg(el: HTMLImageElement, convertFileSrc: (p: string) => string) {
  const src = el.getAttribute("src") || "";
  if (!src.startsWith("persona://")) return;
  try {
    el.setAttribute("src", convertFileSrc(decodeURIComponent(src.slice("persona://".length))));
    attachPersonaAvatarFallback(el);
  } catch {
    /* URIError：保留原 src，不让异常冒泡到 MutationObserver 回调 */
  }
}

/** 只扫描变更子树（新增节点 / 自身），避免每次 mutation 都全文档 querySelectorAll */
function rewritePersonaTree(root: Node, convertFileSrc: (p: string) => string) {
  if (!(root instanceof Element)) return;
  if (root instanceof HTMLImageElement) rewritePersonaImg(root, convertFileSrc);
  root
    .querySelectorAll('img[src^="persona://"]')
    .forEach((el) => rewritePersonaImg(el as HTMLImageElement, convertFileSrc));
}

export async function installPersonaProtocol() {
  if (!IS_TAURI) return;
  try {
    const { convertFileSrc } = await import("@tauri-apps/api/core");
    const w = window as unknown as {
      __rsPersonaConvert?: (p: string) => string;
      __rsPersonaObserver?: MutationObserver;
    };
    w.__rsPersonaConvert = (p: string) => convertFileSrc(p);
    // 幂等：React StrictMode 双调用 / HMR 重复执行时复用已安装的 observer，避免观察器泄漏
    if (w.__rsPersonaObserver) return;
    // 首次安装补扫一次现有 DOM（挂载早于本函数时 <img> 已经渲染）
    rewritePersonaTree(document.documentElement, convertFileSrc);
    const observer = new MutationObserver((mutations) => {
      for (const m of mutations) {
        if (m.type === "attributes") {
          if (m.target instanceof HTMLImageElement) rewritePersonaImg(m.target, convertFileSrc);
          continue;
        }
        m.addedNodes.forEach((n) => rewritePersonaTree(n, convertFileSrc));
      }
    });
    observer.observe(document.documentElement, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ["src"],
    });
    w.__rsPersonaObserver = observer;
  } catch {
    /* noop */
  }
}
