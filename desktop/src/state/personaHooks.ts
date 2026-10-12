/**
 * 人格事件桥 —— useScanConsole（React hook 外不可用 context）与人格通知层的单向桥。
 * 通过 window 事件解耦：hook 触发 → PersonaProvider 内监听分发（say/音效/系统通知）。
 */
import { defaultOperator, type OperatorConfig } from "../persona";
import type { MeiSay } from "./PersonaCtx";

const EVT_DONE = "rs:scan-done";
const EVT_CONFIRM = "rs:confirm-alert";

export interface ScanDoneInfo {
  target: string;
  total: number;
  confirmed: number;
  duration: number;
}

export function fireScanDone(info: ScanDoneInfo) {
  window.dispatchEvent(new CustomEvent(EVT_DONE, { detail: info }));
}

export function fireConfirmAlert(name: string) {
  window.dispatchEvent(new CustomEvent(EVT_CONFIRM, { detail: { name } }));
}

/** PersonaProvider 挂载时调用：把桥事件转成播报 + 音效 + 系统通知 */
export function bindPersonaEvents(
  say: (text: string, tone?: MeiSay["tone"]) => void,
  getCurrent: () => { speak: boolean; sound: boolean; callsign: string },
) {
  const onDone = (e: Event) => {
    // detail 可能缺失/形态异常（第三方派发或历史负载），先防御再使用
    const info = (e as CustomEvent<Partial<ScanDoneInfo> | undefined>).detail;
    if (!info || typeof info !== "object") return;
    const total = Number(info.total) || 0;
    const confirmed = Number(info.confirmed) || 0;
    const cur = getCurrent();
    // 默认代号的唯一来源在 persona.ts：不要再硬编码字面量，避免默认值改动后分叉
    const def = defaultOperator();
    const who = cur.callsign || def.callsign;
    const hot = confirmed > 0;
    say(
      hot
        ? `扫描完成！发现 ${confirmed} 个已确认问题，快看报告吧！`
        : `本轮扫描完成，共 ${total} 条结果，暂无确认项，安全！`,
      hot ? "confirm" : "safe",
    );
    void (async () => {
      // personalize chunk 只动态加载一次：音效与系统通知共用（失败静默降级）
      const m = await import("./personalize").catch(() => null);
      if (!m) return;
      if (cur.sound) {
        try {
          m.playScanDoneSound();
        } catch {
          /* 音效失败不影响播报 */
        }
      }
      // 桥只知道 speak/sound/callsign，其余字段取默认值补全为完整 OperatorConfig，
      // 不用 as 断言绕过编译器（否则 notifyScanDone 读其他字段时会静默拿到 undefined）
      const op: OperatorConfig = { ...def, callsign: who, speak: cur.speak, sound: cur.sound };
      await m.notifyScanDone(op, {
        target: String(info.target ?? ""),
        confirmed,
        safe: Math.max(0, total - confirmed),
        unknown: 0,
        total,
      });
    })().catch(() => { /* notifyScanDone 内部已兜底，这里防御意外异常 */ });
  };
  const onConfirm = (e: Event) => {
    const detail = (e as CustomEvent<{ name?: unknown } | undefined>).detail;
    const name = typeof detail?.name === "string" ? detail.name : "";
    if (!name) return; // detail 缺失时直接忽略，避免监听器内抛 TypeError
    say(`发现已确认问题：${name}`, "confirm");
    if (getCurrent().sound) {
      void import("./personalize").then((m) => m.playConfirmAlertSound()).catch(() => { /* chunk 加载失败静默降级 */ });
    }
  };
  window.addEventListener(EVT_DONE, onDone);
  window.addEventListener(EVT_CONFIRM, onConfirm);
  return () => {
    window.removeEventListener(EVT_DONE, onDone);
    window.removeEventListener(EVT_CONFIRM, onConfirm);
  };
}
