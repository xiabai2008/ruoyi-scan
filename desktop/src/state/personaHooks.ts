/**
 * 人格事件桥 —— useScanConsole（React hook 外不可用 context）与人格通知层的单向桥。
 * 通过 window 事件解耦：hook 触发 → PersonaProvider 内监听分发（say/音效/系统通知）。
 */
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
    const info = (e as CustomEvent<ScanDoneInfo>).detail;
    const who = getCurrent().callsign || "枚依";
    const hot = info.confirmed > 0;
    say(
      hot
        ? `扫描完成！发现 ${info.confirmed} 个已确认问题，快看报告吧！`
        : `本轮扫描完成，共 ${info.total} 条结果，暂无确认项，安全！`,
      hot ? "confirm" : "safe",
    );
    if (getCurrent().sound) {
      void import("./personalize").then((m) => m.playScanDoneSound());
    }
    void import("./personalize").then(async (m) => {
      const op = { callsign: who, speak: getCurrent().speak } as Parameters<typeof m.notifyScanDone>[0];
      await m.notifyScanDone(op, {
        target: info.target,
        confirmed: info.confirmed,
        safe: Math.max(0, info.total - info.confirmed),
        unknown: 0,
        total: info.total,
      });
    });
  };
  const onConfirm = (e: Event) => {
    const { name } = (e as CustomEvent<{ name: string }>).detail;
    say(`发现已确认问题：${name}`, "confirm");
    if (getCurrent().sound) {
      void import("./personalize").then((m) => m.playConfirmAlertSound());
    }
  };
  window.addEventListener(EVT_DONE, onDone);
  window.addEventListener(EVT_CONFIRM, onConfirm);
  return () => {
    window.removeEventListener(EVT_DONE, onDone);
    window.removeEventListener(EVT_CONFIRM, onConfirm);
  };
}
