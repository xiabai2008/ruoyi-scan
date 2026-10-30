/**
 * 报告导出：Tauri 原生保存对话框 + 浏览器下载回退。
 *
 * 旧报告中心的 `<a target="_blank">` 在 Tauri 2 里没有 on_new_window 处理，
 * 点击后无新窗口、无外部浏览器、无下载（测评 P1-4）。这里改为：
 *   fetch 报告字节 → Tauri 命令弹原生保存框并写盘 → 返回真实路径；
 *   dev/浏览器环境回退 Blob 下载。
 */
import { api } from "./backend";

export function isTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

function toBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

async function readError(res: Response): Promise<string> {
  try {
    const body = await res.json();
    if (body?.detail) return typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
  } catch {
    /* ignore */
  }
  return `HTTP ${res.status}`;
}

/** 保存报告；返回保存路径（用户取消返回空串，浏览器回退返回文件名） */
export async function saveReport(taskId: string, fmt: string): Promise<string> {
  const res = await fetch(api.reportDownloadUrl(taskId, fmt));
  if (!res.ok) throw new Error(await readError(res));
  const buffer = await res.arrayBuffer();
  const name = `${taskId}_report.${fmt}`;

  if (isTauri()) {
    const { invoke } = await import("@tauri-apps/api/core");
    const path = await invoke<string>("save_report", {
      defaultName: name,
      dataB64: toBase64(buffer),
    });
    return path || "";
  }

  // 浏览器回退：Blob + 临时 <a download>
  const url = URL.createObjectURL(new Blob([buffer]));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  return name;
}

/** 在文件管理器中定位已保存的报告 */
export async function revealPath(path: string): Promise<void> {
  if (!isTauri() || !path) return;
  const { invoke } = await import("@tauri-apps/api/core");
  await invoke("reveal_path", { path });
}
