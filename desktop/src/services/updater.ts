/** 桌面端在线更新（Tauri updater）。
 *
 * 只在 Tauri 运行时调用；浏览器/vitest 下动态 import 会失败，调用方负责捕获并显示
 * 可读错误。更新包由 Tauri 使用内置公钥验证签名，未签名/签名错误会在插件层拒绝。
 */

export type UpdateInfo = {
  currentVersion: string;
  version: string;
  date?: string;
  body?: string;
};

type ProgressEvent = {
  event: "Started" | "Progress" | "Finished";
  data?: { contentLength?: number; chunkLength?: number };
};

type PendingUpdate = {
  currentVersion: string;
  version: string;
  date?: string;
  body?: string;
  downloadAndInstall: (cb?: (event: ProgressEvent) => void) => Promise<void>;
};

let pending: PendingUpdate | null = null;

export function isTauriRuntime(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

export async function checkForUpdate(): Promise<UpdateInfo | null> {
  if (!isTauriRuntime()) {
    throw new Error("当前不是桌面端运行环境，无法检查桌面更新");
  }
  const mod = await import("@tauri-apps/plugin-updater");
  const update = await mod.check();
  if (!update) {
    pending = null;
    return null;
  }
  const candidate = update as unknown as PendingUpdate;
  pending = candidate;
  return {
    currentVersion: candidate.currentVersion,
    version: candidate.version,
    date: candidate.date,
    body: candidate.body,
  };
}

export async function installPendingUpdate(
  onProgress?: (percent: number | null, downloaded: number, total: number | null) => void,
): Promise<void> {
  if (!pending) throw new Error("没有待安装的更新，请先检查更新");
  let downloaded = 0;
  let total: number | null = null;
  await pending.downloadAndInstall((event) => {
    if (event.event === "Started") {
      total = event.data?.contentLength ?? null;
      onProgress?.(total ? 0 : null, 0, total);
    } else if (event.event === "Progress") {
      downloaded += event.data?.chunkLength ?? 0;
      onProgress?.(total ? Math.min(100, Math.round((downloaded / total) * 100)) : null, downloaded, total);
    } else {
      onProgress?.(100, downloaded, total);
    }
  });
  const { relaunch } = await import("@tauri-apps/plugin-process");
  pending = null;
  await relaunch();
}
