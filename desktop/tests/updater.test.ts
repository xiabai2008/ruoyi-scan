import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// 桌面端在线更新服务：重点锁「浏览器调用不误报」「更新包下载进度/完成」两个边界。
// Tauri 插件在 jsdom 下不存在，必须 mock 后再走动态 import。

const checkMock = vi.fn();
const relaunchMock = vi.fn();
const installMock = vi.fn();

vi.mock("@tauri-apps/plugin-updater", () => ({ check: checkMock }));
vi.mock("@tauri-apps/plugin-process", () => ({ relaunch: relaunchMock }));

type Updater = typeof import("../src/services/updater");

async function freshUpdater(): Promise<Updater> {
  vi.resetModules();
  return import("../src/services/updater");
}

describe("桌面端在线更新", () => {
  beforeEach(() => {
    checkMock.mockReset();
    relaunchMock.mockReset();
    installMock.mockReset();
    delete (window as unknown as { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__;
  });

  afterEach(() => {
    delete (window as unknown as { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__;
  });

  it("非 Tauri 运行环境显式报错，不伪造结果", async () => {
    const updater = await freshUpdater();
    await expect(updater.checkForUpdate()).rejects.toThrow("不是桌面端");
  });

  it("没有更新时返回 null", async () => {
    (window as unknown as { __TAURI_INTERNALS__: unknown }).__TAURI_INTERNALS__ = {};
    checkMock.mockResolvedValue(null);
    const updater = await freshUpdater();
    await expect(updater.checkForUpdate()).resolves.toBeNull();
  });

  it("有更新时返回版本信息，下载完成后再重启", async () => {
    (window as unknown as { __TAURI_INTERNALS__: unknown }).__TAURI_INTERNALS__ = {};
    checkMock.mockResolvedValue({
      currentVersion: "2.0.0",
      version: "2.1.0",
      date: "2026-11-20",
      body: "fixes",
      downloadAndInstall: installMock,
    });
    installMock.mockImplementation(async (cb: (event: { event: string; data?: { contentLength?: number; chunkLength?: number } }) => void) => {
      cb({ event: "Started", data: { contentLength: 100 } });
      cb({ event: "Progress", data: { chunkLength: 40 } });
      cb({ event: "Finished" });
    });
    const updater = await freshUpdater();
    const info = await updater.checkForUpdate();
    expect(info).toEqual({ currentVersion: "2.0.0", version: "2.1.0", date: "2026-11-20", body: "fixes" });

    const progress: Array<number | null> = [];
    await updater.installPendingUpdate((percent) => progress.push(percent));
    expect(installMock).toHaveBeenCalledTimes(1);
    expect(relaunchMock).toHaveBeenCalledTimes(1);
    expect(progress).toContain(40);
    expect(progress[progress.length - 1]).toBe(100);
  });

  it("未检查更新就安装时拒绝执行", async () => {
    (window as unknown as { __TAURI_INTERNALS__: unknown }).__TAURI_INTERNALS__ = {};
    const updater = await freshUpdater();
    await expect(updater.installPendingUpdate()).rejects.toThrow("没有待安装");
  });
});
