import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// 报告导出（src/services/export.ts）
//
// 旧实现用 <a target="_blank">，在 Tauri 2 里点了既不开窗也不下载（测评 P1-4）；
// 另一条踩坑是裸 fetch 无超时，引擎卡死时 busyKey 永不清空，所有报告按钮
// 变灰只能重启窗口。这两条都直接影响「扫描完拿不到交付物」，必须锁住。

const invokeMock = vi.hoisted(() => vi.fn());
vi.mock("@tauri-apps/api/core", () => ({ invoke: invokeMock }));

import { saveReport, revealPath, isTauri } from "../src/services/export";

const okResponse = (bytes: number[] = [1, 2, 3]) =>
  new Response(new Uint8Array(bytes), { status: 200 });

function setTauri(on: boolean) {
  if (on) {
    (window as unknown as Record<string, unknown>).__TAURI_INTERNALS__ = {};
  } else {
    delete (window as unknown as Record<string, unknown>).__TAURI_INTERNALS__;
  }
}

const URLCtor = URL;

beforeEach(() => {
  setTauri(false);
  invokeMock.mockReset();
  vi.stubGlobal(
    "URL",
    Object.assign(URLCtor, {
      createObjectURL: vi.fn(() => "blob:mock-url"),
      revokeObjectURL: vi.fn(),
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
  setTauri(false);
  vi.restoreAllMocks();
});

describe("运行环境判定", () => {
  it("没有 __TAURI_INTERNALS__ 时按浏览器处理", () => {
    setTauri(false);
    expect(isTauri()).toBe(false);
  });

  it("存在 __TAURI_INTERNALS__ 时按 Tauri 处理", () => {
    setTauri(true);
    expect(isTauri()).toBe(true);
  });
});

describe("saveReport — 浏览器回退", () => {
  it("下载字节并触发带正确文件名的 <a download>", async () => {
    const fetchMock = vi.fn(async () => okResponse([1, 2, 3]));
    vi.stubGlobal("fetch", fetchMock);
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});

    const name = await saveReport("t-001", "html");

    expect(name).toBe("t-001_report.html");
    expect(click).toHaveBeenCalledTimes(1);

    const url = (fetchMock.mock.calls[0] as unknown as [string])[0];
    expect(url).toContain("/api/report/t-001/html");
  });

  it("task id 含特殊字符时被 URL 编码", async () => {
    const fetchMock = vi.fn(async () => okResponse());
    vi.stubGlobal("fetch", fetchMock);
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});

    await saveReport("a/b c", "csv");

    const url = (fetchMock.mock.calls[0] as unknown as [string])[0];
    expect(url).toContain("/api/report/a%2Fb%20c/csv");
  });

  it("非 2xx 时优先用后端 detail 作错误文案", async () => {
    vi.stubGlobal(
      "fetch",
      async () =>
        new Response(JSON.stringify({ detail: "报告尚未生成" }), {
          status: 404,
          headers: { "Content-Type": "application/json" },
        }),
    );

    await expect(saveReport("t-001", "pdf")).rejects.toThrow("报告尚未生成");
  });

  it("非 2xx 且响应体非 JSON 时退回 HTTP 状态码", async () => {
    vi.stubGlobal("fetch", async () => new Response("<html>500</html>", { status: 500 }));
    await expect(saveReport("t-001", "pdf")).rejects.toThrow("HTTP 500");
  });

  it("下载超时给出可操作文案（否则报告按钮会永久变灰）", async () => {
    vi.useFakeTimers();
    vi.stubGlobal("fetch", (_url: string, init?: RequestInit) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
      }),
    );

    const pending = saveReport("t-001", "pdf").catch((e: unknown) => e);
    await vi.advanceTimersByTimeAsync(120_000);
    const err = await pending;

    expect(String((err as Error).message)).toContain("报告下载超时");
    expect(String((err as Error).message)).toContain("引擎是否仍在运行");
    vi.useRealTimers();
  });
});

describe("saveReport — Tauri 原生保存", () => {
  beforeEach(() => setTauri(true));

  it("走 save_report 命令并回传真实落盘路径", async () => {
    vi.stubGlobal("fetch", async () => okResponse([1, 2, 3]));
    invokeMock.mockResolvedValue("D:\\reports\\t-001_report.pdf");
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});

    const path = await saveReport("t-001", "pdf");

    expect(path).toBe("D:\\reports\\t-001_report.pdf");
    expect(invokeMock).toHaveBeenCalledWith("save_report", {
      defaultName: "t-001_report.pdf",
      dataB64: btoa(String.fromCharCode(1, 2, 3)),
    });
    expect(click).not.toHaveBeenCalled(); // 原生保存时不触发浏览器下载
  });

  it("用户取消保存时返回空串，不算失败", async () => {
    vi.stubGlobal("fetch", async () => okResponse());
    invokeMock.mockResolvedValue("");

    await expect(saveReport("t-001", "docx")).resolves.toBe("");
  });

  it("大文件按 32KB 分块编码，不因参数过多爆栈", async () => {
    // 64KB 数据：一次性 String.fromCharCode(...bytes) 会超出调用参数上限
    const big = new Array(65536).fill(0x41);
    vi.stubGlobal("fetch", async () => okResponse(big));
    invokeMock.mockResolvedValue("/tmp/x");

    await saveReport("t-001", "xlsx");

    const arg = invokeMock.mock.calls[0][1] as { dataB64: string };
    expect(atob(arg.dataB64).length).toBe(65536);
    expect(atob(arg.dataB64).charAt(0)).toBe("A");
  });
});

describe("revealPath", () => {
  it("非 Tauri 环境直接返回，不调 invoke", async () => {
    setTauri(false);
    await revealPath("D:\\a.pdf");
    expect(invokeMock).not.toHaveBeenCalled();
  });

  it("路径为空时直接返回", async () => {
    setTauri(true);
    await revealPath("");
    expect(invokeMock).not.toHaveBeenCalled();
  });

  it("Tauri 下调 reveal_path 定位文件", async () => {
    setTauri(true);
    invokeMock.mockResolvedValue(undefined);
    await revealPath("D:\\a.pdf");
    expect(invokeMock).toHaveBeenCalledWith("reveal_path", { path: "D:\\a.pdf" });
  });
});
