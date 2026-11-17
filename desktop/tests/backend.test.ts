import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// 后端服务层（src/services/backend.ts）
//
// 这层决定「引擎没起 / 请求超时 / 后端返回 500」时用户看到什么。旧版没有超时，
// 引擎离线时 fetch 会一直挂着，UI 永久停在「提交中…」（测评 P1-7）；issue #66
// 的桌面端白屏也出在这条链路上。所以重点锁错误映射，而不是 happy path。

type Backend = typeof import("../src/services/backend");

/** 每个用例拿一份全新的模块状态（memApiBase / warnedSev 都是模块级变量） */
async function freshBackend(): Promise<Backend> {
  vi.resetModules();
  return import("../src/services/backend");
}

const jsonResponse = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });

describe("apiBase 存取与订阅", () => {
  let be: Backend;

  beforeEach(async () => {
    localStorage.clear();
    be = await freshBackend();
  });

  it("无配置时用默认 127.0.0.1:8123", () => {
    expect(be.getApiBase()).toBe(be.DEFAULT_API_BASE);
    expect(be.DEFAULT_API_BASE).toBe("http://127.0.0.1:8123");
  });

  it("localStorage 里的地址优先于默认值", async () => {
    localStorage.setItem("ruoyi-scan.apiBase", "http://10.0.0.9:9000");
    be = await freshBackend();
    expect(be.getApiBase()).toBe("http://10.0.0.9:9000");
  });

  it("setApiBase 去掉尾部斜杠，避免拼出 //api/...", () => {
    be.setApiBase("http://10.0.0.9:9000///");
    expect(be.getApiBase()).toBe("http://10.0.0.9:9000");
  });

  it("setApiBase 持久化到 localStorage", () => {
    be.setApiBase("http://10.0.0.9:9000");
    expect(localStorage.getItem("ruoyi-scan.apiBase")).toBe("http://10.0.0.9:9000");
  });

  it("地址变更通知所有订阅者", () => {
    const a = vi.fn();
    const b = vi.fn();
    be.subscribeApiBase(a);
    be.subscribeApiBase(b);
    be.setApiBase("http://10.0.0.9:9000");
    expect(a).toHaveBeenCalledWith("http://10.0.0.9:9000");
    expect(b).toHaveBeenCalledWith("http://10.0.0.9:9000");
  });

  it("取消订阅后不再收到通知", () => {
    const fn = vi.fn();
    const off = be.subscribeApiBase(fn);
    off();
    be.setApiBase("http://10.0.0.9:9000");
    expect(fn).not.toHaveBeenCalled();
  });

  it("单个订阅者抛错不影响其他订阅者（地址已生效，界面不能一起崩）", () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    const bad = vi.fn(() => {
      throw new Error("boom");
    });
    const good = vi.fn();
    be.subscribeApiBase(bad);
    be.subscribeApiBase(good);
    expect(() => be.setApiBase("http://10.0.0.9:9000")).not.toThrow();
    expect(good).toHaveBeenCalled();
    expect(spy).toHaveBeenCalled();
  });

  it("localStorage 不可用时 setApiBase 不抛错（仍在本会话生效）", async () => {
    const setItem = vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("QuotaExceededError");
    });
    expect(() => be.setApiBase("http://10.0.0.9:9000")).not.toThrow();
    expect(be.getApiBase()).toBe("http://10.0.0.9:9000");
    setItem.mockRestore();
  });
});

describe("HTTP 层错误映射", () => {
  let be: Backend;

  beforeEach(async () => {
    localStorage.clear();
    be = await freshBackend();
    be.setApiBase("http://engine.test:8123");
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it("成功时返回解析后的 JSON，并带上默认 Content-Type", async () => {
    const fetchMock = vi.fn(async () => jsonResponse({ status: "ok", version: "1.8.0", uptime: 42 }));
    vi.stubGlobal("fetch", fetchMock);

    await expect(be.api.health()).resolves.toEqual({ status: "ok", version: "1.8.0", uptime: 42 });

    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("http://engine.test:8123/api/system/health");
    expect((init.headers as Record<string, string>)["Content-Type"]).toBe("application/json");
  });

  it("调用方 headers 与默认头合并，不整体覆盖（避免丢 Content-Type）", async () => {
    const fetchMock = vi.fn(async () => jsonResponse({ ok: true }));
    vi.stubGlobal("fetch", fetchMock);

    await be.api.health();

    const init = (fetchMock.mock.calls[0] as unknown as [string, RequestInit])[1];
    expect(init.headers).toEqual({ "Content-Type": "application/json" });
  });

  it("请求超时抛 ApiError(0)，文案要说清引擎可能没起", async () => {
    vi.useFakeTimers();
    vi.stubGlobal("fetch", (_url: string, init?: RequestInit) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () =>
          reject(new DOMException("aborted", "AbortError")),
        );
      }),
    );

    const pending = be.api.health().catch((e: unknown) => e);
    await vi.advanceTimersByTimeAsync(6_000); // health 的超时是 6s
    const err = await pending;

    expect(err).toBeInstanceOf(be.ApiError);
    expect((err as InstanceType<Backend["ApiError"]>).status).toBe(0);
    expect(String((err as Error).message)).toContain("请求超时");
    expect(String((err as Error).message)).toContain("引擎可能未启动");
  });

  it("连接失败（TypeError）抛 ApiError(0) 并回显当前地址", async () => {
    vi.stubGlobal("fetch", async () => {
      throw new TypeError("Failed to fetch");
    });

    const err = await be.api.health().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(be.ApiError);
    expect((err as Error).message).toContain("无法连接引擎");
    expect((err as Error).message).toContain("http://engine.test:8123");
  });

  it("非 2xx 时优先用后端 detail 作为文案", async () => {
    vi.stubGlobal("fetch", async () => jsonResponse({ detail: "目标格式非法" }, 400));

    const err = await be.api.listTasks().catch((e: unknown) => e);
    expect((err as InstanceType<Backend["ApiError"]>).status).toBe(400);
    expect((err as Error).message).toBe("目标格式非法");
  });

  it("detail 是对象时序列化，不显示 [object Object]", async () => {
    vi.stubGlobal("fetch", async () => jsonResponse({ detail: { field: "target" } }, 422));

    const err = await be.api.listTasks().catch((e: unknown) => e);
    expect((err as Error).message).toBe('{"field":"target"}');
  });

  it("响应体不是 JSON 时退回 HTTP 状态码文案", async () => {
    vi.stubGlobal(
      "fetch",
      async () => new Response("<html>502 Bad Gateway</html>", { status: 502 }),
    );

    const err = await be.api.listTasks().catch((e: unknown) => e);
    expect((err as InstanceType<Backend["ApiError"]>).status).toBe(502);
    expect((err as Error).message).toBe("HTTP 502");
  });

  it("target 经 encodeURIComponent 拼进 query，特殊字符不破坏 URL", async () => {
    const fetchMock = vi.fn(async () =>
      jsonResponse({ target: "x", cms: "", version: "", confidence: 0, matched: [], waf: "", waf_display: "" }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await be.api.fingerprint("http://a.com/?x=1&y=2#frag");

    const url = (fetchMock.mock.calls[0] as unknown as [string])[0];
    expect(url).toContain("target=http%3A%2F%2Fa.com%2F%3Fx%3D1%26y%3D2%23frag");
    expect(url).not.toContain("#frag");
  });
});

describe("Prometheus 指标解析", () => {
  let be: Backend;

  const TEXT = [
    "# HELP ruoyi_scan_uptime_seconds 引擎运行时长",
    "# TYPE ruoyi_scan_uptime_seconds gauge",
    "ruoyi_scan_uptime_seconds 3600.0",
    "ruoyi_scan_tasks_active 2",
    "ruoyi_scan_tasks_total{status=\"done\"} 12",
    "ruoyi_scan_tasks_total{status=\"running\"} 2",
    "ruoyi_scan_results_total{status=\"CONFIRMED\"} 7",
    "ruoyi_scan_results_total{status=\"SAFE\"} 30",
    "ruoyi_scan_storage_tasks 5",
  ].join("\n");

  beforeEach(async () => {
    localStorage.clear();
    be = await freshBackend();
    be.setApiBase("http://engine.test:8123");
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("解析 uptime / active / 按 status 分组的 series", async () => {
    vi.stubGlobal("fetch", async () => new Response(TEXT, { status: 200 }));

    const m = await be.fetchMetrics();
    expect(m.uptime).toBe(3600);
    expect(m.active).toBe(2);
    expect(m.tasks).toEqual({ done: 12, running: 2 });
    expect(m.results).toEqual({ CONFIRMED: 7, SAFE: 30 });
    expect(m.storageTasks).toBe(5);
  });

  it("缺失的可选指标返回 null 而不是 0（区分「未启用」与「真的是 0」）", async () => {
    vi.stubGlobal(
      "fetch",
      async () => new Response("ruoyi_scan_uptime_seconds 10\n", { status: 200 }),
    );

    const m = await be.fetchMetrics();
    expect(m.storageTasks).toBeNull();
    expect(m.uptime).toBe(10);
    expect(m.tasks).toEqual({});
  });

  it("标签顺序变化时 series 解析为空——这是已知契约脆弱点", async () => {
    // 后端若把 status 放到非首位标签，seriesOf 静默返回 {}，图表会显示全 0。
    // 这里固定现状，逼以后改格式时有人来改这条用例。
    vi.stubGlobal(
      "fetch",
      async () => new Response('ruoyi_scan_tasks_total{app="x",status="done"} 12\n', { status: 200 }),
    );

    const m = await be.fetchMetrics();
    expect(m.tasks).toEqual({});
  });

  it("引擎连不上时 fetchMetrics 抛 ApiError(0)", async () => {
    vi.stubGlobal("fetch", async () => {
      throw new TypeError("Failed to fetch");
    });

    const err = await be.fetchMetrics().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(be.ApiError);
    expect((err as Error).message).toContain("无法连接引擎");
  });

  it("指标端点返回 500 时抛 ApiError(500)", async () => {
    vi.stubGlobal("fetch", async () => new Response("boom", { status: 500 }));

    const err = await be.fetchMetrics().catch((e: unknown) => e);
    expect((err as InstanceType<Backend["ApiError"]>).status).toBe(500);
  });
});

describe("展示层纯函数", () => {
  let be: Backend;

  beforeEach(async () => {
    be = await freshBackend();
  });

  it("severity 映射覆盖后端三档", () => {
    expect(be.sevToUi("high")).toBe("HIGH");
    expect(be.sevToUi("medium")).toBe("MED");
    expect(be.sevToUi("low")).toBe("LOW");
  });

  it("severity 大小写不敏感", () => {
    expect(be.sevToUi("HIGH")).toBe("HIGH");
  });

  it("未知 severity 不静默降成 LOW（会把高危显示成低危），按 MED 并告警一次", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    expect(be.sevToUi("urgent")).toBe("MED");
    expect(be.sevToUi("urgent")).toBe("MED");
    expect(warn).toHaveBeenCalledTimes(1); // 同一个未知值只告警一次，避免刷屏
    warn.mockRestore();
  });

  it("CVE 占位符不算有效编号", () => {
    for (const v of ["", null, undefined, "N/A", "n/a", "none", "null", "-", "—", "   "]) {
      expect(be.hasCve(v as string | null | undefined)).toBe(false);
    }
    expect(be.hasCve("CVE-2024-1234")).toBe(true);
  });

  it("fmtDuration 补零且负数归零", () => {
    expect(be.fmtDuration(0)).toBe("00:00:00");
    expect(be.fmtDuration(59)).toBe("00:00:59");
    expect(be.fmtDuration(61)).toBe("00:01:01");
    expect(be.fmtDuration(3661)).toBe("01:01:01");
    expect(be.fmtDuration(-5)).toBe("00:00:00");
    expect(be.fmtDuration(59.9)).toBe("00:00:59"); // 向下取整，不四舍五入进位
  });

  it("fmtClock 把秒级时间戳渲染成 HH:MM:SS", () => {
    const ts = new Date(2026, 10, 18, 9, 5, 3).getTime() / 1000;
    expect(be.fmtClock(ts)).toBe("09:05:03");
  });

  it("任务状态文案与颜色覆盖全部状态（新增状态不许漏配）", () => {
    const statuses = ["pending", "running", "done", "failed", "cancelled", "interrupted"];
    for (const s of statuses) {
      expect(be.TASK_STATUS_LABEL[s]).toBeTruthy();
      expect(be.TASK_STATUS_COLOR[s]).toBeTruthy();
    }
  });

  it("四种扫描模式都有中文标签", () => {
    for (const m of ["u", "m", "p", "l"] as const) {
      expect(be.MODE_LABEL[m]).toBeTruthy();
    }
  });
});
