import { act, renderHook, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { EngineInfo, ScanTask } from "../src/services/backend";

// 全局应用状态（src/state/AppCtx.tsx）
//
// 这层每个 useEffect 的注释背后都是一次真实事故：健康检查乱序覆盖、
// 任务列表引用变化导致请求风暴、关掉的任务刷新后又冒出来、改服务地址后
// 界面还显示旧地址。桌面端下载量最高，这些坑复发就是用户侧白屏/卡死。
// 所以这里按「事故」写用例，不按函数分支写。

const h = vi.hoisted(() => ({
  health: vi.fn(),
  version: vi.fn(),
  listTasks: vi.fn(),
  submitScan: vi.fn(),
}));

vi.mock("../src/services/backend", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/services/backend")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      health: h.health,
      version: h.version,
      listTasks: h.listTasks,
      submitScan: h.submitScan,
    },
  };
});

import { AppProvider, useApp } from "../src/state/AppCtx";

const ENGINE: EngineInfo = { version: "1.8.0", python: "3.12.9", platform: "win32", uptime: 10 } as EngineInfo;

const task = (id: string, over: Partial<ScanTask> = {}): ScanTask =>
  ({
    task_id: id,
    status: "done",
    target: `http://${id}.test/`,
    mode: "u",
    started_at: 100,
    finished_at: 200,
    duration: 100,
    request_count: 1,
    result_count: 3,
    confirmed_count: 1,
    safe_count: 1,
    unknown_count: 1,
    error: "",
    fingerprint: null,
    waf: null,
    report_paths: [],
    ...over,
  }) as ScanTask;

const wrapper = ({ children }: { children: ReactNode }) => <AppProvider>{children}</AppProvider>;

function deferred<T>() {
  let resolve!: (v: T) => void;
  const promise = new Promise<T>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}

beforeEach(() => {
  localStorage.clear();
  h.health.mockReset().mockResolvedValue({ status: "ok", version: "1.8.0", uptime: 10 });
  h.version.mockReset().mockResolvedValue(ENGINE);
  h.listTasks.mockReset().mockResolvedValue([]);
  h.submitScan.mockReset().mockResolvedValue({ task_id: "new-1", status: "pending" });
});

describe("Provider 契约", () => {
  it("useApp 在 Provider 外使用时抛出可定位的错误，而不是静默拿到空对象", () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    expect(() => renderHook(() => useApp())).toThrow(/useApp 必须在 AppProvider 内使用/);
    spy.mockRestore();
  });
});

describe("主题", () => {
  it("无存档时默认 bluewhite", () => {
    const { result } = renderHook(() => useApp(), { wrapper });
    expect(result.current.theme).toBe("bluewhite");
  });

  it("合法存档被恢复", () => {
    localStorage.setItem("rs.theme", "mintfresh");
    const { result } = renderHook(() => useApp(), { wrapper });
    expect(result.current.theme).toBe("mintfresh");
  });

  it("非法存档回退默认，不把脏值直接塞给主题系统", () => {
    localStorage.setItem("rs.theme", "not-a-theme");
    const { result } = renderHook(() => useApp(), { wrapper });
    expect(result.current.theme).toBe("bluewhite");
  });

  it("setTheme 写盘", () => {
    const { result } = renderHook(() => useApp(), { wrapper });
    act(() => result.current.setTheme("creampop"));
    expect(result.current.theme).toBe("creampop");
    expect(localStorage.getItem("rs.theme")).toBe("creampop");
  });

  it("重复选 custom 也让 customRev 自增（否则换调色板后界面一个像素都不变）", () => {
    const { result } = renderHook(() => useApp(), { wrapper });
    act(() => result.current.setTheme("custom"));
    const rev1 = result.current.customRev;
    act(() => result.current.setTheme("custom"));
    expect(result.current.customRev).toBe(rev1 + 1);
  });

  it("切到非 custom 主题不触发 customRev", () => {
    const { result } = renderHook(() => useApp(), { wrapper });
    const rev = result.current.customRev;
    act(() => result.current.setTheme("darkneon"));
    expect(result.current.customRev).toBe(rev);
  });
});

describe("任务栏隐藏（dismissed）", () => {
  it("从 localStorage 恢复", () => {
    localStorage.setItem("ruoyi-scan.dismissedTasks", JSON.stringify(["a", "b"]));
    const { result } = renderHook(() => useApp(), { wrapper });
    expect([...result.current.dismissed].sort()).toEqual(["a", "b"]);
  });

  it("存档损坏时退回空集合，不抛错", () => {
    localStorage.setItem("ruoyi-scan.dismissedTasks", "{not json");
    const { result } = renderHook(() => useApp(), { wrapper });
    expect(result.current.dismissed.size).toBe(0);
  });

  it("dismissTask 持久化，并让出当前聚焦任务", () => {
    const { result } = renderHook(() => useApp(), { wrapper });
    act(() => result.current.selectTask("a"));
    act(() => result.current.dismissTask("a"));

    expect(result.current.dismissed.has("a")).toBe(true);
    expect(result.current.selectedTaskId).toBeNull();
    expect(JSON.parse(localStorage.getItem("ruoyi-scan.dismissedTasks")!)).toEqual(["a"]);
  });

  it("关闭非当前任务时不动选中态", () => {
    const { result } = renderHook(() => useApp(), { wrapper });
    act(() => result.current.selectTask("a"));
    act(() => result.current.dismissTask("b"));
    expect(result.current.selectedTaskId).toBe("a");
  });
});

describe("健康检查", () => {
  it("成功时 online=true 并带出引擎信息", async () => {
    const { result } = renderHook(() => useApp(), { wrapper });
    await waitFor(() => expect(result.current.online).toBe(true));
    expect(result.current.engine).toEqual(ENGINE);
    expect(result.current.lastError).toBe("");
  });

  it("health 返回非 ok 时 online=false", async () => {
    h.health.mockResolvedValue({ status: "degraded", version: "1.8.0", uptime: 1 });
    const { result } = renderHook(() => useApp(), { wrapper });
    await waitFor(() => expect(result.current.online).toBe(false));
  });

  it("失败时记录错误文案供界面展示", async () => {
    h.health.mockRejectedValue(new Error("无法连接引擎 http://127.0.0.1:8123"));
    const { result } = renderHook(() => useApp(), { wrapper });
    await waitFor(() => expect(result.current.lastError).toContain("无法连接引擎"));
    expect(result.current.online).toBe(false);
  });

  it("4s 轮询重叠时丢弃过期响应，不让旧状态盖掉新状态", async () => {
    const slow = deferred<{ status: string; version: string; uptime: number }>();
    const fast = deferred<{ status: string; version: string; uptime: number }>();
    // 挂载时的那次调用先设成快速成功，后续两次用手动控制
    h.health.mockResolvedValueOnce({ status: "ok", version: "1.8.0", uptime: 1 });
    h.health.mockReturnValueOnce(slow.promise).mockReturnValueOnce(fast.promise);

    const { result } = renderHook(() => useApp(), { wrapper });
    await waitFor(() => expect(result.current.online).toBe(true));

    let p1!: Promise<void>;
    let p2!: Promise<void>;
    act(() => {
      p1 = result.current.refreshHealth(); // 先发，后回
      p2 = result.current.refreshHealth(); // 后发，先回
    });

    fast.resolve({ status: "ok", version: "1.8.0", uptime: 99 });
    await act(async () => {
      await p2;
    });
    slow.resolve({ status: "degraded", version: "1.8.0", uptime: 1 });
    await act(async () => {
      await p1;
    });

    expect(result.current.online).toBe(true); // 来自较新的那次请求
  });
});

describe("任务列表轮询", () => {
  it("内容未变时保持同一引用（否则每 2.5s 触发下游全量重拉）", async () => {
    const list = [task("a"), task("b")];
    h.listTasks.mockResolvedValue(list);

    const { result } = renderHook(() => useApp(), { wrapper });
    await waitFor(() => expect(result.current.tasks).toHaveLength(2));
    const first = result.current.tasks;

    await act(async () => {
      await result.current.refreshTasks();
    });

    // 后端每次返回新对象，但内容一致 → 前端必须保留旧引用
    expect(result.current.tasks).toBe(first);
  });

  it("状态变化时换成新数组", async () => {
    h.listTasks.mockResolvedValue([task("a", { status: "running" })]);
    const { result } = renderHook(() => useApp(), { wrapper });
    await waitFor(() => expect(result.current.tasks).toHaveLength(1));
    const first = result.current.tasks;

    h.listTasks.mockResolvedValue([task("a", { status: "done" })]);
    await act(async () => {
      await result.current.refreshTasks();
    });

    expect(result.current.tasks).not.toBe(first);
    expect(result.current.tasks[0].status).toBe("done");
  });

  it("按开始时间倒序，新任务在前", async () => {
    h.listTasks.mockResolvedValue([task("old", { started_at: 1 }), task("new", { started_at: 9 })]);
    const { result } = renderHook(() => useApp(), { wrapper });
    await waitFor(() => expect(result.current.tasks).toHaveLength(2));
    expect(result.current.tasks.map((t) => t.task_id)).toEqual(["new", "old"]);
  });

  it("后端离线时保留旧列表，不清空", async () => {
    h.listTasks.mockResolvedValue([task("a")]);
    const { result } = renderHook(() => useApp(), { wrapper });
    await waitFor(() => expect(result.current.tasks).toHaveLength(1));

    h.listTasks.mockRejectedValue(new Error("offline"));
    await act(async () => {
      await result.current.refreshTasks();
    });

    expect(result.current.tasks).toHaveLength(1);
  });

  it("列表请求重叠时丢弃过期结果，避免「停止」后徽标又跳回 RUNNING", async () => {
    const slow = deferred<ScanTask[]>();
    const fast = deferred<ScanTask[]>();
    h.listTasks.mockResolvedValueOnce([]).mockReturnValueOnce(slow.promise).mockReturnValueOnce(fast.promise);

    const { result } = renderHook(() => useApp(), { wrapper });
    await waitFor(() => expect(result.current.online).toBe(true));

    let p1!: Promise<void>;
    let p2!: Promise<void>;
    act(() => {
      p1 = result.current.refreshTasks();
      p2 = result.current.refreshTasks();
    });

    fast.resolve([task("a", { status: "done" })]);
    await act(async () => {
      await p2;
    });
    slow.resolve([task("a", { status: "running" })]);
    await act(async () => {
      await p1;
    });

    expect(result.current.tasks[0].status).toBe("done");
  });
});

describe("新建扫描流程", () => {
  it("openDialog 带预置插件与模式，closeDialog 清空", () => {
    const { result } = renderHook(() => useApp(), { wrapper });

    act(() => result.current.openDialog({ plugins: ["sql_inject_dept"], mode: "p" }));
    expect(result.current.dialogOpen).toBe(true);
    expect(result.current.dialogPreset).toEqual({ plugins: ["sql_inject_dept"], mode: "p" });

    act(() => result.current.closeDialog());
    expect(result.current.dialogOpen).toBe(false);
    expect(result.current.dialogPreset).toBeNull();
  });

  it("提交成功后关弹窗、切到现场页、聚焦新任务", async () => {
    const { result } = renderHook(() => useApp(), { wrapper });
    act(() => result.current.openDialog());

    let taskId = "";
    await act(async () => {
      taskId = await result.current.submitScan({ target: "http://a.test/", mode: "u" } as never);
    });

    expect(taskId).toBe("new-1");
    expect(result.current.dialogOpen).toBe(false);
    expect(result.current.view).toBe("livescan");
    expect(result.current.selectedTaskId).toBe("new-1");
    expect(result.current.submitting).toBe(false);
  });

  it("提交失败时 submitting 复位，弹窗保持打开（用户可改参数重试）", async () => {
    h.submitScan.mockRejectedValue(new Error("目标格式非法"));
    const { result } = renderHook(() => useApp(), { wrapper });
    act(() => result.current.openDialog());

    await act(async () => {
      await expect(
        result.current.submitScan({ target: "abc", mode: "u" } as never),
      ).rejects.toThrow("目标格式非法");
    });

    expect(result.current.submitting).toBe(false);
    expect(result.current.dialogOpen).toBe(true);
  });
});

describe("服务地址联动", () => {
  it("setApiBase 后 UI 上的地址同步变化（请求已走新地址，界面不能还写旧的）", async () => {
    const { setApiBase } = await import("../src/services/backend");
    const { result } = renderHook(() => useApp(), { wrapper });

    act(() => setApiBase("http://10.0.0.9:9000"));
    expect(result.current.apiBase).toBe("http://10.0.0.9:9000");
  });
});
