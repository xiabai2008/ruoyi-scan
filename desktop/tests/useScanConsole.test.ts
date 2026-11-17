import { act, renderHook } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ScanResultItem, ScanTask, WsEvent } from "../src/services/backend";

// 扫描控制台事件合成（src/state/useScanConsole.ts）
//
// 桌面端唯一的「实时」数据通路：后端 WS 结构化事件 → 终端行 + 进度 + 三态统计。
// 这里锁三类行为：
//   1. 事件 → 状态映射（尤其三态 tally，写错会让总览数字和报告对不上）
//   2. 缓冲与节流（日志上限、进度分桶）—— 失控会直接吃满内存/刷屏
//   3. 终态兜底（WS 断开后靠 REST 补齐统计）

const h = vi.hoisted(() => ({
  handlers: null as null | {
    onEvent: (e: unknown) => void;
    onState: (s: string) => void;
    onTerminal: () => void;
  },
  closed: 0,
  taskResults: vi.fn(async () => [] as unknown[]),
}));

vi.mock("../src/services/backend", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/services/backend")>();
  return {
    ...actual,
    openTaskSocket: (
      _id: string,
      onEvent: (e: unknown) => void,
      onState: (s: string) => void,
      onTerminal: () => void,
    ) => {
      h.handlers = { onEvent, onState, onTerminal };
      return () => {
        h.closed += 1;
      };
    },
    api: { ...actual.api, taskResults: h.taskResults },
  };
});

// 人格钩子会在 CONFIRMED / complete 时被动态 import，mock 掉避免音频与存储副作用
vi.mock("../src/state/personaHooks", () => ({
  fireScanDone: vi.fn(),
  fireConfirmAlert: vi.fn(),
}));

import { useScanConsole } from "../src/state/useScanConsole";

const TASK: ScanTask = {
  task_id: "t-001",
  status: "running",
  target: "http://demo.example.com/",
  mode: "u",
  started_at: 1766000000,
  finished_at: 0,
  duration: 0,
  request_count: 12,
  result_count: 0,
  confirmed_count: 0,
  safe_count: 0,
  unknown_count: 0,
  error: "",
  fingerprint: { cms: "若依", variant: "Vue3", version: "4.7.8", confidence: 0.7, matched: [] } as ScanTask["fingerprint"],
  waf: null,
  report_paths: [],
};

const ev = (type: string, data: Record<string, unknown> = {}, timestamp?: number): WsEvent =>
  ({ type, data, timestamp }) as WsEvent;

function emit(e: WsEvent) {
  act(() => h.handlers!.onEvent(e));
}

beforeEach(() => {
  h.handlers = null;
  h.closed = 0;
  h.taskResults.mockReset();
  h.taskResults.mockResolvedValue([]);
});

describe("快照初始化", () => {
  it("task 为 null 时不建连接", () => {
    const { result } = renderHook(() => useScanConsole(null, "k"));
    expect(h.handlers).toBeNull();
    expect(result.current.lines).toHaveLength(0);
  });

  it("有 task 时先落一条任务概要行，并把已识别的指纹带出来", () => {
    const { result } = renderHook(() => useScanConsole(TASK, "k"));

    expect(result.current.lines).toHaveLength(1);
    expect(result.current.lines[0].text).toContain("t-001");
    expect(result.current.lines[0].text).toContain("http://demo.example.com/");
    expect(result.current.fingerprint).toBe("若依 Vue3");
    expect(result.current.status).toBe("running");
  });

  it("taskId 变化时重建连接并关闭旧连接", () => {
    const { rerender } = renderHook(({ t, k }) => useScanConsole(t, k), {
      initialProps: { t: TASK, k: "k" },
    });
    const first = h.handlers;
    rerender({ t: { ...TASK, task_id: "t-002" }, k: "k2" });
    expect(h.handlers).not.toBe(first);
    expect(h.closed).toBeGreaterThanOrEqual(1);
  });
});

describe("事件 → 状态", () => {
  it("status 终态置 taskDone，非终态不置", () => {
    const { result } = renderHook(() => useScanConsole(TASK, "k"));

    emit(ev("status", { status: "running" }));
    expect(result.current.taskDone).toBe(false);

    emit(ev("status", { status: "done" }));
    expect(result.current.taskDone).toBe(true);
    expect(result.current.status).toBe("done");
  });

  it("result 事件按三态累计 tally 与 resultCount", () => {
    const { result } = renderHook(() => useScanConsole(TASK, "k"));

    emit(ev("result", { status: "CONFIRMED", name: "定时任务 RCE", severity: "high", url: "http://a/1" }));
    emit(ev("result", { status: "SAFE", name: "任意文件读取", severity: "high" }));
    emit(ev("result", { status: "UNKNOWN", name: "部门树越权", severity: "medium" }));

    expect(result.current.tally).toEqual({ CONFIRMED: 1, SAFE: 1, UNKNOWN: 1 });
    expect(result.current.resultCount).toBe(3);
  });

  it("未知 verdict 归 UNKNOWN，不新增第四种状态", () => {
    const { result } = renderHook(() => useScanConsole(TASK, "k"));
    emit(ev("result", { status: "MAYBE", name: "x", severity: "low" }));

    expect(result.current.tally).toEqual({ CONFIRMED: 0, SAFE: 0, UNKNOWN: 1 });
  });

  it("CONFIRMED 行带 CONFIRMED 级别前缀，供终端上色", () => {
    const { result } = renderHook(() => useScanConsole(TASK, "k"));
    emit(ev("result", { status: "CONFIRMED", name: "SQL 注入", severity: "high", url: "http://a/x" }));

    const line = result.current.lines.at(-1)!;
    expect(line.level).toBe("confirmed");
    expect(line.text).toContain("CONFIRMED");
    expect(line.text).toContain("[HIGH]");
    expect(line.text).toContain("http://a/x");
  });

  it("指纹未识别时明确说未识别，不渲染空主体", () => {
    const { result } = renderHook(() => useScanConsole(TASK, "k"));
    emit(ev("fingerprint", { cms: "", confidence: 0 }));

    const line = result.current.lines.at(-1)!;
    expect(line.text).toContain("未识别");
    expect(line.text).not.toContain("detected");
    expect(result.current.fingerprint).toBe("");
  });

  it("指纹识别成功时带出版本与置信度", () => {
    const { result } = renderHook(() => useScanConsole(TASK, "k"));
    emit(ev("fingerprint", { cms: "若依", version: "4.7.8", confidence: 0.9 }));

    expect(result.current.lines.at(-1)!.text).toContain("若依 4.7.8");
    expect(result.current.fingerprint).toBe("若依 4.7.8");
  });

  it("preflight 失败落 error 行并带不可达阶段", () => {
    const { result } = renderHook(() => useScanConsole(TASK, "k"));
    emit(ev("preflight", { ok: false, stage: "tcp", reason: "connection refused" }));

    const line = result.current.lines.at(-1)!;
    expect(line.level).toBe("error");
    expect(line.text).toContain("TCP");
    expect(line.text).toContain("connection refused");
  });

  it("error 事件置 taskDone 并记录错误文案", () => {
    const { result } = renderHook(() => useScanConsole(TASK, "k"));
    emit(ev("error", { error: "任务异常终止" }));

    expect(result.current.error).toBe("任务异常终止");
    expect(result.current.taskDone).toBe(true);
  });

  it("未知事件类型也落一行，不静默吞掉", () => {
    const { result } = renderHook(() => useScanConsole(TASK, "k"));
    emit(ev("brand_new_event", { foo: "bar" }));

    const line = result.current.lines.at(-1)!;
    expect(line.text).toContain("brand_new_event");
    expect(line.text).toContain("foo");
  });

  it("wsState 跟随连接状态回调", () => {
    const { result } = renderHook(() => useScanConsole(TASK, "k"));
    act(() => h.handlers!.onState("open"));
    expect(result.current.wsState).toBe("open");
  });
});

describe("缓冲与节流", () => {
  it("终端行最多保留 200 行，老行被丢弃", () => {
    const { result } = renderHook(() => useScanConsole(TASK, "k"));
    // 用 SAFE 避免触发 CONFIRMED 的人格钩子动态 import
    for (let i = 0; i < 260; i += 1) emit(ev("result", { status: "SAFE", name: `p${i}`, severity: "low" }));

    expect(result.current.lines).toHaveLength(200);
    expect(result.current.lines.at(-1)!.text).toContain("p259");
    // 首行任务概要已被挤出
    expect(result.current.lines[0].text).not.toContain("t-001");
  });

  it("进度按 5% 分桶，同桶内重复事件不刷屏", () => {
    const { result } = renderHook(() => useScanConsole(TASK, "k"));
    const before = result.current.lines.length;

    emit(ev("progress", { done: 1, total: 100, percent: 1 }));
    emit(ev("progress", { done: 2, total: 100, percent: 2 }));
    emit(ev("progress", { done: 3, total: 100, percent: 3 }));
    expect(result.current.lines).toHaveLength(before + 1); // 0-4% 同桶，只落一行

    emit(ev("progress", { done: 5, total: 100, percent: 5 }));
    expect(result.current.lines).toHaveLength(before + 2);

    // 但进度数值本身每次都更新
    expect(result.current.progress).toEqual({ done: 5, total: 100, percent: 5 });
  });
});

describe("终态兜底", () => {
  it("任务终态后拉 REST 结果重算 tally（WS 可能已断）", async () => {
    const items: ScanResultItem[] = [
      { name: "a", status: "CONFIRMED", severity: "high", url: "u1" } as ScanResultItem,
      { name: "b", status: "CONFIRMED", severity: "high", url: "u2" } as ScanResultItem,
      { name: "c", status: "SAFE", severity: "low", url: "u3" } as ScanResultItem,
      { name: "d", status: "UNKNOWN", severity: "medium", url: "u4" } as ScanResultItem,
    ];
    h.taskResults.mockResolvedValue(items);

    const { result } = renderHook(() => useScanConsole(TASK, "k"));
    emit(ev("complete", { result_count: 4, confirmed_count: 2, duration: 12.34 }));

    await act(async () => {
      await Promise.resolve();
    });

    expect(h.taskResults).toHaveBeenCalledWith("t-001");
    expect(result.current.tally).toEqual({ CONFIRMED: 2, SAFE: 1, UNKNOWN: 1 });
    expect(result.current.resultCount).toBe(4);
  });

  it("REST 兜底失败时不推翻 WS 已有统计", async () => {
    h.taskResults.mockRejectedValue(new Error("引擎已退出"));
    const { result } = renderHook(() => useScanConsole(TASK, "k"));

    emit(ev("result", { status: "CONFIRMED", name: "x", severity: "high" }));
    emit(ev("status", { status: "done" }));

    await act(async () => {
      await Promise.resolve();
    });

    expect(result.current.tally.CONFIRMED).toBe(1);
  });
});
