import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  listPlugins: vi.fn(),
  probe: vi.fn(),
  app: { current: {} as Record<string, unknown> },
}));

vi.mock("../src/state/AppCtx", () => ({
  useApp: () => mocks.app.current,
}));

vi.mock("../src/services/backend", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/services/backend")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      listPlugins: mocks.listPlugins,
      probe: mocks.probe,
    },
  };
});

import { NewScanDialog } from "../src/components/NewScanDialog";

function state(overrides: Record<string, unknown> = {}) {
  return {
    dialogOpen: true,
    dialogPreset: null,
    closeDialog: vi.fn(),
    submitting: false,
    submitScan: vi.fn().mockResolvedValue(undefined),
    online: true,
    ...overrides,
  };
}

describe("NewScanDialog", () => {
  beforeEach(() => {
    mocks.app.current = state();
    mocks.listPlugins.mockResolvedValue([
      { name: "p1", severity: "high", category: "vuln" },
      { name: "p2", severity: "low", category: "recon" },
    ]);
    mocks.probe.mockResolvedValue({ ok: true, elapsed_ms: 3, stage: "http", reason: "" });
  });

  it("关闭时不渲染任何内容", () => {
    mocks.app.current = state({ dialogOpen: false });
    const { container } = render(<NewScanDialog />);
    expect(container).toBeEmptyDOMElement();
  });

  it("#66 回归：dialogOpen 从 false→true→false 不抛 React #310", () => {
    // 旧 bug：useRef 位于 `if (!dialogOpen) return null` 之后，打开时 Hook 数量变化。
    // 必须用同一个组件实例 rerender，才能触发 React 的 Hook 顺序检查。
    mocks.app.current = state({ dialogOpen: false });
    const { rerender } = render(<NewScanDialog />);
    mocks.app.current = state({ dialogOpen: true });
    expect(() => rerender(<NewScanDialog />)).not.toThrow();
    expect(screen.getByText(/新建扫描/)).toBeInTheDocument();
    mocks.app.current = state({ dialogOpen: false });
    expect(() => rerender(<NewScanDialog />)).not.toThrow();
  });

  it("打开后展示目标、模式与默认报告格式", () => {
    render(<NewScanDialog />);
    expect(screen.getByPlaceholderText("https://demo.example.com/")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /综合扫描/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "json" })).toBeInTheDocument();
  });

  it("提交时构造完整 payload（目标归一化 + 默认值）", async () => {
    const submitScan = vi.fn().mockResolvedValue(undefined);
    mocks.app.current = state({ submitScan });
    render(<NewScanDialog />);
    fireEvent.change(screen.getByPlaceholderText("https://demo.example.com/"), {
      target: { value: "127.0.0.1:8080" },
    });
    fireEvent.click(screen.getByRole("button", { name: "开始扫描" }));
    await waitFor(() => expect(submitScan).toHaveBeenCalledTimes(1));
    const payload = submitScan.mock.calls[0][0];
    expect(payload.target).toBe("http://127.0.0.1:8080/");
    expect(payload.mode).toBe("u");
    expect(payload.threads).toBe(8);
    expect(payload.rate).toBe(0);
    expect(payload.timeout).toBe(10);
    expect(payload.pass_level).toBe("top100");
    expect(payload.bypass_waf).toBe("auto");
    expect(payload.portscan).toBe(false);
    expect(payload.report_format).toContain("json");
    expect(payload.plugins).toBeUndefined();
  });

  it("非法目标在前端拦截，不调用 submitScan", async () => {
    const submitScan = vi.fn();
    mocks.app.current = state({ submitScan });
    render(<NewScanDialog />);
    fireEvent.change(screen.getByPlaceholderText("https://demo.example.com/"), {
      target: { value: "abc" },
    });
    fireEvent.click(screen.getByRole("button", { name: "开始扫描" }));
    await screen.findByText(/有效地址/);
    expect(submitScan).not.toHaveBeenCalled();
  });

  it("报告格式至少保留一个", async () => {
    const submitScan = vi.fn().mockResolvedValue(undefined);
    mocks.app.current = state({ submitScan });
    render(<NewScanDialog />);
    for (const fmt of ["html", "json", "csv", "pdf", "docx", "xlsx"]) {
      fireEvent.click(screen.getByRole("button", { name: fmt }));
    }
    fireEvent.change(screen.getByPlaceholderText("https://demo.example.com/"), {
      target: { value: "http://127.0.0.1:8080" },
    });
    fireEvent.click(screen.getByRole("button", { name: "开始扫描" }));
    await waitFor(() => expect(submitScan).toHaveBeenCalled());
    expect(submitScan.mock.calls[0][0].report_format).not.toBe("");
  });

  it("插件子集会进入 payload.plugins", async () => {
    const submitScan = vi.fn().mockResolvedValue(undefined);
    mocks.app.current = state({ submitScan });
    render(<NewScanDialog />);
    fireEvent.click(screen.getByRole("button", { name: /插件选择/ }));
    const p1 = await screen.findByRole("button", { name: "p1" });
    fireEvent.click(p1);
    fireEvent.change(screen.getByPlaceholderText("https://demo.example.com/"), {
      target: { value: "http://127.0.0.1:8080" },
    });
    fireEvent.click(screen.getByRole("button", { name: "开始扫描" }));
    await waitFor(() => expect(submitScan).toHaveBeenCalled());
    expect(submitScan.mock.calls[0][0].plugins).toEqual(["p1"]);
  });
});
