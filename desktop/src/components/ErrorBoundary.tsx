import { Component, type ErrorInfo, type ReactNode } from "react";

interface Props {
  children: ReactNode;
}

interface State {
  error: Error | null;
}

/**
 * 顶层错误边界：任何渲染期异常都降级为可读错误页，而不是把整个窗口卸载成白屏。
 *
 * 背景：v1.5.0 的 NewScanDialog 因条件 Hook（React #310）在打开时崩掉整棵 React 树，
 * 用户只能看到全白界面且无法操作。错误边界保证此类问题至少给出可见提示与恢复入口。
 */
export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("[ui] 渲染错误，已降级显示错误页:", error, info.componentStack);
  }

  render() {
    const { error } = this.state;
    if (!error) return this.props.children;
    return (
      <div
        className="flex h-full w-full items-center justify-center p-6"
        style={{ background: "var(--c-bg-page, #f2f7fd)" }}
      >
        <div
          className="max-w-[680px] rounded-lg border p-6 shadow-xl"
          style={{ borderColor: "var(--c-border, #dbe3ee)", background: "var(--c-card, #ffffff)" }}
        >
          <h1 className="text-[15px] font-semibold" style={{ color: "var(--c-text-primary, #22303f)" }}>
            界面渲染出错
          </h1>
          <p className="mt-2 text-[12px]" style={{ color: "var(--c-text-secondary, #4b5b6e)" }}>
            页面遇到未处理的错误，已停止渲染以避免状态错乱。可尝试重新加载；若持续出现，请附上下方信息反馈到
            GitHub Issues。
          </p>
          <pre
            className="mt-3 max-h-40 overflow-auto rounded-sm p-3 font-mono text-[11px] thin-scroll"
            style={{ background: "var(--c-card-soft, #f6f8fb)", color: "var(--c-text-secondary, #4b5b6e)" }}
          >
            {String(error.stack || error.message || error)}
          </pre>
          <button
            type="button"
            onClick={() => window.location.reload()}
            className="mt-4 h-[30px] rounded-sm border px-3 font-mono text-[11px] transition-colors"
            style={{
              borderColor: "var(--c-border, #dbe3ee)",
              background: "var(--c-card-soft, #f6f8fb)",
              color: "var(--c-text-primary, #22303f)",
            }}
          >
            重新加载
          </button>
        </div>
      </div>
    );
  }
}
