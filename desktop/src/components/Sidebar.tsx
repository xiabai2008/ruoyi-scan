import { NAV, type ViewId } from "../data/mock";
import { StatusDot } from "./icons";
import { useApp } from "../state/AppCtx";
import { usePersona, operatorAvatarSrc } from "../state/PersonaCtx";

export function Sidebar() {
  const { view, setView, online, engine, tasks } = useApp();
  const { operator } = usePersona();
  const running = tasks.filter((t) => t.status === "running" || t.status === "pending").length;
  const nav = (id: ViewId) => setView(id);

  const base = !online
    ? "引擎未连接，先到设置页检查后端。"
    : running > 0
      ? `${running} 个任务扫描中，保持节奏！`
      : view === "livescan"
        ? "扫描队列已就绪，随时可以开工！"
        : "引擎在线，随时可以开工！";
  const greeting = operator.greet ? `${base}${base.endsWith("。") ? "" : ""} ${operator.greet}！` : base;

  return (
    <aside className="flex h-full w-[216px] shrink-0 flex-col border-r border-line bg-sidebar">
      {/* 品牌行 */}
      <div className="flex items-center gap-2 px-3.5 pb-2.5 pt-3.5">
        <img
          src={operatorAvatarSrc(operator)}
          alt="Ruoyi-Scan"
          className="h-7 w-7 rounded-lg object-cover"
        />
        <span className="text-[13px] font-semibold tracking-wide text-ink">Ruoyi-Scan</span>
        <span className="ml-auto font-mono text-[9px] text-ink-3">{engine ? `v${engine.version}` : "v—"}</span>
      </div>

      {/* 操作员卡片 */}
      <div className="mx-3 mb-3 flex items-center gap-2.5 rounded-lg border border-edge-soft bg-card p-2.5">
        <img
          src={operatorAvatarSrc(operator)}
          alt={operator.callsign}
          className="h-10 w-10 shrink-0 rounded-full object-cover"
        />
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-1.5">
            <span className="truncate text-[12.5px] font-semibold text-ink">{operator.callsign}</span>
            <span className="shrink-0 font-mono text-[8px] tracking-wider text-pink">OPERATOR-01</span>
          </div>
          <p className="mt-0.5 line-clamp-2 text-[10px] leading-[14px] text-ink-2">{greeting}</p>
        </div>
      </div>

      {/* 导航 */}
      <nav className="flex flex-1 flex-col gap-0.5 px-2.5">
        {NAV.map((item) => {
          const active = item.id === view;
          return (
            <button
              key={item.id}
              onClick={() => nav(item.id)}
              className={`flex cursor-pointer items-center gap-2.5 rounded-lg p-2.5 text-left transition-colors ${
                active ? "bg-activetab" : "hover:bg-cardsoft"
              }`}
            >
              <span
                className={`font-mono text-[9px] ${active ? "text-accent" : "text-ink-3"}`}
              >
                {item.num}
              </span>
              <span className={`text-[13px] ${active ? "font-medium text-ink" : "text-ink-2"}`}>
                {item.label}
              </span>
              {item.id === "livescan" && running > 0 ? (
                <span className="ml-auto h-1.5 w-1.5 animate-pulse rounded-full bg-accent" />
              ) : null}
            </button>
          );
        })}
      </nav>

      {/* 引擎状态 */}
      <div className="m-3 flex items-center justify-between rounded-lg bg-page px-2.5 py-2">
        <div className="flex items-center gap-1.5">
          <StatusDot color={online ? "var(--c-sem-green)" : "var(--c-sem-red)"} />
          <span className="font-mono text-[9px]" style={{ color: online ? "var(--c-sem-green)" : "var(--c-sem-red)" }}>
            {online ? "ENGINE ONLINE" : "ENGINE OFFLINE"}
          </span>
        </div>
        <span className="font-mono text-[9px] text-ink-3">{online ? (running ? `${running} RUNNING` : "IDLE") : "OFFLINE"}</span>
      </div>
    </aside>
  );
}
