import type { ReactNode } from "react";
import { PulseDot } from "./icons";

export function Topbar({
  title,
  sub,
  right,
  pulse,
}: {
  title: string;
  sub: string;
  right?: ReactNode;
  pulse?: boolean;
}) {
  return (
    <div className="flex items-center justify-between px-6 py-4">
      <div className="flex flex-col gap-1">
        <h1 className="text-[16px] font-semibold text-ink">{title}</h1>
        <div className="flex items-center gap-1.5">
          {pulse ? <PulseDot /> : null}
          <span className="font-mono text-[10px] tracking-wide text-ink-3">{sub}</span>
        </div>
      </div>
      {right ? <div className="flex items-center gap-2.5">{right}</div> : null}
    </div>
  );
}
