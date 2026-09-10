import type { ReactNode } from "react";
import { TrendTri } from "./icons";
import type { Severity, Verdict } from "../data/mock";

const deltaColor = (tone: string) =>
  tone === "red" ? "var(--c-sem-red)" : tone === "green" ? "var(--c-sem-green)" : tone === "purple" ? "var(--c-accent-purple)" : "var(--c-accent-primary)";

export function KpiCard({
  en,
  value,
  delta,
  up,
  tone,
  zh,
  alert,
}: {
  en: string;
  value: string;
  delta: string;
  up: boolean | null;
  tone: "green" | "accent" | "red" | "purple";
  zh: string;
  alert?: boolean;
}) {
  return (
    <div
      className="flex flex-1 flex-col gap-1 rounded border bg-card p-3.5"
      style={{ borderColor: alert ? "var(--c-alert-stroke)" : "var(--c-border)" }}
    >
      <span className={`font-mono text-[9px] tracking-wider ${tone === "red" ? "text-red" : "text-ink-3"}`}>{en}</span>
      <span className={`font-mono text-[30px] font-semibold leading-[38px] tracking-tight ${tone === "red" ? "text-red" : "text-ink"}`}>{value}</span>
      <div className="flex items-center gap-1.5">
        {up !== null && <TrendTri dir={up ? "up" : "down"} color={deltaColor(tone)} />}
        <span className="font-mono text-[10px]" style={{ color: deltaColor(tone) }}>
          {delta}
        </span>
      </div>
      <span className="text-[10px] text-ink-3">{zh}</span>
    </div>
  );
}

export function VerdictChip({ v }: { v: Verdict }) {
  const map = {
    CONFIRMED: { bg: "var(--c-sem-red-tint)", fg: "var(--c-sem-red)" },
    SAFE: { bg: "var(--c-sem-green-tint)", fg: "var(--c-sem-green)" },
    UNKNOWN: { bg: "var(--c-sem-amber-tint)", fg: "var(--c-sem-amber)" },
  } as const;
  const s = map[v];
  return (
    <span
      className="inline-flex h-[22px] w-[92px] items-center justify-center rounded font-mono text-[9px]"
      style={{ background: s.bg, color: s.fg }}
    >
      {v}
    </span>
  );
}

const sevColor: Record<Severity, string> = {
  CRITICAL: "var(--c-sem-red)",
  HIGH: "var(--c-sem-amber)",
  MED: "var(--c-sem-amber)",
  LOW: "var(--c-accent-primary)",
};

export function SeverityText({ s }: { s: Severity }) {
  return (
    <span className="font-mono text-[9.5px]" style={{ color: sevColor[s] }}>
      {s}
    </span>
  );
}

export function SectionCard({
  title,
  right,
  children,
  className = "",
}: {
  title: string;
  right?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`flex flex-col rounded border bg-card ${className}`} style={{ borderColor: "var(--c-border)" }}>
      <div className="flex items-center justify-between px-3.5 py-3">
        <h2 className="text-[12px] font-semibold text-ink">{title}</h2>
        {right}
      </div>
      {children}
    </section>
  );
}

export function Toggle({ on, onChange }: { on: boolean; onChange?: (v: boolean) => void }) {
  return (
    <button
      onClick={() => onChange?.(!on)}
      className="relative h-5 w-9 rounded-full transition-colors"
      style={{
        background: on ? "var(--c-accent-primary)" : "var(--c-zebra)",
        border: on ? "none" : "1px solid var(--c-border)",
      }}
      aria-pressed={on}
    >
      <span
        className="absolute top-0.5 h-4 w-4 rounded-full transition-all"
        style={{
          left: on ? 18 : 2,
          background: on ? "#FFFFFF" : "var(--c-text-muted)",
        }}
      />
    </button>
  );
}
