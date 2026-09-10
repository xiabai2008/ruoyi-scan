/** 全部图标走内联 SVG（与画布矢量一一对应），不引图标库 */

export function ShieldLogo({ size = 22 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 22 22" fill="none">
      <path d="M4 6L11 3L18 6V12C18 17 14 19.5 11 21C8 19.5 4 17 4 12V6Z" stroke="var(--c-accent-primary)" strokeWidth="1.5" />
      <path d="M4 6L6 1.5L9 4.2" stroke="var(--c-accent-primary)" strokeWidth="1.5" />
      <path d="M13 4.2L16 1.5L18 6" stroke="var(--c-accent-primary)" strokeWidth="1.5" />
      <path d="M6 11.5H16" stroke="var(--c-accent-pink)" strokeWidth="1.5" />
      <circle cx="11" cy="15.5" r="1.2" fill="var(--c-accent-primary)" />
    </svg>
  );
}

/** 看板娘「柒遂枚依」姬发式 chibi 头像（画布同款矢量） */
export function MeiYi({ width = 160, height = 110, bg = "var(--c-deep)" }: { width?: number; height?: number; bg?: string }) {
  return (
    <svg width={width} height={height} viewBox="0 0 160 110" style={{ background: bg, borderRadius: 4, display: "block" }}>
      <path d="M28 58 C24 18 52 6 80 6 C108 6 136 18 132 58 L134 104 L26 104 Z" fill="#221C36" />
      <path d="M40 14 C52 8 66 6 78 6 L76 14 C64 14 52 18 44 24 Z" fill="#6C5CE7" opacity="0.55" />
      <path d="M116 20 C112 12 104 8 96 7 L98 15 C106 16 112 20 116 26 Z" fill="#4FD1C5" opacity="0.5" />
      <ellipse cx="80" cy="52" rx="34" ry="36" fill="#FFE3CC" />
      <path d="M46 30 L40 88 C44 92 50 92 54 88 L52 34 Z" fill="#221C36" />
      <path d="M114 30 L120 88 C116 92 110 92 106 88 L108 34 Z" fill="#221C36" />
      <path d="M46 40 C44 12 60 4 80 4 C100 4 116 12 114 40 C104 30 96 26 80 26 C64 26 56 30 46 40 Z" fill="#2A2344" />
      <ellipse cx="66" cy="58" rx="7.5" ry="9" fill="#8B5CF6" />
      <ellipse cx="94" cy="58" rx="7.5" ry="9" fill="#8B5CF6" />
      <circle cx="68" cy="55" r="2.2" fill="#E9D5FF" />
      <circle cx="96" cy="55" r="2.2" fill="#E9D5FF" />
      <circle cx="64.5" cy="61" r="1.1" fill="#FFFFFF" opacity="0.8" />
      <circle cx="92.5" cy="61" r="1.1" fill="#FFFFFF" opacity="0.8" />
      <ellipse cx="58" cy="66" rx="5" ry="2.6" fill="#FF9EB5" opacity="0.5" />
      <ellipse cx="102" cy="66" rx="5" ry="2.6" fill="#FF9EB5" opacity="0.5" />
      <path d="M77 71 Q80 74 83 71" stroke="#C96F6F" strokeWidth="1.6" fill="none" strokeLinecap="round" />
      <path d="M40 110 C42 90 58 82 80 82 C102 82 118 90 120 110 Z" fill="#B7A6EC" />
      <path d="M66 84 C70 90 90 90 94 84 L94 96 C88 100 72 100 66 96 Z" fill="#9C89DB" />
      <path d="M30 44 C30 12 52 2 80 2 C108 2 130 12 130 44" stroke="#0E0E1E" strokeWidth="6" fill="none" />
      <rect x="24" y="40" width="12" height="20" rx="5" fill="#0E0E1E" />
      <rect x="124" y="40" width="12" height="20" rx="5" fill="#0E0E1E" />
      <circle cx="30" cy="50" r="2.6" fill="#2EE6E6" />
      <circle cx="130" cy="50" r="2.6" fill="#2EE6E6" />
      <path d="M30 50 C28 24 46 10 62 7" stroke="#2EE6E6" strokeWidth="2" fill="none" opacity="0.5" />
    </svg>
  );
}

const dot = (r: number, color: string, glow = false) => (
  <>
    {glow && <circle cx="4" cy="4" r="4" fill={color} opacity="0.25" />}
    <circle cx="4" cy="4" r={glow ? 2 : 2.6} fill={color} />
  </>
);

export function StatusDot({ color = "var(--c-sem-green)", glow = true, size = 8 }: { color?: string; glow?: boolean; size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 8 8" fill="none">
      {dot(2, color, glow)}
    </svg>
  );
}

export function PulseDot({ color = "var(--c-accent-pink)" }: { color?: string }) {
  return (
    <svg width="6" height="6" viewBox="0 0 6 6" fill="none">
      <circle cx="3" cy="3" r="3" fill={color} opacity="0.3" />
      <circle cx="3" cy="3" r="1.6" fill={color} />
    </svg>
  );
}

export function TrendTri({ dir, color }: { dir: "up" | "down"; color: string }) {
  return (
    <svg width="8" height="8" viewBox="0 0 8 8" fill="none" style={{ transform: dir === "down" ? "rotate(180deg)" : undefined }}>
      <path d="M4 1L7.5 7H0.5L4 1Z" fill={color} />
    </svg>
  );
}

export function SearchIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
      <circle cx="6" cy="6" r="4.5" stroke="var(--c-text-muted)" strokeWidth="1.5" />
      <path d="M9.5 9.5L13 13" stroke="var(--c-text-muted)" strokeWidth="1.5" strokeLinecap="round" />
    </svg>
  );
}

export function PlayIcon({ color = "var(--c-btn-text)" }: { color?: string }) {
  return (
    <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
      <path d="M3 2L10.5 6L3 10V2Z" fill={color} />
    </svg>
  );
}

export function PlusIcon() {
  return (
    <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
      <path d="M6 1.5V10.5M1.5 6H10.5" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
    </svg>
  );
}

export function PauseIcon() {
  return (
    <svg width="10" height="10" viewBox="0 0 10 10" fill="none">
      <rect x="1" y="1" width="3" height="8" fill="var(--c-text-secondary)" />
      <rect x="6" y="1" width="3" height="8" fill="var(--c-text-secondary)" />
    </svg>
  );
}

export function StopIcon() {
  return (
    <svg width="10" height="10" viewBox="0 0 10 10" fill="none">
      <rect x="1" y="1" width="8" height="8" rx="1" fill="var(--c-sem-red)" />
    </svg>
  );
}

/** 统计条图标：target / check / diamond / bolt */
export function StatIcon({ kind }: { kind: string }) {
  switch (kind) {
    case "target":
      return (
        <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
          <circle cx="10" cy="10" r="7" stroke="var(--c-sem-red)" strokeWidth="2" />
          <circle cx="10" cy="10" r="2.5" fill="var(--c-sem-red)" />
        </svg>
      );
    case "check":
      return (
        <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
          <circle cx="10" cy="10" r="7" stroke="var(--c-sem-green)" strokeWidth="2" />
          <path d="M6.5 10.5L9 13L14 7.5" stroke="var(--c-sem-green)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      );
    case "diamond":
      return (
        <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
          <rect x="5.8" y="5.8" width="8.4" height="8.4" rx="1.5" transform="rotate(45 10 10)" stroke="var(--c-sem-amber)" strokeWidth="2" />
        </svg>
      );
    default:
      return (
        <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
          <path d="M11 2L5 11H9.5L8.5 18L15 8.5H10.5L11 2Z" fill="var(--c-accent-purple)" />
        </svg>
      );
  }
}
