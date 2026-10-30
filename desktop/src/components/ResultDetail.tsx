import { useEffect, useState } from "react";
import { hasCve, sevToUi, type ScanResultItem } from "../services/backend";
import { SeverityText, VerdictChip } from "./ui";

/**
 * 结果详情抽屉：安全工具的证据比名称重要。
 * 旧结果表只有 name 的 title tooltip，行不可点；这里展示
 * 证据 / 复现命令 / 修复建议 / CVE / 原始 extra，并支持一键复制。
 */
export function ResultDetail({ item, onClose }: { item: ScanResultItem; onClose: () => void }) {
  const [copied, setCopied] = useState("");

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const copy = async (label: string, text: string) => {
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      setCopied(label);
      setTimeout(() => setCopied(""), 1500);
    } catch {
      /* 剪贴板不可用（权限/无 https）：静默，用户可手动选中 */
    }
  };

  const extraText = item.extra && Object.keys(item.extra).length > 0
    ? JSON.stringify(item.extra, null, 2)
    : "";
  const complianceText = item.compliance && Object.keys(item.compliance).length > 0
    ? Object.entries(item.compliance).map(([k, v]) => `${k}: ${v}`).join("\n")
    : "";

  return (
    <div className="absolute inset-0 z-50 flex justify-end">
      <div className="absolute inset-0 bg-black/45" onClick={onClose} />
      <aside
        role="dialog"
        aria-modal="true"
        aria-label="扫描结果详情"
        className="thin-scroll relative flex h-full w-[560px] max-w-[92%] flex-col gap-3 overflow-y-auto border-l bg-page p-5 shadow-2xl"
        style={{ borderColor: "var(--c-border)" }}
      >
        <div className="flex items-start justify-between gap-3">
          <div className="flex min-w-0 flex-col gap-1.5">
            <div className="flex items-center gap-2">
              <VerdictChip v={item.status} />
              <SeverityText s={sevToUi(item.severity)} />
              {hasCve(item.cve) ? (
                <span className="rounded-sm border border-edge px-1.5 py-0.5 font-mono text-[9.5px] text-accent">{item.cve}</span>
              ) : null}
              {item.cvss_score ? (
                <span className="font-mono text-[9.5px] text-ink-3">CVSS {item.cvss_score.toFixed(1)}</span>
              ) : null}
            </div>
            <h2 className="break-words text-[14px] font-semibold text-ink">{item.name || "(未命名结果)"}</h2>
            {item.kind ? <span className="font-mono text-[9.5px] text-ink-3">KIND {item.kind}</span> : null}
          </div>
          <button onClick={onClose} className="shrink-0 font-mono text-[13px] text-ink-3 hover:text-ink" aria-label="关闭详情">
            ✕
          </button>
        </div>

        <div className="flex flex-col gap-1 rounded border border-edge bg-cardsoft px-3 py-2">
          <span className="text-[10px] text-ink-3">触发 URL</span>
          <div className="flex items-start gap-2">
            <code className="min-w-0 flex-1 break-all font-mono text-[10.5px] text-ink">{item.url || "—"}</code>
            {item.url ? (
              <button
                onClick={() => copy("url", item.url)}
                className="shrink-0 rounded-sm border border-edge px-1.5 py-0.5 font-mono text-[9px] text-ink-2 hover:bg-card"
              >
                {copied === "url" ? "已复制" : "复制"}
              </button>
            ) : null}
          </div>
        </div>

        <Section title="证据 / EVIDENCE">
          {item.evidence ? (
            <pre className="thin-scroll max-h-[180px] overflow-auto whitespace-pre-wrap break-words rounded border border-edge bg-[#12122a] p-2.5 font-mono text-[10.5px] leading-[16px] text-[#9A9AC0]">
              {item.evidence}
            </pre>
          ) : (
            <Empty text="该结果没有附带证据（UNKNOWN 项常见）" />
          )}
        </Section>

        <Section
          title="复现命令 / REPRODUCE"
          action={item.reproduce ? (
            <button
              onClick={() => copy("repro", item.reproduce || "")}
              className="rounded-sm border border-edge px-1.5 py-0.5 font-mono text-[9px] text-ink-2 hover:bg-cardsoft"
            >
              {copied === "repro" ? "已复制" : "复制命令"}
            </button>
          ) : null}
        >
          {item.reproduce ? (
            <pre className="thin-scroll max-h-[200px] overflow-auto whitespace-pre-wrap break-all rounded border border-edge bg-cardsoft p-2.5 font-mono text-[10.5px] leading-[16px] text-ink">
              {item.reproduce}
            </pre>
          ) : (
            <Empty text="该插件未提供复现命令" />
          )}
        </Section>

        {item.fix || item.fix_detail ? (
          <Section title="修复建议 / REMEDIATION">
            {item.fix ? <p className="text-[11px] leading-[17px] text-ink">{item.fix}</p> : null}
            {item.fix_detail ? (
              <pre className="thin-scroll max-h-[220px] overflow-auto whitespace-pre-wrap break-words rounded border border-edge bg-cardsoft p-2.5 font-mono text-[10px] leading-[16px] text-ink-2">
                {item.fix_detail}
              </pre>
            ) : null}
          </Section>
        ) : null}

        {item.cvss_vector || complianceText ? (
          <Section title="评级与合规 / SCORING">
            {item.cvss_vector ? (
              <Row k="CVSS 向量" v={item.cvss_vector} mono />
            ) : null}
            {complianceText ? <Row k="合规映射" v={complianceText} mono /> : null}
          </Section>
        ) : null}

        <Section
          title="原始附加字段 / EXTRA"
          action={extraText ? (
            <button
              onClick={() => copy("extra", extraText)}
              className="rounded-sm border border-edge px-1.5 py-0.5 font-mono text-[9px] text-ink-2 hover:bg-cardsoft"
            >
              {copied === "extra" ? "已复制" : "复制 JSON"}
            </button>
          ) : null}
        >
          {extraText ? (
            <pre className="thin-scroll max-h-[220px] overflow-auto whitespace-pre-wrap break-all rounded border border-edge bg-cardsoft p-2.5 font-mono text-[10px] leading-[16px] text-ink-2">
              {extraText}
            </pre>
          ) : (
            <Empty text="无附加字段" />
          )}
        </Section>
      </aside>
    </div>
  );
}

function Section({
  title,
  action,
  children,
}: {
  title: string;
  action?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <section className="flex flex-col gap-1.5">
      <div className="flex items-center justify-between">
        <h3 className="font-mono text-[9px] tracking-wider text-ink-3">{title}</h3>
        {action}
      </div>
      {children}
    </section>
  );
}

function Empty({ text }: { text: string }) {
  return <p className="rounded border border-dashed border-edge px-2.5 py-2 text-[10px] text-ink-3">{text}</p>;
}

function Row({ k, v, mono = false }: { k: string; v: string; mono?: boolean }) {
  return (
    <div className="flex items-start gap-3">
      <span className="w-[72px] shrink-0 text-[10.5px] text-ink-3">{k}</span>
      <span className={`min-w-0 flex-1 whitespace-pre-wrap break-words text-[10.5px] text-ink ${mono ? "font-mono" : ""}`}>{v}</span>
    </div>
  );
}
