/**
 * 扫描目标校验（与后端 core.http.normalize_scan_target 的规则保持一致）
 *
 * 旧实现只校验非空：输入 `abc` 会直接建任务并以登录爆破模式跑完，产出
 * 两条 UNKNOWN 和一份报告（测评 P1-6）。这里在提交前拦住明显非法的目标，
 * 并把“无协议自动补 http://”显式告知用户。
 */

export type TargetCheck =
  | { ok: true; url: string; note?: string }
  | { ok: false; error: string };

const IPV4_RE = /^(?:\d{1,3}\.){3}\d{1,3}$/;
// IPv6 字面量必然含冒号；只看 [0-9a-f:] 会把 "abc"/"deadbeef" 误判为 IPv6，
// 从而放过裸主机名（实测输入 abc 直接建任务）。
const IPV6_RE = /^\[?[0-9a-f]*:[0-9a-f:.]*\]?$/i;

export function validateTarget(raw: string): TargetCheck {
  const text = (raw || "").trim();
  if (!text) return { ok: false, error: "目标 URL 不能为空" };
  if (/\s/.test(text)) return { ok: false, error: "目标不能包含空格或换行" };
  // 控制字符（含粘贴进来的不可见字符）
  for (const ch of text) {
    if (ch.charCodeAt(0) < 0x20) return { ok: false, error: "目标包含控制字符" };
  }

  const hadScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(text);
  const candidate = hadScheme ? text : `http://${text}`;
  let url: URL;
  try {
    url = new URL(candidate);
  } catch {
    return { ok: false, error: "目标格式无法解析，请填写 http(s)://host:port/" };
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return { ok: false, error: `仅支持 http/https，当前为 ${url.protocol}//` };
  }
  if (!url.hostname) return { ok: false, error: "目标缺少主机名" };
  if (url.port !== "" && !/^\d+$/.test(url.port)) {
    return { ok: false, error: "端口必须是 1-65535 的数字" };
  }

  // 裸主机名（如 "abc"）几乎不可能是可扫描目标：要求带域名后缀、是 IP、
  // 是 localhost，或显式给了端口（内网单标签主机通常写作 host:port）。
  const host = url.hostname;
  const singleLabel = !host.includes(".") && !IPV4_RE.test(host) && !IPV6_RE.test(host);
  const allowedSingle = host.toLowerCase() === "localhost" || url.port !== "";
  if (singleLabel && !allowedSingle) {
    return {
      ok: false,
      error: "这看起来不是有效地址：请填写完整域名（如 https://demo.example.com/）或 host:port",
    };
  }

  return {
    ok: true,
    url: url.toString(),
    note: hadScheme ? undefined : "已自动补全 http://",
  };
}
