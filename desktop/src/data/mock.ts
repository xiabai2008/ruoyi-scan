/** 与画布设计稿一致的演示数据（后续由 FastAPI sidecar 真实数据替换） */

export type Verdict = "CONFIRMED" | "SAFE" | "UNKNOWN";
export type Severity = "CRITICAL" | "HIGH" | "MED" | "LOW";

export const NAV = [
  { id: "overview", num: "01", label: "总览" },
  { id: "livescan", num: "02", label: "扫描任务" },
  { id: "vulndb", num: "03", label: "漏洞库" },
  { id: "assets", num: "04", label: "资产管理" },
  { id: "reports", num: "05", label: "报告中心" },
  { id: "settings", num: "06", label: "设置" },
] as const;

export type ViewId = (typeof NAV)[number]["id"];

/* ---------- 01 总览 ---------- */
export const overviewKpis = [
  { en: "TARGETS", value: "128", delta: "+12.3% WoW", up: true, tone: "green" as const, zh: "在管资产" },
  { en: "SCANS TODAY", value: "26", delta: "+3 DAILY", up: true, tone: "accent" as const, zh: "今日任务" },
  { en: "CONFIRMED", value: "17", delta: "+2 DAILY", up: true, tone: "red" as const, zh: "已确认漏洞" },
  { en: "POC LOADED", value: "52", delta: "4 FRAMEWORKS", up: null, tone: "purple" as const, zh: "插件覆盖" },
];

export const trendDates = ["09-03", "09-04", "09-05", "09-06", "09-07", "09-08", "09-09"];
export const trendFound = [26, 32, 38, 50, 46, 60, 68];
export const trendConfirmed = [52, 58, 70, 76, 88, 98, 104];

export const verdictMix = [
  { label: "CONFIRMED 已确认", value: 17, pct: "14%" },
  { label: "SAFE 安全", value: 86, pct: "73%" },
  { label: "UNKNOWN 待定", value: 15, pct: "13%" },
];

export interface Finding {
  sev: Severity;
  name: string;
  plugin: string;
  verdict: Verdict;
  time: string;
}

export const recentFindings: Finding[] = [
  { sev: "CRITICAL", name: "若依默认口令 admin/admin123", plugin: "ruoyi/default-password", verdict: "CONFIRMED", time: "09:18:42" },
  { sev: "HIGH", name: "Druid 未授权访问", plugin: "common/druid-unauth", verdict: "CONFIRMED", time: "09:17:05" },
  { sev: "MED", name: "Spring Boot Actuator 端点暴露", plugin: "spring/actuator-exposure", verdict: "UNKNOWN", time: "09:15:37" },
  { sev: "LOW", name: "Swagger 接口暴露", plugin: "common/swagger-exposed", verdict: "SAFE", time: "09:14:20" },
  { sev: "HIGH", name: "JeecgBoot jmLink SSTI 模板注入", plugin: "jeecgboot/jmlink-ssti", verdict: "UNKNOWN", time: "09:12:11" },
  { sev: "MED", name: "Shiro rememberMe 默认密钥", plugin: "common/shiro-key", verdict: "CONFIRMED", time: "09:11:03" },
  { sev: "LOW", name: "Tomcat 示例应用暴露", plugin: "common/tomcat-examples", verdict: "SAFE", time: "09:10:44" },
  { sev: "HIGH", name: "若依 Snapshot 任意文件下载", plugin: "ruoyi/snapshot-download", verdict: "CONFIRMED", time: "09:09:18" },
];

/* ---------- 02 扫描现场 ---------- */
export interface LogLine {
  time: string;
  level: "info" | "route" | "confirmed" | "safe" | "unknown" | "meiyi";
  text: string;
}

export const liveLogs: LogLine[] = [
  { time: "09:20:01", level: "info", text: "fingerprint: RuoYi 4.7.6 detected (confidence 0.97)" },
  { time: "09:20:03", level: "info", text: "waf: no WAF detected, proceeding direct" },
  { time: "09:20:05", level: "route", text: "route: /admin /druid /api /job discovered" },
  { time: "09:20:07", level: "confirmed", text: "CONFIRMED  ruoyi/default-password -> admin/admin123" },
  { time: "09:20:09", level: "safe", text: "SAFE      spring/actuator-exposure -> HTTP 401" },
  { time: "09:20:12", level: "unknown", text: "UNKNOWN   common/druid-unauth -> 200, needs review" },
  { time: "09:20:15", level: "info", text: "pool: 32 workers · token bucket 8 rps" },
  { time: "09:20:18", level: "confirmed", text: "CONFIRMED  common/shiro-key -> rememberMe RCE" },
  { time: "09:20:22", level: "safe", text: "SAFE      jeecgboot/jmlink-ssti -> patched" },
  { time: "09:20:26", level: "unknown", text: "UNKNOWN   spring/snakeyaml -> slow response" },
  { time: "09:20:31", level: "route", text: "progress: 23/52 plugins · elapsed 00:12:47" },
  { time: "09:20:33", level: "meiyi", text: "MEIYI: Druid 未授权已确认，深挖数据源配置中…" },
  { time: "09:20:38", level: "safe", text: "SAFE      ruoyi/quartz-ldap -> connection refused" },
  { time: "09:20:44", level: "unknown", text: "UNKNOWN   common/fastjson-1232 -> dnslog no echo, retry 2/3" },
  { time: "09:20:49", level: "safe", text: "SAFE      spring/cloud-gateway-spel -> patched" },
  { time: "09:20:55", level: "unknown", text: "UNKNOWN   jeecgboot/freemarker-sst -> echo blocked" },
  { time: "09:20:58", level: "route", text: "tally:   CONFIRMED 7 / SAFE 12 / UNKNOWN 4 (23 run)" },
  { time: "09:21:00", level: "info", text: "engine:  24/52 plugins · eta 00:09:12" },
];

export const liveStats = [
  { label: "CONFIRMED 已确认", value: "7", tone: "red" as const, icon: "target" },
  { label: "SAFE 安全", value: "12", tone: "green" as const, icon: "check" },
  { label: "UNKNOWN 待人工复核", value: "4", tone: "amber" as const, icon: "diamond" },
  { label: "ENGINE 吞吐", value: "8.0 RPS", tone: "purple" as const, icon: "bolt" },
];

/* ---------- 03 漏洞库 ---------- */
export const pocFilters = [
  { label: "全部", count: 52, active: true },
  { label: "ruoyi", count: 18, mono: true },
  { label: "spring", count: 14, mono: true },
  { label: "common", count: 12, mono: true },
  { label: "jeecgboot", count: 8, mono: true },
];

export const verdictFilters = [
  { label: "CONFIRMED", count: 21, tone: "red" as const },
  { label: "UNKNOWN", count: 9, tone: "amber" as const },
];

export const pocs: Finding[] = [
  { sev: "CRITICAL", name: "若依默认口令利用", plugin: "ruoyi/default-password", verdict: "CONFIRMED", time: "09-08" },
  { sev: "HIGH", name: "Druid 未授权访问", plugin: "common/druid-unauth", verdict: "CONFIRMED", time: "09-08" },
  { sev: "MED", name: "Fastjson 1.2.32 反序列化", plugin: "common/fastjson-1232", verdict: "UNKNOWN", time: "09-07" },
  { sev: "LOW", name: "Swagger 接口暴露", plugin: "common/swagger-exposed", verdict: "SAFE", time: "09-07" },
  { sev: "HIGH", name: "JeecgBoot jmLink SSTI", plugin: "jeecgboot/jmlink-ssti", verdict: "UNKNOWN", time: "09-06" },
  { sev: "LOW", name: "Spring Cloud Gateway SpEL", plugin: "spring/gateway-spel", verdict: "SAFE", time: "09-05" },
];

/* ---------- 04 资产管理 ---------- */
export const assetGroups = [
  { label: "全部资产", count: 128, active: true },
  { label: "生产环境", count: 46 },
  { label: "测试环境", count: 52 },
  { label: "Docker 实验室", count: 21 },
  { label: "边缘节点", count: 9 },
];

export const assetKpis = [
  { en: "TARGETS", value: "128", delta: "+3 WEEK", up: true, tone: "green" as const, zh: "在管资产" },
  { en: "ALIVE", value: "91", delta: "+5 DAILY", up: true, tone: "accent" as const, zh: "存活主机" },
  { en: "HIGH RISK", value: "9", delta: "2 CRITICAL", up: true, tone: "red" as const, zh: "高危资产" },
  { en: "GROUPS", value: "6", delta: "2 CUSTOM", up: null, tone: "purple" as const, zh: "资产分组" },
];

export interface Asset {
  alive: boolean;
  url: string;
  fingerprint: string;
  port: string;
  scanned: string;
}

export const assets: Asset[] = [
  { alive: true, url: "http://10.211.55.3:8080", fingerprint: "RuoYi 4.7.6 · Java", port: "8080", scanned: "09:20" },
  { alive: true, url: "http://172.17.0.2:8081", fingerprint: "JeecgBoot 3.5.1", port: "8081", scanned: "08:47" },
  { alive: true, url: "http://10.211.55.7:9090", fingerprint: "Spring Boot 2.7", port: "9090", scanned: "22:31" },
  { alive: false, url: "http://192.168.31.20:80", fingerprint: "未知", port: "80", scanned: "14:02" },
  { alive: true, url: "http://10.211.55.9:8082", fingerprint: "RuoYi v3 前后端分离", port: "8082", scanned: "18:05" },
  { alive: true, url: "http://172.17.0.3:8080", fingerprint: "RuoYi-Cloud Gateway", port: "8080", scanned: "16:40" },
];

/* ---------- 05 报告中心 ---------- */
export const reportKpis = [
  { en: "REPORTS", value: "12", delta: "+2 MONTH", up: true, tone: "green" as const, zh: "本月报告" },
  { en: "EXPORTS", value: "49", delta: "+6 WEEK", up: true, tone: "accent" as const, zh: "累计导出" },
  { en: "AVG TIME", value: "8S", delta: "-1.2S MoM", up: false, tone: "accent" as const, zh: "平均耗时" },
  { en: "TEMPLATES", value: "3", delta: "3 FORMATS", up: null, tone: "purple" as const, zh: "报告模板" },
];

export const reportTrendFound = [2, 3, 2, 5, 4, 6, 3];
export const reportTrendTotal = [18, 22, 26, 30, 36, 42, 49];

export const formatMix = [
  { label: "HTML 网页版", value: 26, pct: "53%" },
  { label: "XLSX 表格", value: 14, pct: "29%" },
  { label: "PDF / DOCX", value: 9, pct: "18%" },
];

export interface Report {
  fmt: "PDF" | "HTML" | "XLSX" | "DOCX";
  name: string;
  scope: string;
  done: boolean;
  time: string;
}

export const reports: Report[] = [
  { fmt: "PDF", name: "毕设中期演示报告 v1.2", scope: "全部资产 · 三态摘要", done: true, time: "09-08" },
  { fmt: "HTML", name: "每日扫描快照 09-09", scope: "生产环境", done: true, time: "09-09" },
  { fmt: "XLSX", name: "漏洞明细导出", scope: "CONFIRMED 全量", done: true, time: "09-07" },
  { fmt: "DOCX", name: "开题报告附图数据", scope: "趋势统计", done: false, time: "09-09" },
];

/* ---------- 06 设置 ---------- */
export const engineRows = [
  { label: "并发线程数", control: { kind: "chip" as const, text: "32" } },
  { label: "全局请求速率", control: { kind: "chip" as const, text: "8.0 r/s" } },
  { label: "WAF 指纹识别", control: { kind: "toggle" as const, on: true } },
  { label: "递归扫描子目录", control: { kind: "toggle" as const, on: false } },
];
