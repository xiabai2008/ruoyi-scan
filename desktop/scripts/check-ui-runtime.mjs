#!/usr/bin/env node
/**
 * 桌面端运行时交互检查：主题 / CRT / Widgets / 导航 / 控制台异常。
 *
 * 为什么需要
 * ----------
 * tsc 和 vite build 都能过，但「点了没反应」「切换后样式错乱」这类问题
 * 只有真在浏览器里点一遍才看得见（视觉签名字体切换就是这么漏掉的）。
 *
 * 做法：headless Chrome + CDP，逐项触发交互，比对 computed style 与
 * localStorage，同时收集 console error / page error。
 *
 * 用法：node scripts/check-ui-runtime.mjs
 */
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { createServer } from "node:http";
import { dirname, extname, join, resolve } from "node:path";
import { readFile, stat } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const DIST = join(ROOT, "dist");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const MIME = {
  ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8", ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml", ".png": "image/png",
  ".woff": "font/woff", ".woff2": "font/woff2", ".ttf": "font/ttf",
};

function findChrome() {
  return [
    process.env.CHROME_BIN,
    "C:/Program Files/Google/Chrome/Application/chrome.exe",
    "C:/Program Files (x86)/Google/Chrome/Application/chrome.exe",
    "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
    "C:/Program Files/Microsoft/Edge/Application/msedge.exe",
  ].filter(Boolean).find((p) => existsSync(p)) || null;
}

function serve() {
  return new Promise((done) => {
    const s = createServer(async (req, res) => {
      try {
        let p = decodeURIComponent(req.url.split("?")[0]);
        if (p === "/") p = "/index.html";
        const f = join(DIST, p);
        if (!(await stat(f)).isFile()) throw new Error();
        res.writeHead(200, { "Content-Type": MIME[extname(f)] || "application/octet-stream" });
        res.end(await readFile(f));
      } catch {
        try {
          res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
          res.end(await readFile(join(DIST, "index.html")));
        } catch { res.writeHead(404).end("404"); }
      }
    }).listen(0, "127.0.0.1", () => done(s));
  });
}

const problems = [];
const note = (level, area, detail) => problems.push({ level, area, detail });

async function main() {
  if (!existsSync(DIST)) { console.error("dist 不存在，先 npm run build"); process.exit(1); }
  const chrome = findChrome();
  if (!chrome) { console.error("找不到 Chrome/Edge"); process.exit(1); }

  const server = await serve();
  const port = server.address().port;
  const profile = join(process.env.TEMP || "/tmp", `uirun-${Date.now()}`);
  const proc = spawn(chrome, [
    "--headless=new", "--remote-debugging-port=0", `--user-data-dir=${profile}`,
    "--no-first-run", "--disable-gpu", `http://127.0.0.1:${port}/`,
  ], { stdio: ["ignore", "ignore", "pipe"] });

  let wsPort = null;
  proc.stderr.on("data", (b) => {
    const m = /DevTools listening on ws:\/\/[^:]+:(\d+)\//.exec(b.toString());
    if (m && !wsPort) wsPort = Number(m[1]);
  });
  for (let i = 0; i < 100 && !wsPort; i++) await sleep(100);
  if (!wsPort) { console.error("拿不到 DevTools 端口"); proc.kill(); server.close(); process.exit(1); }

  const targets = await (await fetch(`http://127.0.0.1:${wsPort}/json/list`)).json();
  const page = targets.find((t) => t.type === "page");
  const ws = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((r, j) => { ws.onopen = r; ws.onerror = j; });

  let seq = 0;
  const pending = new Map();
  const consoleErrors = [];
  ws.onmessage = (ev) => {
    const m = JSON.parse(ev.data);
    if (m.id && pending.has(m.id)) {
      const p = pending.get(m.id); pending.delete(m.id);
      m.error ? p.reject(new Error(JSON.stringify(m.error))) : p.resolve(m.result);
      return;
    }
    if (m.method === "Runtime.consoleAPICalled" && m.params.type === "error") {
      consoleErrors.push(m.params.args.map((a) => a.value ?? a.description ?? "").join(" "));
    }
    if (m.method === "Runtime.exceptionThrown") {
      consoleErrors.push("EXCEPTION: " + (m.params.exceptionDetails?.text || ""));
    }
  };
  const send = (method, params = {}) => new Promise((ok, reject) => {
    const id = ++seq; pending.set(id, { resolve: ok, reject });
    ws.send(JSON.stringify({ id, method, params }));
  });
  const evl = async (expr) => {
    const r = await send("Runtime.evaluate", { expression: expr, returnByValue: true, awaitPromise: true });
    if (r.exceptionDetails) throw new Error(r.exceptionDetails.text || "eval error");
    return r.result.value;
  };

  await send("Runtime.enable");
  await send("Page.enable");
  for (let i = 0; i < 100; i++) {
    if (await evl("!!document.body && document.body.innerText.length > 20").catch(() => false)) break;
    await sleep(150);
  }

  const goSettings = () => evl(`(() => {
    const e=[...document.querySelectorAll('a,button,div,span,li')]
      .find(x=>x.textContent.trim()==='设置');
    if(!e) return false; e.click(); return true;
  })()`);
  const clickBtn = (label) => evl(`(() => {
    const b=[...document.querySelectorAll('button')].find(x=>x.textContent.trim()===${JSON.stringify(label)});
    if(!b) return false; b.click(); return true;
  })()`);

  // ── 1. 主题切换 ──
  if (!(await goSettings())) note("高", "导航", "找不到「设置」入口");
  await sleep(600);

  const readThemeVar = () => evl(`(() => {
    const cs=getComputedStyle(document.documentElement);
    return { applied: document.documentElement.dataset.theme || null,
             bg: cs.getPropertyValue('--c-bg-page').trim() };
  })()`);

  const themeBefore = await readThemeVar();
  const themeResults = [];
  for (const pack of ["V0 暗夜霓虹", "B 蜜桃CityPop", "C 白瓷薄荷", "A 天选蓝白"]) {
    // 必须用完整 label 匹配：用 "C" 开头匹配会误中 "CREAM POP" 等其它文本
    const ok = await evl(`(() => {
      const t=[...document.querySelectorAll('*')]
        .filter(e=>e.children.length===0 && e.textContent.trim()===${JSON.stringify(pack)})[0];
      if(!t) return false;
      // 点它最近的卡片容器，而不是纯文本节点
      (t.closest('button') || t.parentElement.parentElement || t).click();
      return true;
    })()`);
    if (!ok) { themeResults.push([pack, "按钮未找到"]); continue; }
    await sleep(500);
    themeResults.push([pack, await readThemeVar()]);
  }
  const themeVals = themeResults.map(([, v]) => v && v.bg).filter(Boolean);
  if (new Set(themeVals).size < 2) {
    note("高", "主题切换", `切换 4 个主题包后背景色未变化：${JSON.stringify(themeVals)}`);
  }

  // ── 2. CRT 开关 ──
  const crtOn = await evl(`(() => {
    const sw=document.querySelector('input[type=checkbox],button[role=switch]');
    if(!sw) return null;
    sw.click(); return document.documentElement.dataset.crt;
  })()`);
  await sleep(300);
  const crtState = await evl("document.documentElement.dataset.crt");
  if (crtOn !== null && crtState === "off") {
    note("中", "CRT 开关", "点击后 data-crt 仍为 off");
  }

  // ── 3. 刷新后偏好是否保留 ──
  const prefsBefore = await evl("localStorage.getItem('rs.visual')");
  await send("Page.reload");
  await sleep(1500);
  for (let i = 0; i < 60; i++) {
    if (await evl("!!document.body && document.body.innerText.length > 20").catch(() => false)) break;
    await sleep(150);
  }
  const prefsAfter = await evl("localStorage.getItem('rs.visual')");
  if (prefsBefore && prefsBefore !== prefsAfter) {
    note("中", "偏好持久化", `刷新后 rs.visual 变化: ${prefsBefore} -> ${prefsAfter}`);
  }
  const fontAfterReload = await evl(`(() => {
    const v=localStorage.getItem('rs.visual');
    if(!v) return null;
    const m=JSON.parse(v).fontMode;
    const el=document.querySelector('.font-mono');
    return { saved:m, live: el?getComputedStyle(el).fontFamily:null };
  })()`);
  if (fontAfterReload && fontAfterReload.saved !== "mono") {
    const want = fontAfterReload.saved === "retro" ? /VT323/i : /Silkscreen|Press Start/i;
    if (fontAfterReload.live && !want.test(fontAfterReload.live)) {
      note("高", "字体持久化", `刷新后保存为 ${fontAfterReload.saved} 但实际字体是 ${fontAfterReload.live}`);
    }
  }

  // ── 4. 全部导航页遍历 ──
  const NAV = ["总览", "扫描任务", "漏洞库", "资产管理", "报告中心", "定时任务", "设置"];
  for (const label of NAV) {
    const ok = await evl(`(() => {
      const e=[...document.querySelectorAll('a,button,div,span,li')]
        .find(x=>x.textContent.trim()===${JSON.stringify(label)});
      if(!e) return false; e.click(); return true;
    })()`);
    if (!ok) { note("中", "导航", `找不到导航项「${label}」`); continue; }
    await sleep(500);
    const info = await evl(`({ len: document.body.innerText.length,
                               empty: document.querySelectorAll('main *').length })`);
    if (info.len < 10) note("高", "导航", `「${label}」页面内容为空（innerText 长度 ${info.len}）`);
  }

  // ── 4b. 自定义主题重复应用（原 bug：theme 已是 custom 时完全无效）──
  await goSettings();
  await sleep(500);
  const applyCustomTwice = await evl(`(async () => {
    const pick = (t) => {
      const n = [...document.querySelectorAll('*')]
        .filter(e=>e.children.length===0 && e.textContent.trim()===t)[0];
      if(!n) return false; (n.closest('button')||n.parentElement.parentElement||n).click(); return true;
    };
    if (!pick('C 白瓷薄荷')) return { err: '未找到主题包' };
    await new Promise(r=>setTimeout(r,400));
    const before = getComputedStyle(document.documentElement).getPropertyValue('--c-bg-page').trim();
    const btn = [...document.querySelectorAll('button')].find(b=>b.textContent.trim()==='应用自定义主题');
    if (!btn) return { err: '未找到应用按钮' };
    btn.click();
    await new Promise(r=>setTimeout(r,400));
    const after1 = getComputedStyle(document.documentElement).getPropertyValue('--c-bg-page').trim();
    // 再点一次：theme 已经是 custom，旧实现这里不会重跑 applyTheme
    btn.click();
    await new Promise(r=>setTimeout(r,400));
    const after2 = getComputedStyle(document.documentElement).getPropertyValue('--c-bg-page').trim();
    return { before, after1, after2, theme: document.documentElement.dataset.theme };
  })()`);
  if (applyCustomTwice && !applyCustomTwice.err) {
    if (applyCustomTwice.theme !== "custom") {
      note("中", "自定义主题", `点应用后 data-theme 不是 custom：${applyCustomTwice.theme}`);
    }
    // 关键是第二次点击后仍有正确的 custom 调色板（不是回到上一个主题的值）
    if (applyCustomTwice.after2 !== applyCustomTwice.after1) {
      note("中", "自定义主题", `重复应用后背景色漂移：${applyCustomTwice.after1} -> ${applyCustomTwice.after2}`);
    }
  } else if (applyCustomTwice?.err) {
    note("中", "自定义主题", applyCustomTwice.err);
  }

  // ── 4c. accent-tint 变量必须随主题变化（原来从未定义，恒为蓝）──
  const tintCheck = await evl(`(async () => {
    const pick = (t) => {
      const n = [...document.querySelectorAll('*')]
        .filter(e=>e.children.length===0 && e.textContent.trim()===t)[0];
      if(!n) return false; (n.closest('button')||n.parentElement.parentElement||n).click(); return true;
    };
    const read = () => getComputedStyle(document.documentElement).getPropertyValue('--c-accent-tint').trim();
    if (!pick('V0 暗夜霓虹')) return null;
    await new Promise(r=>setTimeout(r,500));
    const dark = read();
    if (!pick('C 白瓷薄荷')) return null;
    await new Promise(r=>setTimeout(r,500));
    const mint = read();
    return { dark, mint };
  })()`);
  if (tintCheck && tintCheck.dark && tintCheck.mint && tintCheck.dark === tintCheck.mint) {
    note("低", "主题强调色", `--c-accent-tint 未随主题变化，两主题都是 ${tintCheck.dark}`);
  }

  // ── 4d. 新建扫描弹窗打开时 Ctrl+K 不该抢焦点 ──
  const ctrlK = await evl(`(async () => {
    const btn = [...document.querySelectorAll('button')].find(b=>/新建扫描/.test(b.textContent));
    if (!btn) return { err: '未找到新建扫描按钮' };
    btn.click();
    await new Promise(r=>setTimeout(r,400));
    const dlgOpen = !!document.querySelector('.z-40');
    window.dispatchEvent(new KeyboardEvent('keydown', {key:'k', ctrlKey:true, bubbles:true}));
    await new Promise(r=>setTimeout(r,300));
    const focusedId = document.activeElement ? document.activeElement.id : '';
    const stillOpen = !!document.querySelector('.z-40');
    return { dlgOpen, focusedId, stillOpen };
  })()`);
  if (ctrlK && !ctrlK.err && ctrlK.dlgOpen && ctrlK.focusedId === "rs-global-search") {
    note("中", "快捷键冲突", "弹窗打开时 Ctrl+K 仍把焦点抢到搜索框（弹窗内 Esc 会失效）");
  }

  // ── 5. 控制台错误 ──
  for (const e of consoleErrors.slice(0, 5)) {
    note("高", "控制台", e.slice(0, 220));
  }

  console.log("\n=== 主题切换实测 ===");
  console.log(`  初始: ${JSON.stringify(themeBefore)}`);
  for (const [k, v] of themeResults) console.log(`  ${k.padEnd(18)} ${JSON.stringify(v)}`);

  console.log("\n=== 问题清单 ===");
  if (!problems.length) {
    console.log("  未发现运行时问题");
  } else {
    const order = { 高: 0, 中: 1, 低: 2 };
    problems.sort((a, b) => order[a.level] - order[b.level]);
    for (const p of problems) console.log(`  [${p.level}] ${p.area}: ${p.detail}`);
  }

  ws.close(); proc.kill(); server.close();
  const high = problems.filter((p) => p.level === "高").length;
  console.log(`\n${high ? `[ui-runtime] 发现 ${high} 个高优先级问题` : "[ui-runtime] OK"}`);
  process.exit(high ? 1 : 0);
}

main().catch((e) => { console.error("[ui-runtime] 异常:", e); process.exit(1); });
