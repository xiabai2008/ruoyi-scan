#!/usr/bin/env node
/**
 * 视觉签名「字体切换」回归验证。
 *
 * 为什么单独写一个
 * ----------------
 * 这个 bug 的形态很隐蔽：UI 上三个按钮都正常高亮、localStorage 也存对了，
 * 但页面字体纹丝不动。根因是 Tailwind v4 的 @theme inline 把字体栈
 * 直接烧进了 .font-mono 工具类（产物里是字面值而非 var()），于是
 * applyVisual() 在运行时改变量毫无效果。
 *
 * 光看构建产物不够 —— 必须真的在浏览器里点一下、量 computed style。
 *
 * 用法：node scripts/check-font-switch.mjs [dist 目录]
 */
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { createServer } from "node:http";
import { dirname, extname, join, resolve } from "node:path";
import { readFile, stat } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const DIST = process.argv[2] ? resolve(process.argv[2]) : join(ROOT, "dist");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".woff": "font/woff",
  ".woff2": "font/woff2",
  ".ttf": "font/ttf",
};

function findChrome() {
  const cands = [
    process.env.CHROME_BIN,
    "C:/Program Files/Google/Chrome/Application/chrome.exe",
    "C:/Program Files (x86)/Google/Chrome/Application/chrome.exe",
    "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
    "C:/Program Files/Microsoft/Edge/Application/msedge.exe",
  ].filter(Boolean);
  return cands.find((p) => existsSync(p)) || null;
}

function serve() {
  return new Promise((resolveServer) => {
    const server = createServer(async (req, res) => {
      try {
        let path = decodeURIComponent(req.url.split("?")[0]);
        if (path === "/") path = "/index.html";
        const file = join(DIST, path);
        const info = await stat(file);
        if (!info.isFile()) throw new Error("not a file");
        const body = await readFile(file);
        res.writeHead(200, { "Content-Type": MIME[extname(file)] || "application/octet-stream" });
        res.end(body);
      } catch {
        try {
          const html = await readFile(join(DIST, "index.html"));
          res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
          res.end(html);
        } catch {
          res.writeHead(404).end("404");
        }
      }
    });
    server.listen(0, "127.0.0.1", () => resolveServer(server));
  });
}

async function main() {
  if (!existsSync(DIST)) {
    console.error(`[font-check] dist 不存在：${DIST}  先跑 npm run build`);
    process.exit(1);
  }
  const chrome = findChrome();
  if (!chrome) {
    console.error("[font-check] 找不到 Chrome/Edge，设 CHROME_BIN 指定");
    process.exit(1);
  }

  const server = await serve();
  const port = server.address().port;
  const url = `http://127.0.0.1:${port}/`;
  const profile = join(process.env.TEMP || "/tmp", `fontcheck-${Date.now()}`);

  const proc = spawn(chrome, [
    "--headless=new",
    "--remote-debugging-port=0",
    `--user-data-dir=${profile}`,
    "--no-first-run",
    "--disable-gpu",
    url,
  ], { stdio: ["ignore", "ignore", "pipe"] });

  // 从 stderr 里抓 DevTools 实际端口
  let wsPort = null;
  proc.stderr.on("data", (buf) => {
    const m = /DevTools listening on ws:\/\/[^:]+:(\d+)\//.exec(buf.toString());
    if (m && !wsPort) wsPort = Number(m[1]);
  });
  for (let i = 0; i < 100 && !wsPort; i++) await sleep(100);
  if (!wsPort) {
    console.error("[font-check] 拿不到 DevTools 端口");
    proc.kill();
    server.close();
    process.exit(1);
  }

  const listRes = await fetch(`http://127.0.0.1:${wsPort}/json/list`);
  const targets = await listRes.json();
  const page = targets.find((t) => t.type === "page");
  if (!page) {
    console.error("[font-check] 没有 page target");
    proc.kill();
    server.close();
    process.exit(1);
  }

  const ws = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((r, j) => { ws.onopen = r; ws.onerror = j; });
  let seq = 0;
  const pending = new Map();
  ws.onmessage = (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.id && pending.has(msg.id)) {
      const { resolve: ok, reject } = pending.get(msg.id);
      pending.delete(msg.id);
      msg.error ? reject(new Error(JSON.stringify(msg.error))) : ok(msg.result);
    }
  };
  const send = (method, params = {}) =>
    new Promise((ok, reject) => {
      const id = ++seq;
      pending.set(id, { resolve: ok, reject });
      ws.send(JSON.stringify({ id, method, params }));
    });

  const evaluate = async (expression) => {
    const r = await send("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
    if (r.exceptionDetails) throw new Error(r.exceptionDetails.text || "eval failed");
    return r.result.value;
  };

  await send("Runtime.enable");
  // 等应用挂载
  for (let i = 0; i < 80; i++) {
    const ok = await evaluate(
      "!!document.querySelector('body') && document.body.innerText.length > 20"
    ).catch(() => false);
    if (ok) break;
    await sleep(150);
  }

  // 进「设置」页
  const went = await evaluate(`(() => {
    const els = [...document.querySelectorAll('a,button,div,span,li')];
    const t = els.find(e => e.textContent.trim() === '设置' || e.textContent.trim() === '07  设置');
    if (!t) return false;
    t.click();
    return true;
  })()`);
  if (!went) {
    console.error("[font-check] 找不到「设置」导航");
    ws.close(); proc.kill(); server.close();
    process.exit(1);
  }
  await sleep(700);

  // 读出某个 .font-mono 元素的实际字体
  const readMono = () => evaluate(`(() => {
    const el = document.querySelector('.font-mono');
    if (!el) return null;
    const cs = getComputedStyle(el);
    return { family: cs.fontFamily, fMono: getComputedStyle(document.documentElement).getPropertyValue('--f-mono').trim() };
  })()`);

  const clickFont = (label) => evaluate(`(() => {
    const els = [...document.querySelectorAll('button')];
    const b = els.find(e => e.textContent.trim() === ${JSON.stringify(label)});
    if (!b) return false;
    b.click();
    return true;
  })()`);

  const results = [];
  const before = await readMono();
  results.push(["初始（等宽）", before]);

  for (const label of ["复古终端", "像素街机", "等宽"]) {
    const ok = await clickFont(label);
    if (!ok) {
      console.error(`[font-check] 找不到字体按钮：${label}`);
      continue;
    }
    // 等字体 import + 重排
    await sleep(900);
    results.push([label, await readMono()]);
  }

  console.log("\n=== 字体切换实测（computed font-family）===");
  for (const [label, v] of results) {
    console.log(`  ${String(label).padEnd(14)} ${v ? v.family : "(无 .font-mono 元素)"}`);
  }

  // 判定：三次点击必须产生三种不同字体栈
  const families = results.slice(1, 4).map(([, v]) => v && v.family);
  const uniq = new Set(families.filter(Boolean));
  const distinct = uniq.size >= 3;
  const retroOk = families[0] && /VT323/i.test(families[0]);
  const pixelOk = families[1] && /Silkscreen|Press Start/i.test(families[1]);
  const backOk = families[2] && /JetBrains|Cascadia|Consolas/i.test(families[2]);

  console.log("\n=== 结论 ===");
  console.log(`  切换后字体栈互不相同 : ${distinct ? "PASS" : "FAIL"}`);
  console.log(`  复古终端 -> VT323     : ${retroOk ? "PASS" : "FAIL"}`);
  console.log(`  像素街机 -> Silkscreen: ${pixelOk ? "PASS" : "FAIL"}`);
  console.log(`  切回等宽 -> JetBrains : ${backOk ? "PASS" : "FAIL"}`);

  ws.close();
  proc.kill();
  server.close();

  const allPass = distinct && retroOk && pixelOk && backOk;
  console.log(`\n${allPass ? "[font-check] OK" : "[font-check] 存在问题"}`);
  process.exit(allPass ? 0 : 1);
}

main().catch((e) => {
  console.error("[font-check] 异常:", e);
  process.exit(1);
});
