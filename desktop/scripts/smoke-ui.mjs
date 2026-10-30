#!/usr/bin/env node
/**
 * 桌面端构建产物 UI 冒烟（零第三方依赖，直连 Chrome DevTools Protocol）。
 *
 * 背景：v1.5.0 的「新建扫描」白屏（条件 Hook → React #310）可以通过 tsc / vite build，
 * 只有真实运行才会崩溃。本脚本在 CI 中加载 `dist`，点击「新建扫描」并遍历全部导航页，
 * 任何未捕获异常 / React 控制台错误都会让构建立即失败。
 *
 * 环境变量：
 *   CHROME_BIN 指定 Chrome/Edge 可执行文件（默认自动探测常见路径）
 *
 * 要求：Node.js >= 22（内置 WebSocket）。
 */
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { dirname, extname, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const DIST = join(ROOT, "dist");
const NAV_LABELS = ["总览", "扫描任务", "漏洞库", "资产管理", "报告中心", "定时任务", "设置"];
const sleep = (ms) => new Promise((resolveSleep) => setTimeout(resolveSleep, ms));

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".ico": "image/x-icon",
  ".woff": "font/woff",
  ".woff2": "font/woff2",
  ".ttf": "font/ttf",
  ".map": "application/json; charset=utf-8",
};

if (typeof WebSocket !== "function") {
  console.error("[ui-smoke] 需要 Node.js >= 22（内置 WebSocket）");
  process.exit(1);
}

function findChrome() {
  const candidates = [
    process.env.CHROME_BIN,
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
    "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
    "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  ].filter(Boolean);

  for (const candidate of candidates) {
    if (existsSync(candidate)) return candidate;
  }
  throw new Error("未找到 Chrome/Edge，可通过 CHROME_BIN 指定可执行文件路径");
}

function startStaticServer() {
  const server = createServer(async (req, res) => {
    try {
      const pathname = decodeURIComponent(new URL(req.url, "http://127.0.0.1").pathname);
      const rel = pathname.endsWith("/") ? `${pathname}index.html` : pathname;
      let file = resolve(DIST, `.${rel}`);
      if (!file.startsWith(DIST + sep)) {
        res.writeHead(403).end("forbidden");
        return;
      }

      let info = null;
      try {
        info = await stat(file);
      } catch {
        info = null;
      }
      if (!info || !info.isFile()) file = join(DIST, "index.html");

      const body = await readFile(file);
      res.writeHead(200, {
        "content-type": MIME[extname(file).toLowerCase()] || "application/octet-stream",
        "cache-control": "no-store",
      });
      res.end(body);
    } catch (err) {
      res.writeHead(500).end(String(err));
    }
  });

  return new Promise((resolveListen, rejectListen) => {
    server.once("error", rejectListen);
    server.listen(0, "127.0.0.1", () => resolveListen(server));
  });
}

class CDP {
  constructor(url) {
    this.ws = new WebSocket(url);
    this.nextId = 1;
    this.pending = new Map();
    this.events = [];
    this.ws.onmessage = (event) => {
      const msg = JSON.parse(event.data);
      if (msg.id && this.pending.has(msg.id)) {
        const { resolveSend, rejectSend } = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        if (msg.error) rejectSend(new Error(msg.error.message));
        else resolveSend(msg.result ?? {});
      } else if (msg.method) {
        this.events.push(msg);
      }
    };
  }

  async open() {
    if (this.ws.readyState === WebSocket.OPEN) return;
    await new Promise((resolveOpen, rejectOpen) => {
      this.ws.onopen = resolveOpen;
      this.ws.onerror = () => rejectOpen(new Error("CDP WebSocket 连接失败"));
    });
  }

  send(method, params = {}) {
    return new Promise((resolveSend, rejectSend) => {
      const id = this.nextId++;
      this.pending.set(id, { resolveSend, rejectSend });
      this.ws.send(JSON.stringify({ id, method, params }));
    });
  }

  close() {
    try {
      this.ws.close();
    } catch {
      /* ignore */
    }
  }
}

async function evaluate(cdp, expression) {
  const result = await cdp.send("Runtime.evaluate", {
    expression,
    returnByValue: true,
    awaitPromise: true,
  });
  if (result.exceptionDetails) {
    const details = result.exceptionDetails;
    throw new Error(details.exception?.description || details.text || "Runtime.evaluate 失败");
  }
  return result.result?.value;
}

async function waitFor(cdp, expression, timeoutMs, label) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (await evaluate(cdp, expression)) return;
    await sleep(150);
  }
  const length = await evaluate(cdp, "document.documentElement.innerHTML.length").catch(() => "?");
  throw new Error(`等待超时：${label}（html length=${length}）`);
}

async function clickByText(cdp, label) {
  const clicked = await evaluate(
    cdp,
    `(() => {
      const el = Array.from(document.querySelectorAll("button, a")).find((node) =>
        (node.innerText || "").includes(${JSON.stringify(label)})
      );
      if (!el) return false;
      el.click();
      return true;
    })()`,
  );
  if (!clicked) throw new Error(`找不到可点击元素：${label}`);
}

function isExpectedNoise(text) {
  return /127\.0\.0\.1:8123|net::ERR|Failed to load resource|favicon|ERR_BLOCKED_BY_CLIENT|WebSocket connection to/i.test(
    text,
  );
}

function collectIssues(cdp) {
  const issues = [];
  for (const msg of cdp.events) {
    if (msg.method === "Runtime.exceptionThrown") {
      const details = msg.params.exceptionDetails || {};
      const desc = details.exception?.description || details.text || "unknown exception";
      issues.push(`未捕获异常: ${String(desc).split("\n")[0]}`);
    } else if (msg.method === "Runtime.consoleAPICalled" && msg.params.type === "error") {
      const text = (msg.params.args || [])
        .map((arg) => arg.value ?? arg.description ?? "")
        .join(" ")
        .trim();
      if (text && !isExpectedNoise(text)) issues.push(`console.error: ${text.slice(0, 500)}`);
    }
  }
  return [...new Set(issues)];
}

async function waitForDevToolsPort(profile, chrome, timeoutMs = 20000) {
  const portFile = join(profile, "DevToolsActivePort");
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (chrome.exitCode !== null) {
      throw new Error(`Chrome 提前退出（code=${chrome.exitCode}）`);
    }
    if (existsSync(portFile)) {
      const text = await readFile(portFile, "utf8");
      const port = Number(text.split(/\r?\n/)[0]);
      if (Number.isInteger(port) && port > 0) return port;
    }
    await sleep(100);
  }
  throw new Error("等待 Chrome DevTools 端口超时");
}

async function waitForPageTarget(port, timeoutMs = 15000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const res = await fetch(`http://127.0.0.1:${port}/json/list`);
      if (res.ok) {
        const list = await res.json();
        const page = list.find((target) => target.type === "page" && target.webSocketDebuggerUrl);
        if (page) return page;
      }
    } catch {
      /* 继续等待 */
    }
    await sleep(150);
  }
  throw new Error("等待 Chrome page target 超时");
}

async function stopChrome(chrome) {
  if (!chrome || chrome.exitCode !== null) return;
  if (process.platform === "win32") {
    await new Promise((resolveKill) => {
      const killer = spawn("taskkill", ["/pid", String(chrome.pid), "/T", "/F"], {
        stdio: "ignore",
        windowsHide: true,
      });
      killer.once("exit", resolveKill);
      killer.once("error", resolveKill);
    });
  } else {
    chrome.kill("SIGKILL");
  }
  if (chrome.exitCode === null) {
    await Promise.race([
      new Promise((resolveExit) => chrome.once("exit", resolveExit)),
      sleep(3000),
    ]);
  }
}

async function run() {
  const server = await startStaticServer();
  const profile = await mkdtemp(join(tmpdir(), "ruoyi-ui-smoke-"));
  const chrome = spawn(
    findChrome(),
    [
      "--headless=new",
      "--disable-gpu",
      "--no-sandbox",
      "--disable-setuid-sandbox",
      "--disable-dev-shm-usage",
      "--no-first-run",
      "--no-default-browser-check",
      "--disable-extensions",
      "--mute-audio",
      `--user-data-dir=${profile}`,
      "--remote-debugging-port=0",
      "about:blank",
    ],
    { stdio: "ignore", windowsHide: true },
  );

  let cdp = null;
  try {
    const port = await waitForDevToolsPort(profile, chrome);
    const target = await waitForPageTarget(port);
    cdp = new CDP(target.webSocketDebuggerUrl);
    await cdp.open();

    await cdp.send("Page.enable");
    await cdp.send("Runtime.enable");
    await cdp.send("Log.enable");
    await cdp.send("Network.enable");
    // 强制后端离线，保证本地/CI 行为一致（应用会进入 ENGINE OFFLINE 状态）
    await cdp.send("Network.setBlockedURLs", {
      urls: ["http://127.0.0.1:8123/*", "ws://127.0.0.1:8123/*"],
    });

    const baseUrl = `http://127.0.0.1:${server.address().port}/`;
    await cdp.send("Page.navigate", { url: baseUrl });

    await waitFor(
      cdp,
      "document.readyState === 'complete' && !!document.querySelector('#root') && document.querySelector('#root').children.length > 0",
      20000,
      "应用挂载",
    );
    await waitFor(cdp, "document.body.innerText.includes('新建扫描')", 15000, "总览页渲染");

    await clickByText(cdp, "新建扫描");
    await waitFor(
      cdp,
      "!!document.querySelector('.z-40') && document.body.innerText.includes('扫描目标')",
      8000,
      "新建扫描弹窗渲染",
    );

    const dialogLength = await evaluate(cdp, "document.documentElement.innerHTML.length");
    if (!dialogLength || dialogLength < 5000) {
      throw new Error(`弹窗打开后 DOM 异常（html length=${dialogLength}，疑似整树卸载）`);
    }

    // 关闭弹窗（点击遮罩）
    await evaluate(cdp, "document.querySelector('.z-40 > div')?.click(); true");
    await waitFor(cdp, "!document.querySelector('.z-40')", 5000, "关闭新建扫描弹窗");

    for (const label of NAV_LABELS) {
      await clickByText(cdp, label);
      await sleep(400);
      const alive = await evaluate(
        cdp,
        "document.documentElement.innerHTML.length > 5000 && document.querySelector('#root').children.length > 0",
      );
      if (!alive) {
        throw new Error(`导航到「${label}」后页面异常（疑似整树卸载）`);
      }
    }

    const issues = collectIssues(cdp);
    if (issues.length > 0) {
      throw new Error(`发现运行时错误：\n- ${issues.join("\n- ")}`);
    }

    console.log(`[ui-smoke] OK：新建扫描弹窗 + ${NAV_LABELS.length} 个导航页均正常，未发现运行时异常`);
  } catch (err) {
    if (cdp) {
      try {
        const shot = await cdp.send("Page.captureScreenshot", { format: "png" });
        const outPath = join(process.env.RUNNER_TEMP || tmpdir(), "ruoyi-ui-smoke-failure.png");
        await writeFile(outPath, Buffer.from(shot.data, "base64"));
        console.error(`[ui-smoke] 失败截图：${outPath}`);
      } catch {
        /* 截图失败不影响原始错误 */
      }
    }
    throw err;
  } finally {
    cdp?.close();
    await stopChrome(chrome);
    await new Promise((resolveClose) => server.close(resolveClose));
    await rm(profile, { recursive: true, force: true }).catch(() => {});
  }
}

run().catch((err) => {
  console.error(`[ui-smoke] FAIL: ${err.message}`);
  process.exit(1);
});
