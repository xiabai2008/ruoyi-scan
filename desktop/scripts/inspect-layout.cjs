/* 检查 Overview 页所有元素的几何位置，找出溢出 viewport 的元素 */
const fs = require("fs");
const path = require("path");

/** 加载 puppeteer：常规依赖 → PUPPETEER_MODULE → npm 全局目录（不硬编码开发机路径） */
function loadPuppeteer() {
  const candidates = [
    "puppeteer",
    process.env.PUPPETEER_MODULE,
    process.env.APPDATA ? path.join(process.env.APPDATA, "npm/node_modules/puppeteer") : null,
  ].filter(Boolean);
  for (const c of candidates) {
    try {
      return require(c);
    } catch {
      /* 尝试下一个候选 */
    }
  }
  throw new Error("未找到 puppeteer：请 `npm i -D puppeteer`，或用 PUPPETEER_MODULE 指向模块目录");
}
const puppeteer = loadPuppeteer();

const TARGET_URL = process.argv[2] || process.env.TARGET_URL || "http://localhost:5173";
const VW = Number(process.env.VIEWPORT_W || 1440);
const VH = Number(process.env.VIEWPORT_H || 900);
const SCALE = Number(process.env.DEVICE_SCALE || 1);

/** Chrome 路径：环境变量优先，其次常见安装位置；都找不到则交给 puppeteer 自带 Chromium */
function resolveChrome() {
  const fromEnv = process.env.PUPPETEER_EXECUTABLE_PATH || process.env.CHROME_PATH;
  if (fromEnv) {
    if (!fs.existsSync(fromEnv)) {
      console.error(`CHROME_PATH/PUPPETEER_EXECUTABLE_PATH 指向的文件不存在: ${fromEnv}`);
      process.exit(1);
    }
    return fromEnv;
  }
  return [
    "C:/Program Files/Google/Chrome/Application/chrome.exe",
    "C:/Program Files (x86)/Google/Chrome/Application/chrome.exe",
    "/usr/bin/google-chrome",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  ].find((p) => fs.existsSync(p)); // undefined → puppeteer 打包的 Chromium
}

let browser = null;

(async () => {
  browser = await puppeteer.launch({
    executablePath: resolveChrome(),
    headless: "new",
    args: ["--no-sandbox", `--window-size=${VW},${VH}`, `--force-device-scale-factor=${SCALE}`],
    defaultViewport: { width: VW, height: VH },
  });
  try {
    const page = await browser.newPage();
    await page.goto(TARGET_URL, { waitUntil: "networkidle2", timeout: 30000 });
    // 等图表 canvas 真正渲染（替代固定 sleep，避免慢机器竞态）
    await page
      .waitForFunction(() => [...document.querySelectorAll("canvas")].some((c) => c.width > 0 && c.height > 0), { timeout: 15000 })
      .catch(() => console.warn("警告：15s 内未等到 canvas 渲染，按当前 DOM 继续检查"));

    const report = await page.evaluate(() => {
      const vw = window.innerWidth, vh = window.innerHeight;
      const out = { viewport: [vw, vh], overflow: [], edge: [] };
      const all = document.querySelectorAll("*");
      for (const el of all) {
        const r = el.getBoundingClientRect();
        if (r.width === 0 && r.height === 0) continue;
        const tag = el.tagName.toLowerCase();
        const cls = (typeof el.className === "string" ? el.className : "").slice(0, 60);
        const id = el.id || "";
        const label = `${tag}${id ? "#" + id : ""}${cls ? "." + cls.split(" ").slice(0, 3).join(".") : ""}`;
        // 超出 viewport 右/下边界的元素
        if (r.right > vw + 1 || r.bottom > vh + 1 || r.left < -1 || r.top < -1) {
          out.overflow.push({ label, rect: [Math.round(r.left), Math.round(r.top), Math.round(r.right), Math.round(r.bottom)] });
        }
        // 贴近右边缘 (right > vw - 8) 的非空元素
        if (r.right > vw - 8 && r.width > 4) {
          out.edge.push({ label, rect: [Math.round(r.left), Math.round(r.top), Math.round(r.right), Math.round(r.bottom)] });
        }
      }
      // canvas 元素重点列出（ECharts）
      out.canvases = [...document.querySelectorAll("canvas")].map((c) => {
        const r = c.getBoundingClientRect();
        return { rect: [Math.round(r.left), Math.round(r.top), Math.round(r.right), Math.round(r.bottom)], w: c.width, h: c.height };
      });
      // 截断前记录总数：报告若只展示 40 条，消费方能判断是否有元素被省略
      out.overflowTotal = out.overflow.length;
      out.edgeTotal = out.edge.length;
      out.overflow = out.overflow.slice(0, 40);
      out.edge = out.edge.slice(0, 40);
      return out;
    });

    console.log(JSON.stringify(report, null, 1));
  } finally {
    // 成功或异常都必须回收 headless Chrome，避免孤儿进程
    await browser.close();
  }
})().catch((e) => {
  console.error("FAIL:", e && e.stack ? e.stack : e);
  process.exit(1);
});
