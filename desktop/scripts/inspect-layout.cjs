/* 检查 Overview 页所有元素的几何位置，找出溢出 viewport 的元素 */
const puppeteer = require("C:/Users/HZR/AppData/Roaming/npm/node_modules/puppeteer");

(async () => {
  const browser = await puppeteer.launch({
    executablePath: "C:/Program Files/Google/Chrome/Application/chrome.exe",
    headless: "new",
    args: ["--no-sandbox", "--window-size=1440,900", "--force-device-scale-factor=1"],
    defaultViewport: { width: 1440, height: 900 },
  });
  const page = await browser.newPage();
  await page.goto("http://localhost:5173", { waitUntil: "networkidle2", timeout: 30000 });
  await new Promise((r) => setTimeout(r, 2500)); // 等图表渲染

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
    out.overflow = out.overflow.slice(0, 40);
    out.edge = out.edge.slice(0, 40);
    return out;
  });

  console.log(JSON.stringify(report, null, 1));
  await browser.close();
})().catch((e) => { console.error("FAIL:", e.message); process.exit(1); });
