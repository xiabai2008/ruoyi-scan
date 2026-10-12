/**
 * 抓取桌面端 README 展示截图（6 个页面）
 *
 * 前置条件：
 *   1. vite dev 已在 http://localhost:5173 运行（cd desktop && npm run dev）
 *   2. 引擎已在 127.0.0.1:8123 运行且 CORS 放行 5173：
 *      desktop/engine/dist/ruoyi-scan-engine.exe --serve --host 127.0.0.1 --port 8123 \
 *        --cors-origins "http://localhost:5173,http://127.0.0.1:5173"
 *
 * 用法：node desktop/scripts/capture-readme-shots.cjs
 * 产物：docs/images/desktop-0*.png（1440×900 @2x）
 */
const path = require("path");
const fs = require("fs");
const puppeteer = require("C:/Users/HZR/AppData/Roaming/npm/node_modules/puppeteer");

const CHROME = "C:/Program Files/Google/Chrome/Application/chrome.exe";
const URL = "http://localhost:5173";
const ROOT = path.resolve(__dirname, "../..");
const OUT = path.join(ROOT, "docs/images");

const PAGES = [
  { file: "desktop-01-overview.png", label: "总览" },
  { file: "desktop-02-livescan.png", label: "扫描任务", expand: "结果明细" },
  { file: "desktop-03-vulndb.png", label: "漏洞库" },
  { file: "desktop-04-assets.png", label: "资产管理" },
  { file: "desktop-05-reports.png", label: "报告中心" },
  { file: "desktop-06-settings.png", label: "设置" },
];

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
  fs.mkdirSync(OUT, { recursive: true });

  const browser = await puppeteer.launch({
    executablePath: CHROME,
    headless: "new",
    args: ["--no-sandbox", "--disable-dev-shm-usage", "--force-device-scale-factor=2"],
  });

  try {
    const page = await browser.newPage();
    await page.setViewport({ width: 1440, height: 900, deviceScaleFactor: 2 });
    await page.goto(URL, { waitUntil: "networkidle0" });

    // 等引擎连接 + 首屏图表渲染完成
    await sleep(3000);

    const online = await page.evaluate(() => document.body.innerText.includes("ENGINE ONLINE"));
    console.log(online ? "引擎已连接 ✓" : "⚠ 引擎未连接，截图可能显示离线状态");

    for (const p of PAGES) {
      // 按可见文案选中导航项（nav 顺序/数量变化不会点错页面）
      const clicked = await page.evaluate((label) => {
        const btns = [...document.querySelectorAll("aside nav button")];
        const btn = btns.find((b) => b.textContent.includes(label));
        if (!btn) return false;
        btn.click();
        return true;
      }, p.label);

      if (!clicked) {
        // 缺少必需截图 = 产物不完整，直接失败而不是静默跳过
        throw new Error(`找不到导航项「${p.label}」，无法生成 ${p.file}`);
      }

      // 等 ECharts 动画 / 页面切换完成
      await sleep(1400);

      // 展开可折叠区块（让截图露出真实数据，而非收起状态）
      if (p.expand) {
        const expanded = await page.evaluate((txt) => {
          const btn = [...document.querySelectorAll("button")].find((b) => b.textContent.includes(txt));
          if (!btn) return false;
          btn.click();
          return true;
        }, p.expand);
        if (!expanded) console.warn(`警告：未找到「${p.expand}」按钮，${p.file} 可能为收起状态`);
        await sleep(900);
      }

      const target = path.join(OUT, p.file);
      await page.screenshot({ path: target, type: "png", captureBeyondViewport: false });
      console.log(`OK    ${p.file}  ${(fs.statSync(target).size / 1024).toFixed(0)} KB  (${p.label})`);
    }
  } finally {
    await browser.close();
  }
})().catch((e) => {
  console.error("FAIL", e.message);
  process.exit(1);
});
