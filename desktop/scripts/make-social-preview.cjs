/**
 * 生成 GitHub 社交预览图（1280×640，符合 GitHub Social Preview 规范）
 * 用法：node desktop/scripts/make-social-preview.cjs
 * 产物：assets/social-preview.png（需在仓库 Settings → Social preview 手动上传，GitHub 无公开 API）
 */
const path = require("path");
const fs = require("fs");
const puppeteer = require("C:/Users/HZR/AppData/Roaming/npm/node_modules/puppeteer");

const CHROME = "C:/Program Files/Google/Chrome/Application/chrome.exe";
const ROOT = path.resolve(__dirname, "../..");
const HTML = path.join(ROOT, "desktop/scripts/social-preview.html");
const OUT = path.join(ROOT, "assets/social-preview.png");

(async () => {
  const browser = await puppeteer.launch({
    executablePath: CHROME,
    headless: "new",
    args: ["--no-sandbox", "--disable-dev-shm-usage", "--font-render-hinting=none"],
  });
  try {
    const page = await browser.newPage();
    await page.setViewport({ width: 1280, height: 640, deviceScaleFactor: 2 });
    await page.goto("file:///" + HTML.replace(/\\/g, "/"), { waitUntil: "networkidle0" });
    await page.evaluate(() => document.fonts.ready);
    await page.screenshot({
      path: OUT,
      type: "png",
      clip: { x: 0, y: 0, width: 1280, height: 640 },
      captureBeyondViewport: false,
    });
    const size = fs.statSync(OUT).size;
    console.log(`OK  ${OUT}`);
    console.log(`    ${(size / 1024).toFixed(0)} KB (2560x1280 @2x) — GitHub 上限 1MB`);
  } finally {
    await browser.close();
  }
})().catch((e) => {
  console.error("FAIL", e.message);
  process.exit(1);
});
