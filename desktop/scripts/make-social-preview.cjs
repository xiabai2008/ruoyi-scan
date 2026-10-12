/**
 * 生成 GitHub 社交预览图（1280×640，符合 GitHub Social Preview 规范）
 * 用法：node desktop/scripts/make-social-preview.cjs
 * 产物：assets/social-preview.png（需在仓库 Settings → Social preview 手动上传，GitHub 无公开 API）
 *
 * 尺寸铁律：必须输出 1280×640。曾用 deviceScaleFactor:2 产出 2560×1280，
 * GitHub 上传时直接报 "Something went really wrong and we can't process that picture."
 * —— 超过 1280×640 的图它处理不了，且体积也没必要（GitHub 显示尺寸就是 1280×640）。
 */
const path = require("path");
const fs = require("fs");
const puppeteer = require("C:/Users/HZR/AppData/Roaming/npm/node_modules/puppeteer");

const CHROME = "C:/Program Files/Google/Chrome/Application/chrome.exe";
const ROOT = path.resolve(__dirname, "../..");
const HTML = path.join(ROOT, "desktop/scripts/social-preview.html");
const OUT = path.join(ROOT, "assets/social-preview.png");
// 尺寸铁律（见文件头）：viewport / clip / 校验共用同一对常量，防止漂移
const WIDTH = 1280;
const HEIGHT = 640;

(async () => {
  const browser = await puppeteer.launch({
    executablePath: CHROME,
    headless: "new",
    args: ["--no-sandbox", "--disable-dev-shm-usage", "--font-render-hinting=none"],
  });
  try {
    const page = await browser.newPage();
    await page.setViewport({ width: WIDTH, height: HEIGHT, deviceScaleFactor: 1 });
    await page.goto("file:///" + HTML.replace(/\\/g, "/"), { waitUntil: "networkidle0" });
    await page.evaluate(() => document.fonts.ready);
    // 内容一旦超出画布会被静默裁掉：先量页面实际尺寸，超限直接失败
    const content = await page.evaluate(() => ({
      w: Math.max(document.documentElement.scrollWidth, document.body.scrollWidth),
      h: Math.max(document.documentElement.scrollHeight, document.body.scrollHeight),
    }));
    if (content.w > WIDTH || content.h > HEIGHT) {
      throw new Error(`预览内容超出 ${WIDTH}×${HEIGHT} 画布（实际 ${content.w}×${content.h}），会被裁切`);
    }
    // 干净检出时 assets/ 可能不存在
    fs.mkdirSync(path.dirname(OUT), { recursive: true });
    await page.screenshot({
      path: OUT,
      type: "png",
      clip: { x: 0, y: 0, width: WIDTH, height: HEIGHT },
      captureBeyondViewport: false,
    });
    // 尺寸铁律校验：直接读 PNG IHDR，防止 viewport/clip/HTML 漂移后静默提交错误尺寸
    const png = fs.readFileSync(OUT);
    const w = png.readUInt32BE(16);
    const h = png.readUInt32BE(20);
    if (w !== WIDTH || h !== HEIGHT) {
      throw new Error(`社交预览尺寸错误：${w}×${h}（必须 ${WIDTH}×${HEIGHT}）`);
    }
    if (png.length > 1024 * 1024) {
      throw new Error(`社交预览体积超限：${(png.length / 1024).toFixed(0)} KB（GitHub 上限 1MB）`);
    }
    console.log(`OK  ${OUT}`);
    console.log(`    ${(png.length / 1024).toFixed(0)} KB (${w}x${h}) — GitHub 上限 1MB`);
  } finally {
    await browser.close();
  }
})().catch((e) => {
  console.error("FAIL", e.message);
  process.exit(1);
});
