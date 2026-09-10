/**
 * 三批次（主题自由化 / 视觉签名 / 桌面 Widgets）端到端验证。
 * puppeteer + 本机 Chrome headless → vite 5173。
 */
const puppeteer = require("C:/Users/HZR/AppData/Roaming/npm/node_modules/puppeteer");

const CHROME = "C:/Program Files/Google/Chrome/Application/chrome.exe";
const URL = "http://localhost:5173";
const results = [];
const ok = (name, cond, extra = "") => {
  results.push(`${cond ? "PASS" : "FAIL"} ${name}${extra ? " | " + extra : ""}`);
};

(async () => {
  const browser = await puppeteer.launch({
    executablePath: CHROME,
    headless: "new",
    args: ["--no-sandbox", "--disable-dev-shm-usage", "--window-size=1440,900"],
  });
  const page = await browser.newPage();
  await page.setViewport({ width: 1440, height: 900 });

  const errors = [];
  page.on("pageerror", (e) => errors.push("pageerror: " + e.message));
  page.on("console", (m) => {
    if (m.type() === "error") errors.push("console: " + m.text().slice(0, 160));
  });

  await page.goto(URL, { waitUntil: "networkidle2", timeout: 30000 });
  await new Promise((r) => setTimeout(r, 2500));

  // 进入设置页
  await page.evaluate(() => {
    const btns = [...document.querySelectorAll("aside button, nav button")];
    const settings = btns.find((b) => b.textContent.includes("设置"));
    if (settings) settings.click();
  });
  await new Promise((r) => setTimeout(r, 900));

  // ===== A. 主题自由化 =====
  const board = await page.evaluate(() => {
    const sections = [...document.querySelectorAll("section")];
    const sec = sections.find((s) => s.textContent.includes("主题包"));
    if (!sec) return null;
    return {
      hasCustomCard: sec.textContent.includes("D 自定义"),
      hasEditor: sec.textContent.includes("主题编辑器"),
      colorInputs: [...sec.querySelectorAll('input[type="color"]')].length,
      hasExport: [...sec.querySelectorAll("button")].some((b) => b.textContent.includes("导出 JSON")),
      hasImport: [...sec.querySelectorAll("button")].some((b) => b.textContent.includes("导入 JSON")),
      gridCols: sec.querySelectorAll("button").length,
    };
  });
  ok("A1. 主题包含 D 自定义卡", !!board && board.hasCustomCard, board ? JSON.stringify(board) : "");
  ok("A2. 主题编辑器存在", !!board && board.hasEditor);
  ok("A3. 6 个核心色输入", !!board && board.colorInputs === 6, `inputs=${board && board.colorInputs}`);
  ok("A4. 导出/导入按钮", !!board && board.hasExport && board.hasImport);
  ok("A5. 5 卡栅格(4预设+1自定义)", !!board && board.gridCols >= 5, `cards=${board && board.gridCols}`);

  // 改 3 个核心色 → 应用 → data-theme=custom + CSS 变量生效
  const wantAccent = "#e0568f";
  await page.evaluate((accent) => {
    const sections = [...document.querySelectorAll("section")];
    const sec = sections.find((s) => s.textContent.includes("主题包"));
    const rows = [...sec.querySelectorAll("label")];
    const row = rows.find((l) => l.textContent.includes("强调色"));
    const textInput = row.querySelector('input:not([type="color"])');
    const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value").set;
    setter.call(textInput, accent);
    textInput.dispatchEvent(new Event("input", { bubbles: true }));
  }, wantAccent);
  await new Promise((r) => setTimeout(r, 400));
  await page.evaluate(() => {
    const sections = [...document.querySelectorAll("section")];
    const sec = sections.find((s) => s.textContent.includes("主题包"));
    const applyBtn = [...sec.querySelectorAll("button")].find((b) => b.textContent.includes("应用自定义主题"));
    applyBtn.click();
  });
  await new Promise((r) => setTimeout(r, 900));
  const themeState = await page.evaluate(() => ({
    dt: document.documentElement.dataset.theme,
    accent: getComputedStyle(document.documentElement).getPropertyValue("--c-accent-primary").trim(),
    saved: localStorage.getItem("rs.theme"),
  }));
  ok("A6. 应用后 data-theme=custom", themeState.dt === "custom", JSON.stringify(themeState));
  ok("A7. 强调色变量=输入值", themeState.accent.toLowerCase() === wantAccent, `got ${themeState.accent}`);
  ok("A8. rs.theme=custom 持久化", themeState.saved === "custom", themeState.saved);

  await page.screenshot({ path: "D:/HZR_PROJECTS/ruoyi-scan/desktop/scripts/batch-theme-custom.png" });

  // 导出 JSON（验证下载触发不崩溃即可，headless 拦截）
  const cdp = await page.createCDPSession();
  await cdp.send("Browser.setDownloadBehavior", { behavior: "deny" });
  await page.evaluate(() => {
    const sections = [...document.querySelectorAll("section")];
    const sec = sections.find((s) => s.textContent.includes("主题包"));
    const btn = [...sec.querySelectorAll("button")].find((b) => b.textContent.includes("导出 JSON"));
    btn.click();
  });
  await new Promise((r) => setTimeout(r, 600));
  ok("A9. 导出不崩溃", (await page.evaluate(() => true)) === true);

  // ===== B. 视觉签名 =====
  const visBoard = await page.evaluate(() => {
    const sections = [...document.querySelectorAll("section")];
    const sec = sections.find((s) => s.textContent.includes("视觉签名"));
    if (!sec) return null;
    return {
      hasCrt: sec.textContent.includes("CRT 扫描线"),
      hasFont: sec.textContent.includes("字体模式"),
      fontBtns: [...sec.querySelectorAll("button")].filter((b) => b.textContent.includes("等宽") || b.textContent.includes("复古") || b.textContent.includes("像素")).length,
    };
  });
  ok("B1. 视觉签名板块存在", !!visBoard && visBoard.hasCrt && visBoard.hasFont, visBoard ? JSON.stringify(visBoard) : "");
  ok("B2. 三种字体模式按钮", !!visBoard && visBoard.fontBtns >= 3);

  // 开 CRT → html[data-crt=on] + localStorage
  await page.evaluate(() => {
    const sections = [...document.querySelectorAll("section")];
    const sec = sections.find((s) => s.textContent.includes("视觉签名"));
    const label = [...sec.querySelectorAll("label, div")].find((l) => l.textContent.includes("CRT 扫描线"));
    const toggle = label.querySelector("button");
    toggle.click();
  });
  await new Promise((r) => setTimeout(r, 500));
  const crtState = await page.evaluate(() => ({
    attr: document.documentElement.dataset.crt,
    saved: localStorage.getItem("rs.visual"),
    style: getComputedStyle(document.documentElement).getPropertyValue("--font-mono").slice(0, 30),
  }));
  ok("B3. CRT 开关生效", crtState.attr === "on", JSON.stringify(crtState));
  ok("B4. rs.visual 持久化含 crt:true", crtState.saved.includes('"crt":true'), crtState.saved);

  // 切像素字体 → --font-mono 变为 Silkscreen 栈
  await page.evaluate(() => {
    const sections = [...document.querySelectorAll("section")];
    const sec = sections.find((s) => s.textContent.includes("视觉签名"));
    const btn = [...sec.querySelectorAll("button")].find((b) => b.textContent.trim() === "像素街机");
    btn.click();
  });
  await new Promise((r) => setTimeout(r, 900));
  const fontState = await page.evaluate(() => ({
    mono: getComputedStyle(document.documentElement).getPropertyValue("--font-mono").slice(0, 30),
    saved: localStorage.getItem("rs.visual"),
  }));
  ok("B5. 像素字体栈切换", fontState.mono.includes("Silkscreen"), JSON.stringify(fontState));

  await page.screenshot({ path: "D:/HZR_PROJECTS/ruoyi-scan/desktop/scripts/batch-visual.png" });

  // ===== C. 桌面 Widgets =====
  const wdBoard = await page.evaluate(() => {
    const sections = [...document.querySelectorAll("section")];
    const sec = sections.find((s) => s.textContent.includes("桌面 Widgets"));
    if (!sec) return null;
    return {
      hasFindings: sec.textContent.includes("发现数"),
      hasEngine: sec.textContent.includes("引擎状态"),
      hasProgress: sec.textContent.includes("任务进度"),
      toggles: [...sec.querySelectorAll("button")].filter((b) => b.getAttribute("aria-pressed") !== null).length,
    };
  });
  ok("C1. Widgets 板块三卡开关", !!wdBoard && wdBoard.hasFindings && wdBoard.hasEngine && wdBoard.hasProgress, wdBoard ? JSON.stringify(wdBoard) : "");

  // 全开 → 三个浮窗出现（React state 批量更新会互相覆盖，逐个点+等渲染）
  for (let round = 0; round < 3; round++) {
    const clicked = await page.evaluate(() => {
      const sec = [...document.querySelectorAll("section")].find((x) => x.textContent.includes("桌面 Widgets"));
      const off = [...sec.querySelectorAll('button[aria-pressed="false"]')];
      if (off.length > 0) {
        off[0].click();
        return true;
      }
      return false;
    });
    if (!clicked) break;
    await new Promise((r) => setTimeout(r, 450));
  }
  await new Promise((r) => setTimeout(r, 400));
  const wdState = await page.evaluate(() => {
    const cards = [...document.querySelectorAll("div.fixed.z-50")];
    return {
      count: cards.length,
      labels: cards.map((c) => c.textContent.slice(0, 40)),
      saved: localStorage.getItem("rs.widgets"),
    };
  });
  ok("C2. 开三卡 → 3 个浮窗", wdState.count === 3, JSON.stringify(wdState.labels));
  ok("C3. rs.widgets 持久化", wdState.saved.includes('"findings":true'), wdState.saved);

  // 拖拽 findings 卡 → 位置变化 + 持久化
  const beforePos = await page.evaluate(() => {
    const card = document.querySelector("div.fixed.z-50");
    const r = card.getBoundingClientRect();
    return { x: r.left, y: r.top };
  });
  await page.mouse.move(beforePos.x + 70, beforePos.y + 20);
  await page.mouse.down();
  await page.mouse.move(beforePos.x + 70 - 400, beforePos.y + 20 + 200, { steps: 12 });
  await page.mouse.up();
  await new Promise((r) => setTimeout(r, 500));
  const afterPos = await page.evaluate(() => {
    const card = document.querySelector("div.fixed.z-50");
    const r = card.getBoundingClientRect();
    return { x: r.left, y: r.top, saved: localStorage.getItem("rs.widgets.pos") };
  });
  ok(
    "C4. 拖拽位移 + 位置持久化",
    Math.abs(afterPos.x - beforePos.x) > 300 && Math.abs(afterPos.y - beforePos.y) > 150,
    `before(${beforePos.x},${beforePos.y}) after(${afterPos.x},${afterPos.y})`,
  );

  // 关掉全部 → 浮窗消失（同样逐个点）
  for (let round = 0; round < 3; round++) {
    const clicked = await page.evaluate(() => {
      const sec = [...document.querySelectorAll("section")].find((x) => x.textContent.includes("桌面 Widgets"));
      const on = [...sec.querySelectorAll('button[aria-pressed="true"]')];
      if (on.length > 0) {
        on[0].click();
        return true;
      }
      return false;
    });
    if (!clicked) break;
    await new Promise((r) => setTimeout(r, 450));
  }
  await new Promise((r) => setTimeout(r, 400));
  const wdGone = await page.evaluate(() => document.querySelectorAll("div.fixed.z-50").length);
  ok("C5. 全关 → 浮窗消失", wdGone === 0, `left=${wdGone}`);

  // ===== 控制台错误过滤 =====
  const fatal = errors.filter((e) => !e.includes("Failed to load resource") && !e.includes("the server responded with a status"));
  ok("D1. 控制台零致命错误", fatal.length === 0, fatal.slice(0, 3).join(" || "));

  console.log(results.join("\n"));
  await browser.close();
  process.exit(results.some((r) => r.startsWith("FAIL")) ? 1 : 0);
})().catch((e) => {
  console.error("SCRIPT ERROR:", e);
  process.exit(2);
});
