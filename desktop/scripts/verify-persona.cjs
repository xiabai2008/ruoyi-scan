/**
 * 人格系统端到端验证（puppeteer + 本机 Chrome headless → vite 5173）
 * 检查项：
 *  1. 设置页「操作员人格」板块渲染：11 预设头像 + 自定义格 + 2 输入 + 3 开关
 *  2. 点击预设头像 → 侧边栏代号/问候语/头像变化（localStorage 持久化）
 *  3. 修改代号 → 侧边栏实时更新
 *  4. LiveScan 页 MEIYI SUPPORT 卡 → 代号化标题 + 人格头像
 *  5. 派发 rs:scan-done 桥事件 → 播报浮条出现（音效/通知在浏览器里静默降级）
 *  6. 扫描任务真实完成（等 d7fc080d08d2 done）→ taskDone 兜底 tally
 *  7. 控制台零错误（过滤资源 404/401 等噪音）
 */
const puppeteer = require("C:/Users/HZR/AppData/Roaming/npm/node_modules/puppeteer");

const CHROME = "C:/Program Files/Google/Chrome/Application/chrome.exe";
const URL = "http://localhost:5173";
const results = [];
const ok = (name, cond, extra = "") => {
  results.push(`${cond ? "PASS" : "FAIL"} ${name}${extra ? " | " + extra : ""}`);
};

(async () => {
  // 前置预检：引擎必须在线且 CORS 放行 5173，否则后续 4/5/6 必挂，快速失败并给出原因
  try {
    const pre = await fetch("http://127.0.0.1:8123/api/system/health", {
      headers: { Origin: "http://localhost:5173" },
    });
    if (!pre.ok) throw new Error("HTTP " + pre.status);
  } catch (e) {
    console.error("前置条件不满足：引擎 127.0.0.1:8123 不可达或 CORS 拦截（" + e.message + "）");
    console.error("请先启动引擎并带上与 Tauri 壳一致的 --cors-origins 参数（见脚本头部说明）。");
    process.exit(2);
  }

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

  // ---- 1. 设置页人格板块 ----
  await page.evaluate(() => {
    const btns = [...document.querySelectorAll("aside button, nav button")];
    const settings = btns.find((b) => b.textContent.includes("设置"));
    if (settings) settings.click();
  });
  await new Promise((r) => setTimeout(r, 900));
  await page.evaluate(() => window.scrollBy(0, 0));

  const personaBoard = await page.evaluate(() => {
    const sections = [...document.querySelectorAll("section")];
    const sec = sections.find((s) => s.textContent.includes("操作员人格"));
    if (!sec) return null;
    const imgs = [...sec.querySelectorAll("img")].length;
    const customPlus = sec.textContent.includes("自定义");
    const toggles = [...sec.querySelectorAll("button, input")].length;
    const hasCallsign = sec.textContent.includes("代号");
    const hasGreet = sec.textContent.includes("口头禅");
    const hasNotify = sec.textContent.includes("完成播报");
    const hasSound = sec.textContent.includes("提示音效");
    const hasTry = sec.textContent.includes("试听音效");
    return { imgs, customPlus, toggles, hasCallsign, hasGreet, hasNotify, hasSound, hasTry };
  });
  ok("1. 设置页人格板块存在", !!personaBoard, personaBoard ? JSON.stringify(personaBoard) : "");
  ok("1a. 预设头像 11 张", personaBoard && personaBoard.imgs >= 11, `imgs=${personaBoard && personaBoard.imgs}`);
  ok("1b. 自定义入口存在", !!(personaBoard && personaBoard.customPlus));
  ok("1c. 代号/口头禅输入存在", !!(personaBoard && personaBoard.hasCallsign && personaBoard.hasGreet));
  ok("1d. 播报/音效/试听存在", !!(personaBoard && personaBoard.hasNotify && personaBoard.hasSound && personaBoard.hasTry));

  // 截图：设置页人格板块
  await page.screenshot({ path: "D:/HZR_PROJECTS/ruoyi-scan/desktop/scripts/persona-settings.png" });

  // ---- 2. 点第 3 个预设（注视）→ 侧边栏变化 ----
  const before = await page.evaluate(() => {
    const aside = document.querySelector("aside");
    return aside ? aside.textContent : "";
  });
  await page.evaluate(() => {
    const sections = [...document.querySelectorAll("section")];
    const sec = sections.find((s) => s.textContent.includes("操作员人格"));
    const avatars = sec.querySelectorAll("button");
    avatars[2].click(); // 第 3 个 = v04_gaze
  });
  await new Promise((r) => setTimeout(r, 700));
  const after = await page.evaluate(() => {
    const aside = document.querySelector("aside");
    const ls = localStorage.getItem("rs.operator");
    return { aside: aside ? aside.textContent : "", ls };
  });
  ok("2. 切换预设 → 侧边栏问候语变化", after.aside !== before && after.aside.includes("正面注视"), after.aside.slice(0, 120));
  ok("2a. localStorage 持久化", !!after.ls && after.ls.includes("v04_gaze"), after.ls);

  // ---- 3. 修改代号 ----
  const newCallsign = "测试瑞";
  await page.evaluate((cs) => {
    const sections = [...document.querySelectorAll("section")];
    const sec = sections.find((s) => s.textContent.includes("操作员人格"));
    const inputs = [...sec.querySelectorAll("input")];
    const input = inputs[0];
    const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value").set;
    setter.call(input, cs);
    input.dispatchEvent(new Event("input", { bubbles: true }));
  }, newCallsign);
  await page.evaluate(() => {
    const sections = [...document.querySelectorAll("section")];
    const sec = sections.find((s) => s.textContent.includes("操作员人格"));
    const saveBtn = [...sec.querySelectorAll("button")].find((b) => b.textContent.trim() === "保存");
    saveBtn.click();
  });
  await new Promise((r) => setTimeout(r, 700));
  const sideAfter = await page.evaluate(() => {
    const aside = document.querySelector("aside");
    return aside ? aside.textContent : "";
  });
  ok("3. 代号修改 → 侧边栏同步", sideAfter.includes(newCallsign), sideAfter.slice(0, 90));

  // ---- 4. LiveScan 页 SUPPORT 卡 ----
  await page.evaluate(() => {
    const btns = [...document.querySelectorAll("aside nav button")];
    const live = btns.find((b) => b.textContent.includes("扫描任务"));
    if (live) live.click();
  });
  await new Promise((r) => setTimeout(r, 1500));
  const supportCard = await page.evaluate(() => {
    const span = [...document.querySelectorAll("span")].find((s) => /SUPPORT/.test(s.textContent));
    if (!span) return null;
    const card = span.closest("div.flex");
    const img = card.querySelector("img");
    return { label: span.textContent.trim(), hasImg: !!img, imgSrc: img ? img.src.slice(-40) : "" };
  });
  ok("4. SUPPORT 卡标签人格化", !!supportCard && supportCard.label === `${newCallsign} SUPPORT`, supportCard ? supportCard.label : "not-found");
  ok("4a. SUPPORT 卡头像存在", !!(supportCard && supportCard.hasImg), supportCard ? supportCard.imgSrc : "");

  // ---- 5. 派发 scan-done 桥事件 → 播报浮条 ----
  await page.evaluate(() => {
    window.dispatchEvent(new CustomEvent("rs:scan-done", { detail: { target: "http://127.0.0.1:18081/", total: 3, confirmed: 1, duration: 5.2 } }));
  });
  await new Promise((r) => setTimeout(r, 1200));
  const toast = await page.evaluate(() => {
    const els = [...document.querySelectorAll("p")];
    const t = els.find((p) => p.textContent.includes("发现 1 个已确认问题"));
    return t ? { text: t.textContent } : null;
  });
  ok("5. scan-done → 枚依播报浮条", !!toast, toast ? toast.text : "not-found");
  await page.screenshot({ path: "D:/HZR_PROJECTS/ruoyi-scan/desktop/scripts/persona-livescan.png" });

  // ---- 6. 等真实任务终态 ----
  let real = null;
  for (let i = 0; i < 40; i++) {
    await new Promise((r) => setTimeout(r, 2000));
    real = await page.evaluate(async (id) => {
      try {
        const res = await fetch(`http://127.0.0.1:8123/api/scan/${id}`);
        return await res.json();
      } catch {
        return null;
      }
    }, "d7fc080d08d2");
    if (real && real.status === "done") break;
  }
  ok("6. 真实扫描任务完成", !!real && real.status === "done", real ? real.status : "no-task");

  // ---- 7. 控制台错误过滤 ----
  const fatal = errors.filter((e) => !e.includes("Failed to load resource") && !e.includes("the server responded with a status"));
  ok("7. 控制台零致命错误", fatal.length === 0, fatal.slice(0, 3).join(" || "));

  console.log(results.join("\n"));
  await browser.close();
  process.exit(results.some((r) => r.startsWith("FAIL")) ? 1 : 0);
})().catch((e) => {
  console.error("SCRIPT ERROR:", e);
  process.exit(2);
});
