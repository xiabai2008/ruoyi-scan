import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// Tauri CLI 构建时注入的平台变量（windows/macos/linux…）；纯 vite build 时为 undefined。
// 用 globalThis 读取，避免项目未装 @types/node 时的 `process` 类型错误。
const tauriPlatform = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env
  ?.TAURI_ENV_PLATFORM;

// Tauri expects a fixed port, fail if that port is not available
export default defineConfig({
  plugins: [react(), tailwindcss()],
  clearScreen: false,
  server: {
    // 5173 必须与 src-tauri/tauri.conf.json 的 build.devUrl（http://localhost:5173）保持一致；
    // 改端口时两处同步，否则 tauri dev 壳会连不上前端。
    port: 5173,
    strictPort: true,
    // 忽略 Rust 侧源码/产物：避免 tauri dev 时 src-tauri 变更触发前端整页 reload（Windows 上易出 EBUSY 噪声）
    watch: {
      ignored: ["**/src-tauri/**"],
    },
  },
  build: {
    // Tauri webview 基线（官方模板同款）：Windows WebView2 ≈ chrome105；macOS/Linux WebKit ≈ safari13
    target: tauriPlatform === "windows" ? "chrome105" : "safari13",
  },
});
