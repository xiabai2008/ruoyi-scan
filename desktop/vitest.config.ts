import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

// WP-4：桌面端组件测试层。
// 测试文件放 desktop/tests/ 而不是 src/__tests__/：
//   - eslint 只 lint src/**，不会把测试文件纳入 react-hooks: error 规则；
//   - tsc --noEmit 的 include 是 ["src"]，不会因测试类型拖慢生产构建。
export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    include: ["tests/**/*.test.{ts,tsx}"],
    setupFiles: ["tests/setup.ts"],
    globals: true,
    css: false,
    restoreMocks: true,
  },
});
