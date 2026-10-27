import tseslint from "typescript-eslint";
import reactHooks from "eslint-plugin-react-hooks";

/**
 * 桌面端最小 ESLint 配置：只启用 React Hooks 规则。
 *
 * 动因：v1.5.0 的「新建扫描」白屏（React #310）源于 `useRef` 位于提前 return 之后，
 * tsc / vite build 都无法发现。`react-hooks/rules-of-hooks` 可在静态阶段直接拦截。
 */
export default tseslint.config(
  {
    ignores: ["dist/**", "node_modules/**", "src-tauri/**"],
  },
  {
    files: ["src/**/*.{ts,tsx}"],
    languageOptions: {
      parser: tseslint.parser,
      parserOptions: {
        ecmaVersion: "latest",
        sourceType: "module",
        ecmaFeatures: { jsx: true },
      },
    },
    plugins: {
      "react-hooks": reactHooks,
    },
    rules: {
      "react-hooks/rules-of-hooks": "error",
      "react-hooks/exhaustive-deps": "warn",
    },
  },
);
