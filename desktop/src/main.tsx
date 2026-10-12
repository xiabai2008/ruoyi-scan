import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";

import "@fontsource/jetbrains-mono/400.css";
import "@fontsource/jetbrains-mono/500.css";
import "@fontsource/jetbrains-mono/700.css";
import "@fontsource-variable/noto-sans-sc";
import "./styles/theme.css";

const rootEl = document.getElementById("root");
if (!rootEl) throw new Error("挂载点 #root 不存在：index.html 是否被修改？");

ReactDOM.createRoot(rootEl).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
