import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import App from "./App";
import { ToastProvider } from "./hooks/useToast";
import "./index.css";

// "/app" when the backend serves the SPA; set VITE_ROUTER_BASE=/ for a
// standalone deploy at the domain root (e.g. Vercel).
const ROUTER_BASE = import.meta.env.VITE_ROUTER_BASE || "/app";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <BrowserRouter basename={ROUTER_BASE}>
      <ToastProvider>
        <App />
      </ToastProvider>
    </BrowserRouter>
  </React.StrictMode>,
);
