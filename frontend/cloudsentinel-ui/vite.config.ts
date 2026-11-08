import { defineConfig } from "vite";
import type { IncomingMessage } from "node:http";
import react from "@vitejs/plugin-react";

const backend = process.env.VITE_API_PROXY_TARGET ?? "http://127.0.0.1:8001";
const appAwareProxy = {
  target: backend,
  bypass: (request: IncomingMessage) =>
    request.headers.accept?.includes("text/html") ? request.url : undefined,
};

export default defineConfig({
  plugins: [react()],
  server: {
    host: "0.0.0.0",
    allowedHosts: [".trycloudflare.com"],
    proxy: {
      "/auth": { ...appAwareProxy },
      "/organizations": { ...appAwareProxy },
      "/users": { ...appAwareProxy },
      "/teams": { ...appAwareProxy },
      "/cloud-accounts": { ...appAwareProxy },
      "/scans": { ...appAwareProxy },
      "/customer-scans": { ...appAwareProxy },
      "/assets": { ...appAwareProxy },
      "/search": { ...appAwareProxy },
      "/policies": { ...appAwareProxy },
      "/findings": { ...appAwareProxy },
      "/risk": { ...appAwareProxy },
      "/compliance": { ...appAwareProxy },
      "/remediation": { ...appAwareProxy },
      "/reports": { ...appAwareProxy },
      "/alerts": { ...appAwareProxy },
      "/alert-rules": { ...appAwareProxy },
      "/notifications": { ...appAwareProxy },
      "/audit-events": { ...appAwareProxy },
      "/audit-export": { ...appAwareProxy },
      "/dashboard": { ...appAwareProxy },
    },
  },
});
