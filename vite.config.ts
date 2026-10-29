import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { existsSync, readFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";

// The host no longer treats "connected over 127.0.0.1" as proof of ownership:
// any local process, and any page the agent's browser opens, also connects from
// loopback. The owner's credential is the token file in the data home (mode
// 0600 in a 0700 directory). In development the browser talks to Vite, which
// proxies /api to the host, so Vite must forward that credential — otherwise
// the dev studio would be locked out of its own API.
function ownerAccessToken(): string | null {
  const dataDir = process.env.OPENBOT_DATA_DIR || path.join(os.homedir(), ".openbot");
  const tokenFile = path.join(dataDir, "access.token");
  try {
    if (!existsSync(tokenFile)) return null;
    return readFileSync(tokenFile, "utf8").trim() || null;
  } catch {
    return null;
  }
}

export default defineConfig({
  plugins: [react()],
  build: {
    rollupOptions: { input: { app: "index.html", studio: "studio.html" } },
  },
  server: {
    host: "127.0.0.1",
    port: 4310,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:4311",
        configure(proxy) {
          proxy.on("proxyReq", (request) => {
            if (request.getHeader("authorization")) return;
            // Read per request: the host creates the token on first start.
            const token = ownerAccessToken();
            if (token) request.setHeader("authorization", `Bearer ${token}`);
          });
        },
      },
    },
  },
});
