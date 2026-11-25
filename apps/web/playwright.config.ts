import { defineConfig } from "@playwright/test";

/**
 * End-to-end smoke test against a running stack (Docker Compose). CI starts Compose first;
 * locally: `docker compose -f deploy/compose/docker-compose.yml up --build`, then
 * `SKYLINE_E2E_PASSWORD=<bootstrap password> pnpm --dir apps/web e2e`.
 * `SKYLINE_E2E_CHANNEL=msedge` (or `chrome`) uses an installed browser instead of
 * Playwright's own Chromium.
 */
export default defineConfig({
  testDir: "./e2e",
  timeout: 120_000,
  retries: 0,
  forbidOnly: Boolean(process.env.CI),
  use: {
    baseURL: process.env.SKYLINE_E2E_BASE_URL ?? "http://localhost:3000",
    channel: process.env.SKYLINE_E2E_CHANNEL || undefined,
    // Traces record typed values (passwords) and cookies: keep them off.
    trace: "off",
    screenshot: "only-on-failure",
  },
});
