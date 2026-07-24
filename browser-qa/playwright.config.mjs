import { defineConfig, devices } from "@playwright/test";
import path from "node:path";

const port = 18082;

export default defineConfig({
  testDir: ".",
  testMatch: "managed-secret-ux.spec.mjs",
  fullyParallel: false,
  forbidOnly: true,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: "line",
  outputDir: path.join(import.meta.dirname, "test-results"),
  timeout: 30_000,
  use: {
    baseURL: `http://127.0.0.1:${port}`,
    trace: "off",
    screenshot: "off",
    video: "off",
    colorScheme: "light",
    reducedMotion: "reduce",
    locale: "en-GB",
    timezoneId: "Europe/Vienna",
  },
  projects: [
    {
      name: "chromium-desktop",
      use: {
        ...devices["Desktop Chrome"],
        viewport: { width: 1440, height: 1000 },
      },
    },
    {
      name: "chromium-mobile",
      use: { ...devices["Pixel 7"] },
    },
  ],
  webServer: {
    command:
      "cd ../go-envelope && " +
      "JANUS_MANAGED_BROWSER_ASSURANCE_SERVER=1 " +
      "go test -run '^TestManagedBrowserAssuranceServer$' -count=1 -timeout=0",
    url: `http://127.0.0.1:${port}/healthz`,
    reuseExistingServer: false,
    timeout: 60_000,
  },
});
