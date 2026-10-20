import { defineConfig, devices } from "@playwright/test";
import { fileURLToPath } from "node:url";

// Playwright otherwise writes an ARIA error-context snapshot on failure, which
// could contain a replacement key even with screenshots and traces disabled.
process.env.PLAYWRIGHT_NO_COPY_PROMPT = "1";
const browserEnvironment = Object.fromEntries([
  "PATH", "HOME", "LANG", "LC_ALL", "TZ", "DISPLAY", "FONTCONFIG_FILE",
  "XDG_RUNTIME_DIR", "LD_LIBRARY_PATH", "GITMESH_TEST_WEBKIT_LIBRARIES",
  "WEBKIT_EXEC_PATH", "WEBKIT_INJECTED_BUNDLE_PATH", "WEBKIT_INSPECTOR_RESOURCES_PATH",
].filter((name) => process.env[name] !== undefined).map((name) => [name, process.env[name]]));

export default defineConfig({
  testDir: ".",
  testMatch: "*.spec.mjs",
  workers: 1,
  retries: 0,
  timeout: 30000,
  expect: { timeout: 8000 },
  reporter: "list",
  outputDir: fileURLToPath(new URL("../../../generated-artifacts/browser-results/", import.meta.url)),
  // Rotation views contain ephemeral credentials. Never record them.
  use: { trace: "off", screenshot: "off", video: "off", acceptDownloads: true },
  projects: [
    {
      name: "mobile-chromium",
      use: {
        ...devices["Pixel 7"],
        browserName: "chromium",
        launchOptions: {
          env: browserEnvironment,
          ...(process.env.GITMESH_TEST_CHROMIUM_EXECUTABLE
            ? { executablePath: process.env.GITMESH_TEST_CHROMIUM_EXECUTABLE } : {}),
        },
      },
    },
    {
      name: "mobile-webkit",
      use: {
        ...devices["iPhone 13"],
        browserName: "webkit",
        launchOptions: {
          env: browserEnvironment,
          ...(process.env.GITMESH_TEST_WEBKIT_EXECUTABLE
            ? { executablePath: process.env.GITMESH_TEST_WEBKIT_EXECUTABLE } : {}),
        },
      },
    },
  ],
});
