import { defineConfig } from "vite";
import { fileURLToPath } from "node:url";

export default defineConfig({
  root: fileURLToPath(new URL("./client", import.meta.url)),
  appType: "spa",
  build: {
    outDir: fileURLToPath(new URL("../../generated-artifacts/public", import.meta.url)),
    emptyOutDir: true,
  },
  server: {
    allowedHosts: true,
    fs: {
      strict: true,
      // Never allow Vite's development file endpoint to expose the vault/repo.
      allow: [
        fileURLToPath(new URL("./client", import.meta.url)),
        fileURLToPath(new URL("../../node_modules", import.meta.url)),
      ],
      deny: ["**/.env*", "**/SovereignMeshVault/**", "**/.git/**", "**/attached_assets/**", "**/.agents/**"],
    },
  },
});
