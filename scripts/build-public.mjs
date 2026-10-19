import { build } from "vite";
import { fileURLToPath } from "node:url";

// Vite's client root is isolated from the repository and local vault.
await build({ configFile: fileURLToPath(new URL("../projects/live/vite.config.mjs", import.meta.url)) });
