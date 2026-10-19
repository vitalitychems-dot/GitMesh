import { mkdir, readFile, rm, writeFile } from "node:fs/promises";

// Deliberately publish one public file, never the repository or local vault.
const output = new URL("../generated-artifacts/public/", import.meta.url);
await rm(output, { recursive: true, force: true });
await mkdir(output, { recursive: true });
await writeFile(new URL("index.html", output), await readFile(new URL("../index.html", import.meta.url)));
console.log("Public site built: index.html only; no vault files or credentials included.");
