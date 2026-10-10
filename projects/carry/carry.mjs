import { readFileSync } from "node:fs";

const index = JSON.parse(readFileSync(new URL("../../mesh/index.json", import.meta.url), "utf8"));
if (index.needsWeb !== false || index.carriedBy !== "git") process.exit(1);
const names = (index.projects ?? []).map((project) => project.name).join(", ");
console.log(`${index.net}\t${index.carriedBy}\tneedsWeb ${index.needsWeb}\t${names}`);
