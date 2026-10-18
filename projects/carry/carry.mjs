import { readFileSync, readdirSync, statSync } from "node:fs";

const index = JSON.parse(readFileSync(new URL("../../mesh/index.json", import.meta.url), "utf8"));
if (index.needsWeb !== false || index.carriedBy !== "git") process.exit(1);
const root = new URL("../../projects/", import.meta.url);
const dirs = readdirSync(root).filter((d) => statSync(new URL(d + "/", root)).isDirectory()).map((d) => `projects/${d}`);
const listed = new Set((index.projects ?? []).map((p) => p.path));
const drift = [...dirs.filter((d) => !listed.has(d)).map((d) => `missing from index: ${d}`), ...[...listed].filter((p) => !dirs.includes(p)).map((p) => `index lists missing folder: ${p}`)];
if (drift.length) { console.error(drift.join("\n")); process.exit(2); }
const names = (index.projects ?? []).map((project) => project.name).join(", ");
console.log(`${index.net}\t${index.carriedBy}\tneedsWeb ${index.needsWeb}\t${names}`);
