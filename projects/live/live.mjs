import { createServer } from "node:http";
import { readFileSync } from "node:fs";

const html = readFileSync(new URL("../../index.html", import.meta.url));
const port = Number(process.env.PORT || 8791);

createServer((_req, res) => {
  res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
  res.end(html);
}).listen(port, "127.0.0.1", () => {
  console.log(`live\t${port}`);
});
