import { createServer } from "node:http";
import { readFileSync } from "node:fs";

const html = readFileSync(new URL("../../index.html", import.meta.url));
const start = Number(process.env.PORT || 8791);

function open(port) {
  const server = createServer((_req, res) => {
    res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    res.end(html);
  });
  server.on("error", (error) => {
    if (error && error.code === "EADDRINUSE" && !process.env.PORT && port < start + 20) {
      open(port + 1);
      return;
    }
    throw error;
  });
  server.listen(port, "0.0.0.0", () => {
    console.log(`live\t${port}`);
  });
}

open(start);
