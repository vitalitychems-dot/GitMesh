// Replit Clerk proxy protocol and response buffering, using httpxy instead of
// http-proxy-middleware to avoid its vulnerable braces/micromatch dependency.
import { createProxyServer } from "httpxy";

export const CLERK_PROXY_PATH = "/api/__clerk";
export function getClerkProxyHost(req) {
  const forwarded = req.headers["x-forwarded-host"];
  const raw = Array.isArray(forwarded) ? forwarded[0] : forwarded;
  return raw?.split(",")[0]?.trim() || req.headers.host?.trim() || undefined;
}

export function clerkProxyMiddleware({
  production = process.env.NODE_ENV === "production",
  secretKey = process.env.CLERK_SECRET_KEY,
  target = "https://frontend-api.clerk.dev",
} = {}) {
  if (!production || !secretKey) {
    return (_req, _res, next) => next();
  }
  const { on, ...options } = {
    target,
    changeOrigin: true,
    selfHandleResponse: true,
    proxyTimeout: 20000,
    timeout: 25000,
    on: {
      proxyReq: (proxyReq, req) => {
        const protocol = req.headers["x-forwarded-proto"] || "https";
        const host = getClerkProxyHost(req) || "";
        proxyReq.setHeader("Clerk-Proxy-Url", `${protocol}://${host}${CLERK_PROXY_PATH}`);
        proxyReq.setHeader("Clerk-Secret-Key", secretKey);
        const xff = req.headers["x-forwarded-for"];
        const clientIp = (Array.isArray(xff) ? xff[0] : xff)?.split(",")[0]?.trim() || req.socket?.remoteAddress || "";
        if (clientIp) proxyReq.setHeader("X-Forwarded-For", clientIp);
      },
      proxyRes: (proxyRes, req, res) => {
        const headers = { ...proxyRes.headers };
        delete headers["transfer-encoding"];
        delete headers.connection;
        delete headers["keep-alive"];
        const status = proxyRes.statusCode ?? 502;
        if (status < 200 || status === 204) delete headers["content-length"];
        const bodyless = req.method === "HEAD" || status < 200 || status === 204 || status === 304;
        if (headers["content-length"] !== undefined || bodyless) {
          res.writeHead(status, headers);
          proxyRes.on("error", () => res.destroy());
          proxyRes.pipe(res);
          return;
        }
        const chunks = [];
        let bytes = 0;
        proxyRes.on("data", (chunk) => {
          bytes += chunk.length;
          if (bytes > 4 * 1024 * 1024) {
            proxyRes.destroy(new Error("Upstream response exceeded the proxy limit"));
            return;
          }
          chunks.push(chunk);
        });
        proxyRes.on("end", () => {
          const body = Buffer.concat(chunks);
          headers["content-length"] = String(body.length);
          res.writeHead(status, headers);
          res.end(body);
        });
        proxyRes.on("error", () => {
          if (!res.headersSent) res.writeHead(502, { "content-length": "0" });
          res.end();
        });
      },
      error: (_error, _req, res) => {
        if (!res.headersSent) res.writeHead(502, { "content-length": "0" });
        res.end();
      },
    },
  };
  const proxy = createProxyServer(options);
  for (const [name, handler] of Object.entries(on)) proxy.on(name, handler);
  // Express has already stripped CLERK_PROXY_PATH from req.url at the mount.
  // The destination is fixed by server configuration, never by a client URL.
  return (req, res) => {
    proxy.web(req, res).catch((error) => on.error(error, req, res));
  };
}
