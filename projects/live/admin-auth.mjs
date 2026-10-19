export function createRateLimit({ limit = 60, windowMs = 60000, maxKeys = 2000, clock = Date.now } = {}) {
  const buckets = new Map();
  return (req, res, next) => {
    const now = clock();
    for (const [key, bucket] of buckets) if (bucket.until <= now) buckets.delete(key);
    // Socket IP cannot be arbitrarily changed with a client-supplied XFF.
    // Aggregate limits remain conservative when the edge shares an IP.
    const key = req.socket.remoteAddress || "unknown";
    let bucket = buckets.get(key);
    if (!bucket) {
      if (buckets.size >= maxKeys) {
        res.set("Retry-After", "60");
        return res.status(429).json({ error: "Please wait before trying again." });
      }
      bucket = { count: 0, until: now + windowMs };
      buckets.set(key, bucket);
    }
    if (++bucket.count > limit) {
      res.set("Retry-After", String(Math.max(1, Math.ceil((bucket.until - now) / 1000))));
      return res.status(429).json({ error: "Too many requests. Please wait before trying again." });
    }
    next();
  };
}
