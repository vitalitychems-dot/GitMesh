import { createHash, randomBytes, scrypt, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";

const derive = promisify(scrypt);
const TOKEN = /^[A-Za-z0-9_-]{43}$/;
export const digest = (value) => createHash("sha256").update(value, "utf8").digest("hex");
const token = () => randomBytes(32).toString("base64url");
export function validSigil(value) {
  return typeof value === "string" && Buffer.byteLength(value, "utf8") >= 20 &&
    Buffer.byteLength(value, "utf8") <= 256 && !/[\u0000-\u001f\u007f]/.test(value);
}
async function verifier(value, salt) {
  return (await derive(value, salt, 64, { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 })).toString("hex");
}
function failure(status, message) { return Object.assign(new Error(message), { publicStatus: status }); }

export class PrivateAuth {
  constructor(store) { this.store = store; this.inFlight = 0; }
  async initialize(bootstrap = process.env.GITMESH_WEB_ADMIN_KEY) {
    if (await this.store.active() || !bootstrap) return;
    if (!validSigil(bootstrap)) throw new Error("GITMESH_WEB_ADMIN_KEY must contain 20–256 bytes and no control characters.");
    const salt = randomBytes(32).toString("hex");
    await this.store.initialize({ salt, verifier: await verifier(bootstrap, salt), digest: digest(bootstrap) });
  }
  async configured() { return Boolean(await this.store.active()); }
  async begin(sigil) {
    if (!validSigil(sigil)) throw failure(400, "Enter an admin key of 20–256 bytes.");
    if (this.inFlight >= 2) throw failure(429, "Sign-in is busy. Please wait and try again.");
    this.inFlight++;
    try {
      if (!await this.store.attemptAllowed()) throw failure(429, "Too many sign-in attempts. Wait one minute and try again.");
      const current = await this.store.active();
      if (!current) throw failure(503, "Web admin access is not configured. Set the initial key in project Secrets.");
      const actual = Buffer.from(await verifier(sigil, current.salt), "hex");
      const expected = Buffer.from(current.verifier, "hex");
      if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) throw failure(401, "Sign-in failed. The current key remains unchanged.");
      if (current.generation >= 2147483646) throw failure(409, "Key rotation is unavailable. No key was consumed.");
      let nextSigil;
      for (let i = 0; i < 8; i++) {
        const candidate = `gm-web-${current.generation + 1}-${token()}`;
        if (!await this.store.knownKey(digest(candidate))) { nextSigil = candidate; break; }
      }
      if (!nextSigil) throw failure(503, "Could not issue a replacement. No key was consumed.");
      const pendingToken = token();
      const salt = randomBytes(32).toString("hex");
      const saved = await this.store.pending({
        tokenHash: digest(pendingToken), generation: current.generation,
        salt, verifier: await verifier(nextSigil, salt), digest: digest(nextSigil),
      });
      if (!saved) throw failure(409, "Another sign-in completed. Use the latest saved key.");
      return { nextSigil, pendingToken };
    } finally { this.inFlight--; }
  }
  async confirm(pendingToken) {
    if (!TOKEN.test(pendingToken || "")) throw failure(410, "This sign-in expired. Start again with the current key.");
    const sessionToken = token();
    if (!await this.store.confirm(digest(pendingToken), digest(sessionToken))) {
      throw failure(409, "This sign-in expired or another sign-in completed. Use your latest saved key.");
    }
    return sessionToken;
  }
  async session(sessionToken) {
    return TOKEN.test(sessionToken || "") ? this.store.session(digest(sessionToken)) : false;
  }
  async cancel(pendingToken) {
    if (TOKEN.test(pendingToken || "")) await this.store.cancel(digest(pendingToken));
  }
  async logout(sessionToken) {
    if (TOKEN.test(sessionToken || "")) await this.store.logout(digest(sessionToken));
  }
}
