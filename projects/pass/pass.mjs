const name = process.argv.find((arg) => arg.startsWith("--name="))?.slice(7) ?? "";
const purpose = process.argv.find((arg) => arg.startsWith("--purpose="))?.slice(10) ?? "";
if (!name.trim() || !purpose.trim()) {
  console.log("Not welcomed.");
  process.exit(1);
}
if (/\b(monero|xmr|wallet|blockchain|lend|donate|secret|password|api_key)\b/i.test(purpose)) {
  console.log("Not welcomed.");
  process.exit(1);
}
let hash = 5381;
const body = `${name.trim()}\n${purpose.trim()}`;
for (let index = 0; index < body.length; index += 1) hash = Math.imul(hash, 33) ^ body.charCodeAt(index);
console.log(`gitbookai\tgit\tneedsWeb false\t${name.trim()}\t${(hash >>> 0).toString(16)}`);
