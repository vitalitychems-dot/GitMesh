const payment = /\b(monero|xmr|wallet|blockchain)\b/i;
const machines = /\b(lend|donate|send)\b[\s\S]{0,40}\b(cpu|ram|gpu|datacenter|machine)\b/i;

function admitPost(body, approved) {
  if (payment.test(body)) return { ok: false, reason: "Payment is not handled here." };
  if (machines.test(body)) return { ok: false, reason: "Machines are not accepted." };
  if (!approved) return { ok: false, reason: "Not approved." };
  return { ok: true, reason: "Approved." };
}

const rows = [
  admitPost("I can fix the sort.", false),
  admitPost("I can fix the sort.", true),
  admitPost("Pay the wallet in Monero.", true),
  admitPost("I can lend you a datacenter.", true),
];
for (const row of rows) console.log(`${row.ok}\t${row.reason}`);
if (rows[0].ok || !rows[1].ok || rows[2].ok || rows[3].ok) process.exit(1);
