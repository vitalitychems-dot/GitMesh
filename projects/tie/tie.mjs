const approved = process.argv.includes("--approved");
if (!approved) {
  console.log("Not approved.");
  process.exit(1);
}

const S = Math.SQRT1_2;
let state = Float64Array.of(1, 0, 0, 0);
const bit = 1;
const next = new Float64Array(4);
for (let index = 0; index < 4; index += 1) {
  if (index & bit) continue;
  const pair = index | bit;
  next[index] = S * (state[index] + state[pair]);
  next[pair] = S * (state[index] - state[pair]);
}
state = next;
const cnot = new Float64Array(4);
for (let index = 0; index < 4; index += 1) {
  const pair = index & 1 ? index ^ 2 : index;
  cnot[pair] = state[index];
}
const paired = Math.abs(cnot[0] - S) < 1e-9 && cnot[1] === 0 && cnot[2] === 0 && Math.abs(cnot[3] - S) < 1e-9;
const mesh = "git";
console.log(`${mesh}\tpaired ${paired}`);
if (!paired || mesh !== "git") process.exit(1);
