const S = Math.SQRT1_2;

function mulberry32(seed) {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let next = Math.imul(state ^ (state >>> 15), 1 | state);
    next = (next + Math.imul(next ^ (next >>> 7), 61 | next)) ^ next;
    return ((next ^ (next >>> 14)) >>> 0) / 4294967296;
  };
}

function hadamard(state, qubit) {
  const bit = 1 << qubit;
  const next = new Float64Array(state.length);
  for (let index = 0; index < state.length; index += 1) {
    if (index & bit) continue;
    const pair = index | bit;
    next[index] = S * (state[index] + state[pair]);
    next[pair] = S * (state[index] - state[pair]);
  }
  return next;
}

function cnot(state, control, target) {
  const controlBit = 1 << control;
  const targetBit = 1 << target;
  const next = new Float64Array(state.length);
  for (let index = 0; index < state.length; index += 1) {
    const pair = index & controlBit ? index ^ targetBit : index;
    next[pair] = state[index];
  }
  return next;
}

function shots(state, count, seed) {
  const random = mulberry32(seed);
  const weights = Array.from(state, (value) => value * value);
  const counts = new Array(state.length).fill(0);
  for (let shot = 0; shot < count; shot += 1) {
    let mark = random();
    let chosen = weights.length - 1;
    for (let index = 0; index < weights.length; index += 1) {
      mark -= weights[index];
      if (mark <= 0) {
        chosen = index;
        break;
      }
    }
    counts[chosen] += 1;
  }
  return counts;
}

const state = cnot(hadamard(Float64Array.of(1, 0, 0, 0), 0), 0, 1);
const counts = shots(state, 20000, 7);
const together = counts[0] + counts[3];
const split = counts[1] + counts[2];
const back = hadamard(hadamard(Float64Array.of(1, 0), 0), 0);
const held = together > split * 9 && Math.abs(back[0] - 1) < 1e-9;
console.log(`${counts.join(",")}\ttogether ${together}\tsplit ${split}\theld ${held}`);
if (!held) process.exit(1);
