const jobs = [
  ["house", () => {
    let total = 0;
    for (let step = 0; step < 2000; step += 1) total += Math.hypot(Math.cos(step), Math.sin(step));
    return total;
  }],
  ["rank", () => {
    const rows = Array.from({ length: 4000 }, (_, index) => (index * 17) % 97);
    rows.sort((left, right) => left - right);
    return rows[0];
  }],
  ["spin", () => {
    let even = 0;
    for (let shot = 0; shot < 8000; shot += 1) if (shot % 2 === 0) even += 1;
    return even;
  }],
];

const order = jobs
  .map(([name, work]) => {
    const start = performance.now();
    work();
    return { name, ms: performance.now() - start };
  })
  .sort((left, right) => left.ms - right.ms || left.name.localeCompare(right.name));

console.log(order.map((job) => `${job.name} ${job.ms.toFixed(1)}`).join(", "));
