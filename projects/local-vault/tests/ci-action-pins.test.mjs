import { readFile } from "node:fs/promises";
import assert from "node:assert/strict";
import test from "node:test";

test("source-sync workflow uses reviewed immutable action pins with release comments", async () => {
  const workflow = await readFile(new URL("../../../.github/workflows/local-vault-regressions.yml", import.meta.url), "utf8");
  const actions = [...workflow.matchAll(/^\s*uses:\s*(\S+)\s*#\s*(v[\d.]+)\s*$/gm)];
  assert.equal(actions.length, 2);
  assert.deepEqual(actions.map((m) => [m[1], m[2]]), [
    ["actions/checkout@11d5960a326750d5838078e36cf38b85af677262", "v4.4.0"],
    ["actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020", "v4.4.0"],
  ]);
  assert.equal([...workflow.matchAll(/^\s*uses:/gm)].length, actions.length);
  assert.match(workflow, /contents: read/);
  assert.match(workflow, /persist-credentials: false/);
});
