import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import test from "node:test";

const SOURCE_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function runSyncWithSyntaxResult(t, mode) {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "gitmesh-sync-syntax-"));
  t.after(() => fs.rmSync(tempDir, { recursive: true, force: true }));

  const scriptPath = path.join(tempDir, "sync-public-source.mjs");
  const preloadPath = path.join(tempDir, "simulate-syntax-result.mjs");
  const syntaxMarker = path.join(tempDir, "syntax-check-invoked");
  const fetchMarker = path.join(tempDir, "github-fetch-invoked");
  const privateSource = "PRIVATE_SYNTAX_SOURCE_SENTINEL";
  const privateNodeOutput = "PRIVATE_NODE_DIAGNOSTIC_SENTINEL";
  const fakeToken = "test-only-not-a-real-token";

  for (const name of ["README.md", "sync-public-source.mjs", "gitmesh-ultimate-core.mjs"]) {
    fs.copyFileSync(path.join(SOURCE_DIR, name), path.join(tempDir, name));
  }
  fs.writeFileSync(
    path.join(tempDir, "gitmesh-ultimate-core.mjs"),
    `export const ${privateSource} = ;\n`,
  );
  fs.writeFileSync(
    preloadPath,
    [
      'import fs from "node:fs";',
      'import childProcess from "node:child_process";',
      'import { syncBuiltinESMExports } from "node:module";',
      "const originalSpawnSync = childProcess.spawnSync.bind(childProcess);",
      "childProcess.spawnSync = (command, args, options) => {",
      '  if (command === process.execPath && Array.isArray(args) && args.includes("--check")) {',
      '    fs.writeFileSync(process.env.GITMESH_TEST_SYNTAX_MARKER, "invoked");',
      '    const mode = process.env.GITMESH_TEST_SYNTAX_FAILURE_MODE;',
      '    if (mode === "syntax") return originalSpawnSync(command, args, options);',
      '    const errorCode = mode === "timeout" ? "ETIMEDOUT" : "ENOBUFS";',
      "    return {",
      `      error: mode === "interrupted" ? undefined : Object.assign(new Error("${privateNodeOutput}"), { code: errorCode }),`,
      "      status: null,",
      '      signal: mode === "interrupted" ? "SIGTERM" : null,',
      `      stdout: Buffer.from("${privateNodeOutput}"),`,
      `      stderr: Buffer.from("${privateNodeOutput}"),`,
      "      pid: 123,",
      "      output: [],",
      "    };",
      "  }",
      "  return originalSpawnSync(command, args, options);",
      "};",
      "syncBuiltinESMExports();",
      "globalThis.fetch = async () => {",
      '  fs.writeFileSync(process.env.GITMESH_TEST_FETCH_MARKER, "called");',
      '  throw new Error("network request attempted");',
      "};",
    ].join("\n"),
  );

  const result = spawnSync(process.execPath, [scriptPath], {
    cwd: tempDir,
    encoding: "utf8",
    timeout: 30_000,
    env: {
      PATH: process.env.PATH ?? "",
      GITHUB_TOKEN: fakeToken,
      GITMESH_TEST_SYNTAX_MARKER: syntaxMarker,
      GITMESH_TEST_FETCH_MARKER: fetchMarker,
      GITMESH_TEST_SYNTAX_FAILURE_MODE: mode,
      NODE_OPTIONS: `--import=${pathToFileURL(preloadPath).href}`,
    },
  });
  return {
    output: result.stdout + result.stderr,
    result,
    syntaxMarker,
    fetchMarker,
    privateTexts: [privateSource, privateNodeOutput, fakeToken, "ENOBUFS", "[stdin]", "SyntaxError"],
  };
}

function assertSafeSyntaxFailure(fixture, expectedMessage) {
  const { output, result, syntaxMarker, fetchMarker, privateTexts } = fixture;
  assert.notEqual(result.status, 0, output);
  assert.equal(output.trim(), expectedMessage);
  assert.ok(fs.existsSync(syntaxMarker), "the bounded syntax subprocess was not exercised");
  assert.ok(!fs.existsSync(fetchMarker), "source sync attempted a GitHub request");
  for (const privateText of privateTexts) {
    assert.ok(!output.includes(privateText), `private diagnostic leaked: ${privateText}`);
  }
}

test("syntax-check output overflow is private and stops source sync before GitHub", (t) => {
  const fixture = runSyncWithSyntaxResult(t, "enobufs");
  assertSafeSyntaxFailure(
    fixture,
    "Refusing to sync JavaScript that fails Node syntax validation: " +
      "gitmesh-ultimate-core.mjs. Correct the JavaScript and retry the source sync. " +
      "No GitHub requests were made.",
  );
});

test("syntax-check timeout is distinct from invalid JavaScript and stops source sync", (t) => {
  const fixture = runSyncWithSyntaxResult(t, "timeout");
  assertSafeSyntaxFailure(
    fixture,
    "Node syntax validation timed out for gitmesh-ultimate-core.mjs. " +
      "Retry the source sync. No GitHub requests were made.",
  );
});

test("interrupted syntax-check is distinct from invalid JavaScript and stops source sync", (t) => {
  const fixture = runSyncWithSyntaxResult(t, "interrupted");
  assertSafeSyntaxFailure(
    fixture,
    "Node syntax validation was interrupted for gitmesh-ultimate-core.mjs. " +
      "Retry the source sync. No GitHub requests were made.",
  );
});

test("genuine syntax errors still report invalid JavaScript without parser output", (t) => {
  const fixture = runSyncWithSyntaxResult(t, "syntax");
  assertSafeSyntaxFailure(
    fixture,
    "Refusing to sync JavaScript that fails Node syntax validation: " +
      "gitmesh-ultimate-core.mjs. Correct the JavaScript and retry the source sync. " +
      "No GitHub requests were made.",
  );
});
