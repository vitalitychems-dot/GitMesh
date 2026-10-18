import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import test from "node:test";

const SOURCE_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function timeoutFromSource(source, pattern, label) {
  const match = source.match(pattern);
  assert.ok(match, `could not find the ${label} timeout in sync-public-source.mjs`);
  return Number(match[1].replaceAll("_", ""));
}

test("README timeout guidance matches the fixed source-sync limits", () => {
  const implementation = fs.readFileSync(
    path.join(SOURCE_DIR, "sync-public-source.mjs"),
    "utf8",
  );
  const readme = fs.readFileSync(path.join(SOURCE_DIR, "README.md"), "utf8");
  const syntaxTimeoutMs = timeoutFromSource(
    implementation,
    /\btimeout:\s*([\d_]+)/,
    "Node syntax validation",
  );
  const githubTimeoutMs = timeoutFromSource(
    implementation,
    /AbortSignal\.timeout\(([\d_]+)\)/,
    "GitHub request",
  );

  assert.equal(syntaxTimeoutMs % 1000, 0, "Node syntax timeout must use whole seconds");
  assert.equal(githubTimeoutMs % 1000, 0, "GitHub request timeout must use whole seconds");
  assert.ok(
    readme.includes(
      `JavaScript syntax validation times out after ${syntaxTimeoutMs / 1000} seconds.`,
    ),
    `README must document the ${syntaxTimeoutMs} ms syntax-validation timeout`,
  );
  assert.ok(
    readme.includes(
      `Each GitHub API request times out after ${githubTimeoutMs / 1000} seconds.`,
    ),
    `README must document the ${githubTimeoutMs} ms GitHub request timeout`,
  );
  assert.ok(
    readme.includes(
      "These are fixed limits; there is no repository-specific or environment override.",
    ),
    "README must explain that timeout values cannot be overridden",
  );
});

function runSyncWithSyntaxResult(t, mode, { checkOnly = false } = {}) {
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
  const sourcePath = path.join(tempDir, "gitmesh-ultimate-core.mjs");
  if (mode === "invalid-utf8") {
    fs.writeFileSync(
      sourcePath,
      Buffer.concat([Buffer.from(`// ${privateSource}\n`), Buffer.from([0xc3, 0x28])]),
    );
  } else if (mode === "nul") {
    fs.writeFileSync(
      sourcePath,
      Buffer.concat([
        Buffer.from(`// ${privateSource}\nconst value = "`),
        Buffer.from([0]),
        Buffer.from('";\n'),
      ]),
    );
  } else if (mode === "linked") {
    const readmePath = path.join(tempDir, "README.md");
    fs.appendFileSync(readmePath, `\n${privateSource}\n`);
    fs.unlinkSync(sourcePath);
    fs.symlinkSync(readmePath, sourcePath);
  } else if (mode === "oversized") {
    fs.writeFileSync(
      sourcePath,
      Buffer.concat([
        Buffer.from(`// ${privateSource}\n`),
        Buffer.alloc(512 * 1024 + 1, 0x20),
      ]),
    );
  } else if (mode === "other-invalid") {
    fs.unlinkSync(sourcePath);
    fs.mkdirSync(sourcePath);
    fs.writeFileSync(path.join(sourcePath, "private-data"), privateSource);
  } else if (mode !== "success") {
    fs.writeFileSync(sourcePath, `export const ${privateSource} = ;\n`);
  } else {
    fs.appendFileSync(path.join(tempDir, "README.md"), `\n${privateSource}\n`);
  }
  fs.writeFileSync(
    preloadPath,
    [
      'import fs from "node:fs";',
      'import childProcess from "node:child_process";',
      'import { syncBuiltinESMExports } from "node:module";',
      "const originalSpawnSync = childProcess.spawnSync.bind(childProcess);",
      "const originalReadFileSync = fs.readFileSync.bind(fs);",
      "let sourceChangedDuringRead = false;",
      "fs.readFileSync = (file, ...args) => {",
      "  const content = originalReadFileSync(file, ...args);",
      '  if (process.env.GITMESH_TEST_SYNTAX_FAILURE_MODE === "changed-during-read" && !sourceChangedDuringRead && typeof file === "string" && file.endsWith("gitmesh-ultimate-core.mjs")) {',
      "    sourceChangedDuringRead = true;",
      `    fs.writeFileSync(file, "// ${privateNodeOutput}\\n");`,
      "  }",
      "  return content;",
      "};",
      "childProcess.spawnSync = (command, args, options) => {",
      '  if (command === process.execPath && Array.isArray(args) && args.includes("--check")) {',
      '    fs.writeFileSync(process.env.GITMESH_TEST_SYNTAX_MARKER, "invoked");',
      '    const mode = process.env.GITMESH_TEST_SYNTAX_FAILURE_MODE;',
      '    if (mode === "syntax" || mode === "success") return originalSpawnSync(command, args, options);',
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

  const env = {
    PATH: process.env.PATH ?? "",
    GITMESH_TEST_SYNTAX_MARKER: syntaxMarker,
    GITMESH_TEST_FETCH_MARKER: fetchMarker,
    GITMESH_TEST_SYNTAX_FAILURE_MODE: mode,
    NODE_OPTIONS: `--import=${pathToFileURL(preloadPath).href}`,
  };
  if (!checkOnly) env.GITHUB_TOKEN = fakeToken;
  const result = spawnSync(process.execPath, [
    scriptPath,
    ...(checkOnly ? ["--check-syntax"] : []),
  ], {
    cwd: tempDir,
    encoding: "utf8",
    timeout: 30_000,
    env,
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

function assertSafeSyntaxPreflightFailure(fixture, expectedMessage) {
  const { output, result, syntaxMarker, fetchMarker, privateTexts } = fixture;
  assert.notEqual(result.status, 0, output);
  assert.equal(output.trim(), expectedMessage);
  assert.ok(!fs.existsSync(syntaxMarker), "syntax validation ran before source checks");
  assert.ok(!fs.existsSync(fetchMarker), "preflight attempted a GitHub request");
  for (const privateText of privateTexts) {
    assert.ok(!output.includes(privateText), `private diagnostic leaked: ${privateText}`);
  }
}

function runSyncWithBranchSha(t, branchSha, mode = "success") {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "gitmesh-sync-branch-sha-"));
  t.after(() => fs.rmSync(tempDir, { recursive: true, force: true }));

  const scriptPath = path.join(tempDir, "sync-public-source.mjs");
  const preloadPath = path.join(tempDir, "mock-github-branch-sha.mjs");
  const requestLog = path.join(tempDir, "github-requests.json");
  const fakeToken = "test-only-not-a-real-token";
  const privateSource = "PRIVATE_BRANCH_SHA_SOURCE_SENTINEL";
  const privateResponseBody = "PRIVATE_BASE_COMMIT_RESPONSE_SENTINEL";
  const privateNetworkError = "PRIVATE_BRANCH_NETWORK_ERROR_SENTINEL";

  for (const name of ["README.md", "sync-public-source.mjs", "gitmesh-ultimate-core.mjs"]) {
    fs.copyFileSync(path.join(SOURCE_DIR, name), path.join(tempDir, name));
  }
  fs.appendFileSync(path.join(tempDir, "README.md"), `\n${privateSource}\n`);
  fs.writeFileSync(requestLog, "[]");
  fs.writeFileSync(
    preloadPath,
    [
      'import fs from "node:fs";',
      'const response = (value) => ({ ok: true, json: async () => value });',
      "const requests = [];",
      "const branchSha = process.env.GITMESH_TEST_BRANCH_SHA;",
      'const baseTreeSha = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";',
      'const newTreeSha = "cccccccccccccccccccccccccccccccccccccccc";',
      'const commitSha = "dddddddddddddddddddddddddddddddddddddddd";',
      'const blobSha = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";',
      "globalThis.fetch = async (url, options = {}) => {",
      '  const method = options.method ?? "GET";',
      "  const request = { method, url };",
      '  if (method === "POST" && url.endsWith("/git/trees")) {',
      '    request.treePaths = JSON.parse(options.body).tree.map((entry) => entry.path);',
      "  }",
      "  requests.push(request);",
      "  fs.writeFileSync(process.env.GITMESH_TEST_REQUEST_LOG, JSON.stringify(requests));",
      '  if (method === "GET" && url.endsWith("/git/ref/heads/main")) {',
      '    if (process.env.GITMESH_TEST_MODE === "branch-http-503") {',
      "      return {",
      "        ok: false,",
      "        status: 503,",
      "        statusText: process.env.GITMESH_TEST_RESPONSE_SENTINEL,",
      "        json: async () => { throw new Error(process.env.GITMESH_TEST_RESPONSE_SENTINEL); },",
      "      };",
      "    }",
      '    if (process.env.GITMESH_TEST_MODE === "branch-network-error") {',
      "      throw new Error(process.env.GITMESH_TEST_NETWORK_SENTINEL);",
      "    }",
      '    if (process.env.GITMESH_TEST_MODE === "branch-invalid-json") {',
      "      return {",
      "        ok: true,",
      "        json: async () => { throw new Error(process.env.GITMESH_TEST_RESPONSE_SENTINEL); },",
      "      };",
      "    }",
      "    return response({ object: { sha: branchSha } });",
      "  }",
      '  if (method === "GET" && url.endsWith(`/git/commits/${branchSha}`)) {',
      '    if (process.env.GITMESH_TEST_MODE === "base-commit-invalid-json") {',
      "      return {",
      "        ok: true,",
      "        json: async () => { throw new Error(process.env.GITMESH_TEST_RESPONSE_SENTINEL); },",
      "      };",
      "    }",
      "    return response({ tree: { sha: baseTreeSha } });",
      "  }",
      '  if (method === "POST" && url.endsWith("/git/blobs")) {',
      "    return response({ sha: blobSha });",
      "  }",
      '  if (method === "POST" && url.endsWith("/git/trees")) {',
      "    return response({ sha: newTreeSha });",
      "  }",
      '  if (method === "POST" && url.endsWith("/git/commits")) {',
      "    return response({ sha: commitSha });",
      "  }",
      '  if (method === "PATCH" && url.endsWith("/git/refs/heads/main")) {',
      "    return response({ object: { sha: commitSha } });",
      "  }",
      '  throw new Error("unexpected mocked GitHub request");',
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
      GITMESH_TEST_BRANCH_SHA: branchSha,
      GITMESH_TEST_MODE: mode,
      GITMESH_TEST_RESPONSE_SENTINEL: privateResponseBody,
      GITMESH_TEST_NETWORK_SENTINEL: privateNetworkError,
      GITMESH_TEST_REQUEST_LOG: requestLog,
      NODE_OPTIONS: `--import=${pathToFileURL(preloadPath).href}`,
    },
  });
  return {
    output: result.stdout + result.stderr,
    result,
    requests: JSON.parse(fs.readFileSync(requestLog, "utf8")),
    fakeToken,
    privateSource,
    privateResponseBody,
    privateNetworkError,
  };
}

for (const [label, branchSha] of [
  ["39-character lowercase SHA", "a".repeat(39)],
  ["41-character lowercase SHA", "a".repeat(41)],
  ["64-character lowercase SHA", "a".repeat(64)],
  ["uppercase SHA", "A".repeat(40)],
]) {
  test(`normal sync rejects invalid ${label} before any writes`, (t) => {
    const fixture = runSyncWithBranchSha(t, branchSha);
    const expectedRefUrl =
      "https://api.github.com/repos/vitalitychems-dot/GitMesh/git/ref/heads/main";

    assert.equal(fixture.result.status, 1, fixture.output);
    assert.equal(
      fixture.output.trim(),
      "GitHub returned an invalid main branch commit; sync stopped.",
    );
    assert.deepEqual(fixture.requests, [{ method: "GET", url: expectedRefUrl }]);
    assert.ok(!fixture.output.includes(branchSha), "malformed SHA leaked in output");
    assert.ok(!fixture.output.includes(fixture.fakeToken), "GitHub token leaked in output");
    assert.ok(!fixture.output.includes(fixture.privateSource), "source content leaked in output");
  });
}

test("normal sync accepts a valid lowercase 40-character branch SHA", (t) => {
  const branchSha = "a".repeat(40);
  const fixture = runSyncWithBranchSha(t, branchSha);
  const apiRoot = "https://api.github.com/repos/vitalitychems-dot/GitMesh";

  assert.equal(fixture.result.status, 0, fixture.output);
  assert.ok(fixture.output.includes("Synced 3 allowlisted source files"));
  assert.deepEqual(
    fixture.requests.map(({ method, url }) => [method, url]),
    [
      ["GET", `${apiRoot}/git/ref/heads/main`],
      ["GET", `${apiRoot}/git/commits/${branchSha}`],
      ["POST", `${apiRoot}/git/blobs`],
      ["POST", `${apiRoot}/git/blobs`],
      ["POST", `${apiRoot}/git/blobs`],
      ["POST", `${apiRoot}/git/trees`],
      ["POST", `${apiRoot}/git/commits`],
      ["PATCH", `${apiRoot}/git/refs/heads/main`],
    ],
  );
  assert.deepEqual(fixture.requests[5].treePaths, [
    "projects/local-vault/gitmesh-ultimate-core.mjs",
    "projects/local-vault/README.md",
    "projects/local-vault/sync-public-source.mjs",
  ]);
  assert.ok(fixture.requests.every(({ url }) => url.startsWith(`${apiRoot}/`)));
  assert.ok(!fixture.output.includes(fixture.fakeToken), "GitHub token leaked in output");
  assert.ok(!fixture.output.includes(fixture.privateSource), "source content leaked in output");
});

test("normal sync stops when the base-commit response JSON is unreadable", (t) => {
  const branchSha = "a".repeat(40);
  const fixture = runSyncWithBranchSha(t, branchSha, "base-commit-invalid-json");
  const apiRoot = "https://api.github.com/repos/vitalitychems-dot/GitMesh";

  assert.equal(fixture.result.status, 1, fixture.output);
  assert.equal(
    fixture.output.trim(),
    `GitHub returned an invalid response during GET /git/commits/${branchSha}.`,
  );
  assert.deepEqual(fixture.requests, [
    { method: "GET", url: `${apiRoot}/git/ref/heads/main` },
    { method: "GET", url: `${apiRoot}/git/commits/${branchSha}` },
  ]);
  assert.ok(!fixture.output.includes(fixture.privateResponseBody), "response body leaked in output");
  assert.ok(!fixture.output.includes(fixture.fakeToken), "GitHub token leaked in output");
  assert.ok(!fixture.output.includes(fixture.privateSource), "source content leaked in output");
  assert.ok(
    fixture.requests.every(({ method }) => method === "GET"),
    "sync attempted a write after the unreadable base-commit response",
  );
});

test("normal sync stops when the branch response JSON is unreadable", (t) => {
  const fixture = runSyncWithBranchSha(t, "a".repeat(40), "branch-invalid-json");
  const expectedRefUrl =
    "https://api.github.com/repos/vitalitychems-dot/GitMesh/git/ref/heads/main";

  assert.equal(fixture.result.status, 1, fixture.output);
  assert.equal(
    fixture.output.trim(),
    "GitHub returned an invalid response during GET /git/ref/heads/main.",
  );
  assert.deepEqual(fixture.requests, [{ method: "GET", url: expectedRefUrl }]);
  assert.ok(!fixture.output.includes(fixture.privateResponseBody), "response body leaked in output");
  assert.ok(!fixture.output.includes(fixture.fakeToken), "GitHub token leaked in output");
  assert.ok(!fixture.output.includes(fixture.privateSource), "source content leaked in output");
  assert.ok(
    fixture.requests.every(({ method }) => method === "GET"),
    "sync attempted a source read or write after the unreadable branch response",
  );
});

for (const [mode, label, expectedMessage] of [
  [
    "branch-http-503",
    "HTTP 503",
    "GitHub request failed with HTTP 503 during GET /git/ref/heads/main. " +
      "Check the connection and retry; sync stopped.",
  ],
  [
    "branch-network-error",
    "a network failure",
    "GitHub request failed during GET /git/ref/heads/main. " +
      "Check the connection and retry; sync stopped.",
  ],
]) {
  test(`normal sync gives safe rerun guidance for ${label} on the branch lookup`, (t) => {
    const fixture = runSyncWithBranchSha(t, "a".repeat(40), mode);
    const expectedRefUrl =
      "https://api.github.com/repos/vitalitychems-dot/GitMesh/git/ref/heads/main";

    assert.equal(fixture.result.status, 1, fixture.output);
    assert.equal(fixture.output.trim(), expectedMessage);
    assert.deepEqual(fixture.requests, [{ method: "GET", url: expectedRefUrl }]);
    assert.ok(!fixture.output.includes(fixture.privateResponseBody), "response data leaked in output");
    assert.ok(!fixture.output.includes(fixture.privateNetworkError), "network diagnostic leaked in output");
    assert.ok(!fixture.output.includes(fixture.fakeToken), "GitHub token leaked in output");
    assert.ok(!fixture.output.includes(fixture.privateSource), "source content leaked in output");
  });
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

for (const [mode, problem, expectedReason] of [
  ["invalid-utf8", "invalid UTF-8", "is not valid UTF-8"],
  ["nul", "NUL bytes", "contains NUL bytes"],
]) {
  test(`non-text JavaScript reports syntax-specific repair guidance for ${problem}`, (t) => {
    const fixture = runSyncWithSyntaxResult(t, mode, { checkOnly: true });
    assertSafeSyntaxPreflightFailure(
      fixture,
      `JavaScript source gitmesh-ultimate-core.mjs ${expectedReason}. ` +
        "Save it as valid UTF-8 text and rerun --check-syntax. " +
        "No GitHub requests were made.",
    );
  });
}

for (const [mode, problem, expectedMessage] of [
  [
    "linked",
    "a symbolic link",
    "JavaScript source gitmesh-ultimate-core.mjs is a symbolic link. " +
      "Replace it with a regular file, then rerun --check-syntax. " +
      "No GitHub requests were made.",
  ],
  [
    "oversized",
    "an oversized file",
    "JavaScript source gitmesh-ultimate-core.mjs exceeds the 512 KiB limit. " +
      "Reduce it to 512 KiB or less, then rerun --check-syntax. " +
      "No GitHub requests were made.",
  ],
  [
    "other-invalid",
    "a non-regular file",
    "JavaScript source gitmesh-ultimate-core.mjs is not a regular file. " +
      "Restore it as a regular file, then rerun --check-syntax. " +
      "No GitHub requests were made.",
  ],
]) {
  test(`--check-syntax explains how to repair ${problem}`, (t) => {
    const fixture = runSyncWithSyntaxResult(t, mode, { checkOnly: true });
    assertSafeSyntaxPreflightFailure(fixture, expectedMessage);
  });
}

test("--check-syntax succeeds without a GitHub token or network request", (t) => {
  const fixture = runSyncWithSyntaxResult(t, "success", { checkOnly: true });

  assert.equal(fixture.result.status, 0, fixture.output);
  assert.equal(
    fixture.output.trim(),
    "JavaScript syntax validation passed for 2 files: " +
      "gitmesh-ultimate-core.mjs, sync-public-source.mjs.",
  );
  assert.ok(!fixture.output.includes("README.md"), "a non-JavaScript file was listed");
  assert.ok(fs.existsSync(fixture.syntaxMarker), "the syntax subprocess was not exercised");
  assert.ok(!fs.existsSync(fixture.fetchMarker), "syntax check attempted a GitHub request");
  for (const privateText of fixture.privateTexts) {
    assert.ok(!fixture.output.includes(privateText), `source content leaked: ${privateText}`);
  }
});

test("syntax validation rejects a source file that changes during inspection", (t) => {
  const fixture = runSyncWithSyntaxResult(t, "changed-during-read");
  const { output, result, syntaxMarker, fetchMarker, privateTexts } = fixture;

  assert.notEqual(result.status, 0, output);
  assert.equal(
    output.trim(),
    "JavaScript source changed during syntax validation: gitmesh-ultimate-core.mjs. " +
      "Save the intended file and retry the source sync; syntax validation will run again. " +
      "No GitHub requests were made.",
  );
  assert.ok(!fs.existsSync(syntaxMarker), "syntax validation used a stale source snapshot");
  assert.ok(!fs.existsSync(fetchMarker), "source sync attempted a GitHub request");
  for (const privateText of privateTexts) {
    assert.ok(!output.includes(privateText), `private diagnostic leaked: ${privateText}`);
  }
});

test("GitHub request timeout stops sync without leaking source or continuing writes", (t) => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "gitmesh-sync-timeout-"));
  t.after(() => fs.rmSync(tempDir, { recursive: true, force: true }));

  const scriptPath = path.join(tempDir, "sync-public-source.mjs");
  const preloadPath = path.join(tempDir, "simulate-fetch-timeout.mjs");
  const requestLog = path.join(tempDir, "github-requests.json");
  const fakeToken = "test-only-not-a-real-token";
  const privateSource = "PRIVATE_SOURCE_CONTENT_SENTINEL";
  const privateFetchError = "PRIVATE_FETCH_TIMEOUT_SENTINEL";

  for (const name of ["README.md", "sync-public-source.mjs", "gitmesh-ultimate-core.mjs"]) {
    fs.copyFileSync(path.join(SOURCE_DIR, name), path.join(tempDir, name));
  }
  fs.appendFileSync(
    path.join(tempDir, "gitmesh-ultimate-core.mjs"),
    `\n// ${privateSource}\n`,
  );
  fs.writeFileSync(
    preloadPath,
    [
      'import fs from "node:fs";',
      "globalThis.fetch = async (url, options = {}) => {",
      "  const requests = JSON.parse(fs.readFileSync(process.env.GITMESH_TEST_REQUEST_LOG, \"utf8\") || \"[]\");",
      '  requests.push({ method: options.method ?? "GET", url });',
      '  fs.writeFileSync(process.env.GITMESH_TEST_REQUEST_LOG, JSON.stringify(requests));',
      '  if (url.endsWith("/git/ref/heads/main")) {',
      '    return { ok: true, json: async () => ({ object: { sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" } }) };',
      "  }",
      '  if (url.endsWith("/git/commits/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")) {',
      '    return { ok: true, json: async () => ({ tree: { sha: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" } }) };',
      "  }",
      `  const error = new Error("${privateFetchError}");`,
      '  error.name = "TimeoutError";',
      "  throw error;",
      "};",
    ].join("\n"),
  );
  fs.writeFileSync(requestLog, "[]");

  const result = spawnSync(process.execPath, [scriptPath], {
    cwd: tempDir,
    encoding: "utf8",
    timeout: 30_000,
    env: {
      PATH: process.env.PATH ?? "",
      GITHUB_TOKEN: fakeToken,
      GITMESH_TEST_REQUEST_LOG: requestLog,
      NODE_OPTIONS: `--import=${pathToFileURL(preloadPath).href}`,
    },
  });
  const output = result.stdout + result.stderr;

  assert.equal(result.status, 1, output);
  assert.equal(
    output.trim(),
    "GitHub request timed out during POST /git/blobs. " +
      "Check the connection and retry; sync stopped.",
  );
  assert.deepEqual(JSON.parse(fs.readFileSync(requestLog, "utf8")), [
    {
      method: "GET",
      url: "https://api.github.com/repos/vitalitychems-dot/GitMesh/git/ref/heads/main",
    },
    {
      method: "GET",
      url: "https://api.github.com/repos/vitalitychems-dot/GitMesh/git/commits/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    },
    {
      method: "POST",
      url: "https://api.github.com/repos/vitalitychems-dot/GitMesh/git/blobs",
    },
  ]);
  assert.ok(!output.includes(fakeToken), "GitHub token leaked in timeout output");
  assert.ok(!output.includes(privateSource), "source content leaked in timeout output");
  assert.ok(!output.includes(privateFetchError), "raw fetch error leaked in timeout output");
});
