import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import test from "node:test";

const SOURCE_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const REPOSITORY_ROOT = path.resolve(SOURCE_DIR, "../..");
const DEFAULT_BRANCH = process.env.GITMESH_REPOSITORY_DEFAULT_BRANCH || "main";
const MOCK_BASE_TREE_SHA = "b".repeat(40);

test("README source-sync badge targets the tracked workflow on the default branch", () => {
  if (process.env.GITHUB_ACTIONS === "true") {
    assert.ok(
      process.env.GITMESH_REPOSITORY_DEFAULT_BRANCH,
      "workflow must provide the repository's current default branch",
    );
  }
  const readme = fs.readFileSync(path.join(REPOSITORY_ROOT, "README.md"), "utf8");
  const badges = [...readme.matchAll(/^\[!\[[^\]]+\]\(([^)]+)\)\]\(([^)]+)\)$/gm)];
  assert.equal(badges.length, 1, "README must have exactly one status badge");

  const [, imageHref, linkHref] = badges[0];
  const imageUrl = new URL(imageHref);
  const linkUrl = new URL(linkHref);
  for (const url of [imageUrl, linkUrl]) {
    assert.equal(url.protocol, "https:");
    assert.equal(url.hostname, "github.com");
    assert.equal(url.username, "", "badge URLs must not contain embedded credentials");
    assert.equal(url.password, "", "badge URLs must not contain embedded credentials");
  }

  const basePath = "/vitalitychems-dot/GitMesh/actions/workflows/";
  const imageMatch = imageUrl.pathname.match(
    /^\/vitalitychems-dot\/GitMesh\/actions\/workflows\/([A-Za-z0-9._-]+\.ya?ml)\/badge\.svg$/,
  );
  const linkMatch = linkUrl.pathname.match(
    /^\/vitalitychems-dot\/GitMesh\/actions\/workflows\/([A-Za-z0-9._-]+\.ya?ml)$/,
  );
  assert.ok(imageMatch, "badge image must use a GitMesh Actions workflow URL");
  assert.ok(linkMatch, "badge link must open a GitMesh Actions workflow");
  assert.equal(imageMatch[1], linkMatch[1], "badge image and link must name the same workflow");
  assert.ok(imageUrl.pathname.startsWith(basePath));
  assert.ok(linkUrl.pathname.startsWith(basePath));

  assert.deepEqual(
    [...imageUrl.searchParams.entries()],
    [["branch", DEFAULT_BRANCH]],
    "badge image must target the default branch without extra query parameters",
  );
  assert.deepEqual(
    [...linkUrl.searchParams.entries()],
    [["query", `branch:${DEFAULT_BRANCH}`]],
    "badge link must target the default branch without extra query parameters",
  );

  const workflowPath = path.posix.join(".github", "workflows", imageMatch[1]);
  const tracked = spawnSync("git", ["ls-files", "--error-unmatch", "--", workflowPath], {
    cwd: REPOSITORY_ROOT,
    encoding: "utf8",
    timeout: 5000,
    windowsHide: true,
  });
  assert.equal(tracked.status, 0, `README badge workflow must be tracked: ${workflowPath}`);
  assert.equal(tracked.stdout.trim(), workflowPath);
});

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

function runSyncWithSyntaxResult(
  t,
  mode,
  { checkOnly = false, tokenPresent = !checkOnly, tokenValue, extraArgs = [] } = {},
) {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "gitmesh-sync-syntax-"));
  t.after(() => fs.rmSync(tempDir, { recursive: true, force: true }));

  const scriptPath = path.join(tempDir, "run-sync.mjs");
  const preloadPath = path.join(tempDir, "simulate-syntax-result.mjs");
  const syntaxMarker = path.join(tempDir, "syntax-check-invoked");
  const sourceReadMarker = path.join(tempDir, "source-read-invoked");
  const metadataMarker = path.join(tempDir, "metadata-lookup-invoked");
  const syntaxInvocationLog = path.join(tempDir, "syntax-invocations.jsonl");
  const fetchMarker = path.join(tempDir, "github-fetch-invoked");
  const privateSource = "PRIVATE_SYNTAX_SOURCE_SENTINEL";
  const privateNodeOutput = "PRIVATE_NODE_DIAGNOSTIC_SENTINEL";
  const childOutputSentinel = "PRIVATE_HUNG_CHILD_OUTPUT_SENTINEL";
  const hungChildPath = path.join(tempDir, "hung-syntax-child.mjs");
  const hungChildStarted = path.join(tempDir, "hung-child-started");
  const fakeToken = tokenValue ?? "test-only-not-a-real-token";

  if (mode === "hung-child") {
    fs.writeFileSync(
      hungChildPath,
      [
        'import fs from "node:fs";',
        'fs.writeFileSync(process.env.GITMESH_TEST_HUNG_CHILD_STARTED, "started");',
        `process.stderr.write("${childOutputSentinel}");`,
        "setInterval(() => {}, 1000);",
      ].join("\n"),
    );
  }

  for (const name of ["README.md", "sync-public-source.mjs", "gitmesh-ultimate-core.mjs"]) {
    fs.copyFileSync(path.join(SOURCE_DIR, name), path.join(tempDir, name));
  }
  fs.copyFileSync(path.join(SOURCE_DIR, "sync-public-source.mjs"), scriptPath);
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
  } else if (mode === "eacces-open" || mode === "eacces-metadata") {
    fs.appendFileSync(sourcePath, `\n// ${privateSource}\n`);
    fs.appendFileSync(scriptPath, `\n// ${privateSource}\n`);
  } else if (mode === "multiple-syntax") {
    fs.writeFileSync(
      sourcePath,
      `// ${privateSource}\nexport const FIRST_PRIVATE_SYNTAX_SENTINEL = ;\n`,
    );
    fs.writeFileSync(
      path.join(tempDir, "sync-public-source.mjs"),
      "\nexport const SECOND_PRIVATE_SYNTAX_SENTINEL = ;\n",
    );
  } else if (mode === "later-syntax") {
    fs.writeFileSync(
      path.join(tempDir, "sync-public-source.mjs"),
      `export const ${privateSource}_LATER = ;\n`,
    );
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
      'import { fileURLToPath } from "node:url";',
      "const originalSpawnSync = childProcess.spawnSync.bind(childProcess);",
      "const originalReadFileSync = fs.readFileSync.bind(fs);",
      "const originalLstatSync = fs.lstatSync.bind(fs);",
      "let sourceChangedDuringRead = false;",
      "fs.lstatSync = (file, ...args) => {",
      '  if (process.env.GITMESH_TEST_SYNTAX_FAILURE_MODE === "eacces-metadata" && typeof file === "string" && file.endsWith("sync-public-source.mjs")) {',
      '    fs.writeFileSync(process.env.GITMESH_TEST_METADATA_MARKER, "invoked");',
      `    const error = new Error("EACCES: permission denied ${privateNodeOutput} ${privateSource}");`,
      '    error.code = "EACCES";',
      "    throw error;",
      "  }",
      "  return originalLstatSync(file, ...args);",
      "};",
      "fs.readFileSync = (file, ...args) => {",
      '  if (typeof file === "string" && ["README.md", "gitmesh-ultimate-core.mjs", "sync-public-source.mjs"].some((name) => file === fileURLToPath(new URL(name, import.meta.url)))) {',
      '    fs.writeFileSync(process.env.GITMESH_TEST_SOURCE_READ_MARKER, "invoked");',
      "  }",
      '  if (process.env.GITMESH_TEST_SYNTAX_FAILURE_MODE === "eacces-open" && typeof file === "string" && file.endsWith("sync-public-source.mjs")) {',
      `    const error = new Error("EACCES: permission denied ${privateNodeOutput}");`,
      '    error.code = "EACCES";',
      "    throw error;",
      "  }",
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
      "    const invocation = {",
      "      command,",
      "      args,",
      "      env: options?.env ?? {},",
      '      inputHasSourceSentinel: Buffer.from(options?.input ?? "").includes(Buffer.from(process.env.GITMESH_TEST_SOURCE_SENTINEL)),',
      "    };",
      '    if (mode === "hung-child") {',
      "      const child = originalSpawnSync(process.execPath, [process.env.GITMESH_TEST_HUNG_CHILD_PATH], {",
      '        env: { PATH: process.env.PATH ?? "", GITMESH_TEST_HUNG_CHILD_STARTED: process.env.GITMESH_TEST_HUNG_CHILD_STARTED },',
      "        encoding: \"utf8\", timeout: options?.timeout, maxBuffer: options?.maxBuffer,",
      "      });",
      '      const childOutput = `${child.stdout ?? ""}${child.stderr ?? ""}`;',
      "      fs.appendFileSync(process.env.GITMESH_TEST_SYNTAX_INVOCATION_LOG, JSON.stringify({",
      "        ...invocation, pid: child.pid, status: child.status, error: child.error?.code ?? null, signal: child.signal,",
      `        childOutputContainsSentinel: childOutput.includes("${childOutputSentinel}"),`,
      '      }) + "\\n");',
      "      return child;",
      "    }",
      '    if (mode === "unrecognized-diagnostic") {',
      "      fs.appendFileSync(process.env.GITMESH_TEST_SYNTAX_INVOCATION_LOG, JSON.stringify({",
      "        ...invocation, status: 1, error: null, unrecognizedDiagnostic: true,",
      '      }) + "\\n");',
      "      return {",
      "        error: undefined, status: 1, signal: null,",
      '        stdout: "", stderr: "Unrecognized parser diagnostic PRIVATE_NODE_DIAGNOSTIC_SENTINEL PRIVATE_SYNTAX_SOURCE_SENTINEL",',
      "        pid: 123, output: [],",
      "      };",
      "    }",
      '    if (mode === "syntax" || mode === "success" || mode === "eacces-open" || mode === "eacces-metadata" || mode === "multiple-syntax" || mode === "later-syntax") {',
      "      const result = originalSpawnSync(command, args, options);",
      "      fs.appendFileSync(process.env.GITMESH_TEST_SYNTAX_INVOCATION_LOG, JSON.stringify({",
      "        ...invocation, status: result.status, error: result.error?.code ?? null,",
      '      }) + "\\n");',
      "      return result;",
      "    }",
      '    fs.appendFileSync(process.env.GITMESH_TEST_SYNTAX_INVOCATION_LOG, JSON.stringify(invocation) + "\\n");',
      '    const errorCode = mode === "timeout" ? "ETIMEDOUT" : mode === "spawn-failure" ? "ENOENT" : "ENOBUFS";',
      "    return {",
      `      error: mode === "interrupted" ? undefined : Object.assign(new Error(mode === "spawn-failure" ? "spawn ENOENT ${privateNodeOutput} ${privateSource}" : "${privateNodeOutput}"), { code: errorCode }),`,
      "      status: null,",
      '      signal: mode === "interrupted" ? "SIGTERM" : null,',
      `      stdout: Buffer.from(mode === "spawn-failure" ? "${privateNodeOutput} ${privateSource}" : "${privateNodeOutput}"),`,
      `      stderr: Buffer.from(mode === "spawn-failure" ? "raw startup diagnostic ${privateNodeOutput} ${privateSource}" : "${privateNodeOutput}"),`,
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
    GITMESH_TEST_SOURCE_READ_MARKER: sourceReadMarker,
    GITMESH_TEST_METADATA_MARKER: metadataMarker,
    GITMESH_TEST_SYNTAX_INVOCATION_LOG: syntaxInvocationLog,
    GITMESH_TEST_FETCH_MARKER: fetchMarker,
    GITMESH_TEST_SYNTAX_FAILURE_MODE: mode,
    GITMESH_TEST_SOURCE_SENTINEL: privateSource,
    GITMESH_TEST_HUNG_CHILD_OUTPUT: childOutputSentinel,
    NODE_OPTIONS: `--import=${pathToFileURL(preloadPath).href}`,
  };
  if (mode === "hung-child") {
    env.GITMESH_TEST_HUNG_CHILD_PATH = hungChildPath;
    env.GITMESH_TEST_HUNG_CHILD_STARTED = hungChildStarted;
  }
  if (tokenPresent) env.GITHUB_TOKEN = fakeToken;
  const result = spawnSync(process.execPath, [
    scriptPath,
    ...(checkOnly ? ["--check-syntax"] : []),
    ...extraArgs,
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
    sourceReadMarker,
    metadataMarker,
    syntaxInvocationLog,
    fetchMarker,
    scriptPath,
    privateSource,
    fakeToken,
    tokenPresent,
    privateTexts: [
      privateSource,
      privateNodeOutput,
      childOutputSentinel,
      fakeToken,
      "FIRST_PRIVATE_SYNTAX_SENTINEL",
      "SECOND_PRIVATE_SYNTAX_SENTINEL",
      "ENOBUFS",
      "ENOENT",
      "spawn ENOENT",
      "raw startup diagnostic",
      "[stdin]",
      "SyntaxError",
      "EACCES",
      "permission denied",
    ],
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

for (const mode of ["success", "syntax", "eacces-open"]) {
  test(`normal sync without a GitHub token stops before reading or checking ${mode} sources`, (t) => {
    const fixture = runSyncWithSyntaxResult(t, mode, { tokenPresent: false });
    assert.equal(fixture.result.error, undefined);
    assert.equal(fixture.result.status, 1, fixture.output);
    assert.equal(fixture.output.trim(), "Set GITHUB_TOKEN through Replit Secrets before running source sync.");
    assert.equal(fs.existsSync(fixture.sourceReadMarker), false, "missing credentials must stop before opening allowlisted source files");
    assert.equal(fs.existsSync(fixture.syntaxMarker), false, "missing credentials must stop before syntax validation");
    assert.equal(fs.existsSync(fixture.fetchMarker), false, "missing credentials must never reach fetch");
    for (const text of fixture.privateTexts) assert.ok(!fixture.output.includes(text), "setup error leaked private diagnostic material");
  });
}

test("oversized GitHub token is rejected before fetch and never printed", (t) => {
  const sentinel = `PRIVATE_OVERSIZED_TOKEN_SENTINEL_${"X".repeat(4097)}`;
  const fixture = runSyncWithSyntaxResult(t, "success", { tokenPresent: true, tokenValue: sentinel });
  assert.notEqual(fixture.result.status, 0);
  assert.equal(fixture.output.trim(), "Set GITHUB_TOKEN through Replit Secrets before running source sync.");
  assert.equal(fs.existsSync(fixture.fetchMarker), false, "oversized token reached fetch");
  assert.ok(!fixture.output.includes(sentinel), "oversized token was printed");
  for (const text of fixture.privateTexts) assert.ok(!fixture.output.includes(text), "private diagnostic data leaked");
});

test("GitHub token containing CR/LF is rejected before fetch and never printed", (t) => {
  const sentinel = "PRIVATE_CRLF_TOKEN_SENTINEL\r\nSECOND_PRIVATE_TOKEN_LINE";
  const fixture = runSyncWithSyntaxResult(t, "success", { tokenPresent: true, tokenValue: sentinel });
  assert.notEqual(fixture.result.status, 0);
  assert.equal(fixture.output.trim(), "Set GITHUB_TOKEN through Replit Secrets before running source sync.");
  assert.equal(fs.existsSync(fixture.fetchMarker), false, "CR/LF token reached fetch");
  assert.ok(!fixture.output.includes(sentinel), "CR/LF token was printed");
  for (const text of fixture.privateTexts) assert.ok(!fixture.output.includes(text), "private diagnostic data leaked");
});

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

function runSyncWithBranchSha(
  t,
  branchSha,
  mode = "success",
  { remoteHeadPath: sharedRemoteHeadPath } = {},
) {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "gitmesh-sync-branch-sha-"));
  t.after(() => fs.rmSync(tempDir, { recursive: true, force: true }));

  const scriptPath = path.join(tempDir, "sync-public-source.mjs");
  const preloadPath = path.join(tempDir, "mock-github-branch-sha.mjs");
  const requestLog = path.join(tempDir, "github-requests.json");
  const syntaxInvocationLog = path.join(tempDir, "syntax-invocations.jsonl");
  const privateSymlinkReadLog = path.join(tempDir, "private-symlink-reads.log");
  const remoteHeadPath = sharedRemoteHeadPath ?? path.join(tempDir, "mock-remote-head.txt");
  const fakeToken = "test-only-not-a-real-token";
  const privateSource = "PRIVATE_BRANCH_SHA_SOURCE_SENTINEL";
  const privateResponseBody = "PRIVATE_BASE_COMMIT_RESPONSE_SENTINEL";
  const privateNetworkError = "PRIVATE_BRANCH_NETWORK_ERROR_SENTINEL";
  const privateMalformedBlobSha = "PRIVATE_MALFORMED_BLOB_SHA_SENTINEL";
  const privateUppercaseBlobSha = "A".repeat(40);
  const privateRetryAfterHeader = "PRIVATE_RETRY_AFTER_HEADER_SENTINEL";
  const privateInvalidTreeSha = "PRIVATE_INVALID_TREE_SHA_SENTINEL";
  const privateInvalidCommitSha = "PRIVATE_INVALID_COMMIT_SHA_SENTINEL";
  const advancedHeadSha = "ffffffffffffffffffffffffffffffffffffffff";
  const retryAfterHeader =
    mode === "blob-http-429"
      ? "120"
      : mode === "blob-http-429-negative"
        ? "-5"
        : mode === "blob-http-429-over-limit"
          ? "99999"
          : privateRetryAfterHeader;
  const privateSymlinkTargetContents = "PRIVATE_SYMLINK_TARGET_CONTENT_SENTINEL";
  let privateSymlinkTargetDirectory;
  let privateSymlinkTargetPath;
  if (mode === "readme-symlink") {
    privateSymlinkTargetDirectory = fs.mkdtempSync(
      path.join(os.tmpdir(), "gitmesh-sync-private-target-"),
    );
    t.after(() => fs.rmSync(privateSymlinkTargetDirectory, { recursive: true, force: true }));
    privateSymlinkTargetPath = path.join(
      privateSymlinkTargetDirectory,
      "PRIVATE_SYMLINK_TARGET_PATH_SENTINEL.txt",
    );
    fs.writeFileSync(privateSymlinkTargetPath, privateSymlinkTargetContents);
  }
  const changedSourceDuringRequest =
    "// CHANGED_AFTER_SYNC_SNAPSHOT_SENTINEL\nexport const changedAfterSnapshot = true;\n";
  const mutableSourcePath = path.join(tempDir, "gitmesh-ultimate-core.mjs");

  for (const name of ["README.md", "sync-public-source.mjs", "gitmesh-ultimate-core.mjs"]) {
    fs.copyFileSync(path.join(SOURCE_DIR, name), path.join(tempDir, name));
  }
  fs.appendFileSync(path.join(tempDir, "README.md"), `\n${privateSource}\n`);
  if (mode === "readme-invalid-js") {
    fs.appendFileSync(
      path.join(tempDir, "README.md"),
      `\nexport const ${privateSource} = ;\n`,
    );
  }
  if (mode === "readme-invalid-utf8") {
    fs.appendFileSync(path.join(tempDir, "README.md"), Buffer.from([0xc3, 0x28]));
  }
  if (!sharedRemoteHeadPath) fs.writeFileSync(remoteHeadPath, branchSha);
  fs.writeFileSync(requestLog, "[]");
  fs.writeFileSync(privateSymlinkReadLog, "");
  const expectedSources = {
    "projects/local-vault/gitmesh-ultimate-core.mjs": fs.readFileSync(
      path.join(tempDir, "gitmesh-ultimate-core.mjs"),
      "utf8",
    ),
    "projects/local-vault/README.md": fs.readFileSync(
      path.join(tempDir, "README.md"),
      "utf8",
    ),
    "projects/local-vault/sync-public-source.mjs": fs.readFileSync(
      path.join(tempDir, "sync-public-source.mjs"),
      "utf8",
    ),
  };
  if (mode === "readme-symlink") {
    const readmePath = path.join(tempDir, "README.md");
    fs.unlinkSync(readmePath);
    fs.symlinkSync(privateSymlinkTargetPath, readmePath);
  }
  fs.writeFileSync(
    preloadPath,
    [
      'import fs from "node:fs";',
      'import childProcess from "node:child_process";',
      'import { createHash } from "node:crypto";',
      'import { syncBuiltinESMExports } from "node:module";',
      "const originalReadFileSync = fs.readFileSync.bind(fs);",
      "fs.readFileSync = (file, ...args) => {",
      "  if (process.env.GITMESH_TEST_PRIVATE_TARGET_PATH && String(file) === process.env.GITMESH_TEST_PRIVATE_TARGET_PATH) {",
      '    fs.appendFileSync(process.env.GITMESH_TEST_PRIVATE_TARGET_READ_LOG, "read\\n");',
      "  }",
      "  return originalReadFileSync(file, ...args);",
      "};",
      "const originalSpawnSync = childProcess.spawnSync.bind(childProcess);",
      "childProcess.spawnSync = (command, args, options) => {",
      '  if (command === process.execPath && Array.isArray(args) && args.includes("--check")) {',
      "    const result = originalSpawnSync(command, args, options);",
      "    fs.appendFileSync(process.env.GITMESH_TEST_SYNTAX_LOG, JSON.stringify({",
      "      command, args, status: result.status, error: result.error?.code ?? null,",
      '    }) + "\\n");',
      "    return result;",
      "  }",
      "  return originalSpawnSync(command, args, options);",
      "};",
      "syncBuiltinESMExports();",
      'const response = (value) => ({ ok: true, json: async () => value });',
      "const requests = [];",
      'const branchSha = fs.readFileSync(process.env.GITMESH_TEST_REMOTE_HEAD, "utf8");',
      'const baseTreeSha = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";',
      'const currentTreeEntries = [',
      '  ["projects/local-vault/gitmesh-ultimate-core.mjs", "gitmesh-ultimate-core.mjs"],',
      '  ["projects/local-vault/README.md", "README.md"],',
      '  ["projects/local-vault/sync-public-source.mjs", "sync-public-source.mjs"],',
      '].map(([path, filename]) => {',
      '  const content = fs.readFileSync(filename);',
      '  const sha = createHash("sha1").update(`blob ${content.length}\\0`).update(content).digest("hex");',
      '  return { path, mode: "100644", type: "blob", sha };',
      '});',
      'const isCurrentTreeMode = process.env.GITMESH_TEST_MODE === "source-current" || process.env.GITMESH_TEST_MODE === "tree-current-branch-advanced";',
      'const matchingRemoteTree = isCurrentTreeMode',
      '  ? [...currentTreeEntries, { path: "other/ignored.txt", mode: "100644", type: "blob", sha: "2222222222222222222222222222222222222222" }]',
      '  : process.env.GITMESH_TEST_MODE === "one-source-diff"',
      '    ? currentTreeEntries.map((entry, index) => index === 0 ? { ...entry, sha: "9999999999999999999999999999999999999999" } : entry)',
      '    : [];',
      'const newTreeSha = process.env.GITMESH_TEST_MODE === "invalid-tree-sha" ? process.env.GITMESH_TEST_INVALID_TREE_SHA : "cccccccccccccccccccccccccccccccccccccccc";',
      'const commitSha = process.env.GITMESH_TEST_MODE === "retry-after-ref-timeout" ? "2222222222222222222222222222222222222222" : process.env.GITMESH_TEST_MODE === "invalid-commit-sha" ? process.env.GITMESH_TEST_INVALID_COMMIT_SHA : "dddddddddddddddddddddddddddddddddddddddd";',
      'const blobShas = [',
      '  "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",',
      '  "ffffffffffffffffffffffffffffffffffffffff",',
      '  "1111111111111111111111111111111111111111",',
      "];",
      "let blobIndex = 0;",
      "let branchReadCount = 0;",
      "globalThis.fetch = async (url, options = {}) => {",
      '  const method = options.method ?? "GET";',
      "  const request = { method, url };",
      '  if (method === "POST" && url.endsWith("/git/blobs")) {',
      "    request.blob = JSON.parse(options.body);",
      "  }",
      '  if (method === "POST" && url.endsWith("/git/trees")) {',
      "    const treeBody = JSON.parse(options.body);",
      "    request.treePaths = treeBody.tree.map((entry) => entry.path);",
      "    request.treeEntries = treeBody.tree.map(({ path, mode, type, sha }) => ({ path, mode, type, sha }));",
      "  }",
      '  if (method === "POST" && url.endsWith("/git/commits")) {',
      "    request.commit = JSON.parse(options.body);",
      "  }",
      '  if (method === "PATCH" && url.endsWith("/git/refs/heads/main")) {',
      "    request.refUpdate = JSON.parse(options.body);",
      "  }",
      "  requests.push(request);",
      "  fs.writeFileSync(process.env.GITMESH_TEST_REQUEST_LOG, JSON.stringify(requests));",
      '  if (method === "GET" && url.endsWith("/git/ref/heads/main")) {',
      "    branchReadCount += 1;",
      '    if (process.env.GITMESH_TEST_MODE === "change-source-after-read") {',
      "      fs.writeFileSync(process.env.GITMESH_TEST_MUTABLE_SOURCE_PATH, process.env.GITMESH_TEST_CHANGED_SOURCE);",
      "    }",
      '    if (process.env.GITMESH_TEST_MODE === "branch-http-503") {',
      "      return {",
      "        ok: false,",
      "        status: 503,",
      "        statusText: process.env.GITMESH_TEST_RESPONSE_SENTINEL,",
      "        json: async () => ({",
      "          message: process.env.GITMESH_TEST_RESPONSE_SENTINEL,",
      "          source: process.env.GITMESH_TEST_PRIVATE_SOURCE,",
      "          credential: process.env.GITHUB_TOKEN,",
      "        }),",
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
      '    if (process.env.GITMESH_TEST_MODE === "tree-current-branch-advanced" && branchReadCount > 1) {',
      '      return response({ object: { sha: process.env.GITMESH_TEST_ADVANCED_HEAD } });',
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
      '  if (method === "GET" && url.endsWith(`/git/trees/${baseTreeSha}?recursive=1`)) {',
      '    if (process.env.GITMESH_TEST_MODE === "tree-read-invalid-json") {',
      "      return {",
      "        ok: true,",
      "        json: async () => { throw new Error(process.env.GITMESH_TEST_RESPONSE_SENTINEL); },",
      "      };",
      "    }",
      '    const truncated = process.env.GITMESH_TEST_MODE === "tree-truncated";',
      "    return response({ truncated, tree: matchingRemoteTree });",
      "  }",
      '  if (method === "POST" && url.endsWith("/git/blobs")) {',
      '    if (process.env.GITMESH_TEST_MODE.startsWith("blob-http-429") && blobIndex === 1) {',
      "      return {",
      "        ok: false,",
      "        status: 429,",
      "        statusText: process.env.GITMESH_TEST_RESPONSE_SENTINEL,",
      "        headers: {",
      '          get: (name) => name.toLowerCase() === "retry-after" ? process.env.GITMESH_TEST_RETRY_AFTER : null,',
      "        },",
      "        json: async () => ({",
      "          message: process.env.GITMESH_TEST_RESPONSE_SENTINEL,",
      "          source: process.env.GITMESH_TEST_PRIVATE_SOURCE,",
      "          credential: process.env.GITHUB_TOKEN,",
      "        }),",
      "      };",
      "    }",
      '    if ((process.env.GITMESH_TEST_MODE === "blob-http-401" || process.env.GITMESH_TEST_MODE === "blob-http-403") && blobIndex === 1) {',
      "      return {",
      "        ok: false,",
      '        status: process.env.GITMESH_TEST_MODE === "blob-http-401" ? 401 : 403,',
      "        statusText: process.env.GITMESH_TEST_RESPONSE_SENTINEL,",
      "        json: async () => ({",
      "          message: process.env.GITMESH_TEST_RESPONSE_SENTINEL,",
      "          source: process.env.GITMESH_TEST_PRIVATE_SOURCE,",
      "          credential: process.env.GITHUB_TOKEN,",
      "        }),",
      "      };",
      "    }",
      '    if (process.env.GITMESH_TEST_MODE === "later-blob-timeout" && blobIndex === 1) {',
      "      const error = new Error(process.env.GITMESH_TEST_NETWORK_SENTINEL);",
      '      error.name = "TimeoutError";',
      "      throw error;",
      "    }",
      '    const malformedBlobMode = process.env.GITMESH_TEST_MODE.startsWith("malformed-blob-sha-");',
      '    const uppercaseBlobMode = process.env.GITMESH_TEST_MODE.startsWith("uppercase-blob-sha-");',
      "    if (malformedBlobMode || uppercaseBlobMode) {",
      '      const badBlobIndex = Number(process.env.GITMESH_TEST_MODE.split("-").at(-1));',
      "      if (blobIndex === badBlobIndex) {",
      "        const sha = uppercaseBlobMode",
      "          ? process.env.GITMESH_TEST_UPPERCASE_BLOB_SHA",
      "          : process.env.GITMESH_TEST_MALFORMED_BLOB_SHA;",
      "        return response({ sha });",
      "      }",
      "    }",
      "    return response({ sha: blobShas[blobIndex++] });",
      "  }",
      '  if (method === "POST" && url.endsWith("/git/trees")) {',
      '    if (process.env.GITMESH_TEST_MODE === "tree-invalid-json") {',
      "      return {",
      "        ok: true,",
      "        json: async () => { throw new Error(process.env.GITMESH_TEST_RESPONSE_SENTINEL); },",
      "      };",
      "    }",
      "    return response({ sha: newTreeSha });",
      "  }",
      '  if (method === "POST" && url.endsWith("/git/commits")) {',
      '    if (process.env.GITMESH_TEST_MODE === "commit-invalid-json") {',
      "      return {",
      "        ok: true,",
      "        json: async () => { throw new Error(process.env.GITMESH_TEST_RESPONSE_SENTINEL); },",
      "      };",
      "    }",
      "    return response({ sha: commitSha });",
      "  }",
      '  if (method === "PATCH" && url.endsWith("/git/refs/heads/main")) {',
      "    const refUpdate = JSON.parse(options.body);",
      '    if (process.env.GITMESH_TEST_MODE === "branch-advance-before-ref-update") {',
      "      fs.writeFileSync(process.env.GITMESH_TEST_REMOTE_HEAD, process.env.GITMESH_TEST_ADVANCED_HEAD);",
      "      return {",
      "        ok: false,",
      "        status: 422,",
      "        statusText: process.env.GITMESH_TEST_RESPONSE_SENTINEL,",
      "        json: async () => { throw new Error(process.env.GITMESH_TEST_RESPONSE_SENTINEL); },",
      "      };",
      "    }",
      "    fs.writeFileSync(process.env.GITMESH_TEST_REMOTE_HEAD, refUpdate.sha);",
      '    if (process.env.GITMESH_TEST_MODE === "ref-update-timeout-after-accept") {',
      "      const error = new Error(process.env.GITMESH_TEST_NETWORK_SENTINEL);",
      '      error.name = "TimeoutError";',
      "      throw error;",
      "    }",
      "    return response({ object: { sha: refUpdate.sha } });",
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
      GITMESH_TEST_ADVANCED_HEAD: advancedHeadSha,
      GITMESH_TEST_MODE: mode,
      GITMESH_TEST_RESPONSE_SENTINEL: privateResponseBody,
      GITMESH_TEST_PRIVATE_SOURCE: privateSource,
      GITMESH_TEST_NETWORK_SENTINEL: privateNetworkError,
      GITMESH_TEST_MALFORMED_BLOB_SHA: privateMalformedBlobSha,
      GITMESH_TEST_UPPERCASE_BLOB_SHA: privateUppercaseBlobSha,
      GITMESH_TEST_RETRY_AFTER: retryAfterHeader,
      GITMESH_TEST_INVALID_TREE_SHA: privateInvalidTreeSha,
      GITMESH_TEST_INVALID_COMMIT_SHA: privateInvalidCommitSha,
      GITMESH_TEST_REQUEST_LOG: requestLog,
      GITMESH_TEST_SYNTAX_LOG: syntaxInvocationLog,
      GITMESH_TEST_MUTABLE_SOURCE_PATH: mutableSourcePath,
      GITMESH_TEST_CHANGED_SOURCE: changedSourceDuringRequest,
      GITMESH_TEST_REMOTE_HEAD: remoteHeadPath,
      GITMESH_TEST_PRIVATE_TARGET_PATH: privateSymlinkTargetPath ?? "",
      GITMESH_TEST_PRIVATE_TARGET_READ_LOG: privateSymlinkReadLog,
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
    privateMalformedBlobSha,
    privateUppercaseBlobSha,
    privateRetryAfterHeader,
    retryAfterHeader,
    privateInvalidTreeSha,
    privateInvalidCommitSha,
    advancedHeadSha,
    privateSymlinkTargetPath,
    privateSymlinkTargetContents,
    privateSymlinkReadLog,
    syntaxInvocationLog,
    expectedSources,
    changedSourceDuringRequest,
    localCoreAfterSync: fs.readFileSync(mutableSourcePath, "utf8"),
    remoteHeadPath,
    remoteHeadAfterSync: fs.readFileSync(remoteHeadPath, "utf8"),
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

for (const [shaKind, shaValue] of [
  ["malformed", "privateMalformedBlobSha"],
  ["uppercase", "privateUppercaseBlobSha"],
]) {
  for (const blobIndex of [0, 1, 2]) {
    test(`normal sync stops before tree creation when blob ${blobIndex + 1} has a ${shaKind} SHA`, (t) => {
      const branchSha = "a".repeat(40);
      const mode = `${shaKind}-blob-sha-${blobIndex}`;
      const fixture = runSyncWithBranchSha(t, branchSha, mode);
      const apiRoot = "https://api.github.com/repos/vitalitychems-dot/GitMesh";
      const expectedRequests = [
        ["GET", `${apiRoot}/git/ref/heads/main`],
        ["GET", `${apiRoot}/git/commits/${branchSha}`],
        ["GET", `${apiRoot}/git/trees/${MOCK_BASE_TREE_SHA}?recursive=1`],
        ...Array.from({ length: blobIndex + 1 }, () => ["POST", `${apiRoot}/git/blobs`]),
      ];

      assert.equal(fixture.result.status, 1, fixture.output);
      assert.equal(fixture.output.trim(), "GitHub returned an invalid blob SHA; sync stopped.");
      assert.deepEqual(
        fixture.requests.map(({ method, url }) => [method, url]),
        expectedRequests,
      );
      assert.ok(!fixture.output.includes(fixture.fakeToken), "GitHub token leaked in output");
      assert.ok(!fixture.output.includes(fixture.privateSource), "source content leaked in output");
      assert.ok(
        !fixture.output.includes(fixture[shaValue]),
        `${shaKind} blob SHA leaked in output`,
      );
      assert.equal(
        fixture.remoteHeadAfterSync,
        branchSha,
        `branch was updated after the ${shaKind} blob response`,
      );
    });
  }
}

for (const [mode, label, shaField, expectedRequests] of [
  [
    "invalid-tree-sha",
    "tree",
    "privateInvalidTreeSha",
    [
      ["GET", "/git/ref/heads/main"],
      ["GET", "/git/commits/BRANCH_SHA"],
      ["GET", `/git/trees/${MOCK_BASE_TREE_SHA}?recursive=1`],
      ["POST", "/git/blobs"],
      ["POST", "/git/blobs"],
      ["POST", "/git/blobs"],
      ["POST", "/git/trees"],
    ],
  ],
  [
    "invalid-commit-sha",
    "commit",
    "privateInvalidCommitSha",
    [
      ["GET", "/git/ref/heads/main"],
      ["GET", "/git/commits/BRANCH_SHA"],
      ["GET", `/git/trees/${MOCK_BASE_TREE_SHA}?recursive=1`],
      ["POST", "/git/blobs"],
      ["POST", "/git/blobs"],
      ["POST", "/git/blobs"],
      ["POST", "/git/trees"],
      ["POST", "/git/commits"],
    ],
  ],
]) {
  test(`normal sync stops before later writes when GitHub returns an invalid ${label} SHA`, (t) => {
    const branchSha = "a".repeat(40);
    const fixture = runSyncWithBranchSha(t, branchSha, mode);
    const apiRoot = "https://api.github.com/repos/vitalitychems-dot/GitMesh";
    const expectedMessage = `GitHub returned an invalid ${label} SHA; sync stopped.`;

    assert.equal(fixture.result.status, 1, fixture.output);
    assert.equal(fixture.output.trim(), expectedMessage);
    assert.deepEqual(
      fixture.requests.map(({ method, url }) => [
        method,
        url.replace(apiRoot, "").replace(branchSha, "BRANCH_SHA"),
      ]),
      expectedRequests,
    );
    assert.ok(!fixture.output.includes(fixture.fakeToken), "GitHub token leaked in output");
    assert.ok(!fixture.output.includes(fixture.privateSource), "source content leaked in output");
    assert.ok(!fixture.output.includes(fixture[shaField]), `${label} SHA leaked in output`);
    assert.ok(!fixture.output.includes(fixture.privateResponseBody), "response details leaked in output");
    assert.equal(fixture.remoteHeadAfterSync, branchSha, "branch was updated after an invalid response SHA");
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
      ["GET", `${apiRoot}/git/trees/${MOCK_BASE_TREE_SHA}?recursive=1`],
      ["POST", `${apiRoot}/git/blobs`],
      ["POST", `${apiRoot}/git/blobs`],
      ["POST", `${apiRoot}/git/blobs`],
      ["POST", `${apiRoot}/git/trees`],
      ["POST", `${apiRoot}/git/commits`],
      ["PATCH", `${apiRoot}/git/refs/heads/main`],
    ],
  );
  assert.deepEqual(fixture.requests[6].treePaths, [
    "projects/local-vault/gitmesh-ultimate-core.mjs",
    "projects/local-vault/README.md",
    "projects/local-vault/sync-public-source.mjs",
  ]);
  const blobRequests = fixture.requests.filter(({ method, url }) =>
    method === "POST" && url.endsWith("/git/blobs"),
  );
  assert.equal(blobRequests.length, Object.keys(fixture.expectedSources).length);
  Object.entries(fixture.expectedSources).forEach(([targetPath, expectedContent], index) => {
    const blob = blobRequests[Number(index)].blob;
    assert.equal(blob.encoding, "base64", `${targetPath} was not sent as base64`);
    assert.equal(
      Buffer.from(blob.content, "base64").toString("utf8"),
      expectedContent,
      `${targetPath} blob did not match the validated local source`,
    );
  });
  assert.deepEqual(fixture.requests[6].treeEntries, [
    {
      path: "projects/local-vault/gitmesh-ultimate-core.mjs",
      mode: "100644",
      type: "blob",
      sha: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
    },
    {
      path: "projects/local-vault/README.md",
      mode: "100644",
      type: "blob",
      sha: "ffffffffffffffffffffffffffffffffffffffff",
    },
    {
      path: "projects/local-vault/sync-public-source.mjs",
      mode: "100644",
      type: "blob",
      sha: "1111111111111111111111111111111111111111",
    },
  ]);
  const syntaxInvocations = fs
    .readFileSync(fixture.syntaxInvocationLog, "utf8")
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));
  assert.equal(syntaxInvocations.length, 2, "not every JavaScript file was syntax-checked");
  assert.ok(
    syntaxInvocations.every(
      ({ args, status, error }) =>
        args.includes("--input-type=module") &&
        args.includes("--check") &&
        status === 0 &&
        error === null,
    ),
    "one or more JavaScript syntax checks did not pass",
  );
  assert.ok(fixture.requests.every(({ url }) => url.startsWith(`${apiRoot}/`)));
  assert.ok(!fixture.output.includes(fixture.fakeToken), "GitHub token leaked in output");
  assert.ok(!fixture.output.includes(fixture.privateSource), "source content leaked in output");
});

test("source sync creates no GitHub writes when every allowlisted blob is current", (t) => {
  const branchSha = "a".repeat(40);
  const fixture = runSyncWithBranchSha(t, branchSha, "source-current");
  const apiRoot = "https://api.github.com/repos/vitalitychems-dot/GitMesh";

  assert.equal(fixture.result.status, 0, fixture.output);
  assert.equal(
    fixture.output.trim(),
    "Sources are already current in vitalitychems-dot/GitMesh@main; no commit was created.",
  );
  assert.deepEqual(
    fixture.requests.map(({ method, url }) => [method, url]),
    [
      ["GET", `${apiRoot}/git/ref/heads/main`],
      ["GET", `${apiRoot}/git/commits/${branchSha}`],
      ["GET", `${apiRoot}/git/trees/${MOCK_BASE_TREE_SHA}?recursive=1`],
      ["GET", `${apiRoot}/git/ref/heads/main`],
    ],
  );
  assert.ok(fixture.requests.every(({ method }) => method === "GET"));
  assert.equal(fixture.remoteHeadAfterSync, branchSha);
  assert.ok(!fixture.output.includes(fixture.fakeToken), "GitHub token leaked in output");
  assert.ok(!fixture.output.includes(fixture.privateSource), "source content leaked in output");
});

test("source sync retries instead of skipping when main advances during the no-op check", (t) => {
  const branchSha = "a".repeat(40);
  const fixture = runSyncWithBranchSha(t, branchSha, "tree-current-branch-advanced");
  const apiRoot = "https://api.github.com/repos/vitalitychems-dot/GitMesh";

  assert.equal(fixture.result.status, 1, fixture.output);
  assert.equal(
    fixture.output.trim(),
    "GitHub branch changed while checking sources; rerun the sync; sync stopped.",
  );
  assert.deepEqual(
    fixture.requests.map(({ method, url }) => [method, url]),
    [
      ["GET", `${apiRoot}/git/ref/heads/main`],
      ["GET", `${apiRoot}/git/commits/${branchSha}`],
      ["GET", `${apiRoot}/git/trees/${MOCK_BASE_TREE_SHA}?recursive=1`],
      ["GET", `${apiRoot}/git/ref/heads/main`],
    ],
  );
  assert.ok(fixture.requests.every(({ method }) => method === "GET"));
  assert.ok(!fixture.output.includes(fixture.fakeToken), "GitHub token leaked in output");
  assert.ok(!fixture.output.includes(fixture.privateSource), "source content leaked in output");
});

test("source sync writes when one allowlisted blob differs from GitHub", (t) => {
  const branchSha = "a".repeat(40);
  const fixture = runSyncWithBranchSha(t, branchSha, "one-source-diff");
  const apiRoot = "https://api.github.com/repos/vitalitychems-dot/GitMesh";

  assert.equal(fixture.result.status, 0, fixture.output);
  assert.ok(fixture.output.includes("Synced 3 allowlisted source files"));
  assert.deepEqual(
    fixture.requests.map(({ method, url }) => [method, url]),
    [
      ["GET", `${apiRoot}/git/ref/heads/main`],
      ["GET", `${apiRoot}/git/commits/${branchSha}`],
      ["GET", `${apiRoot}/git/trees/${MOCK_BASE_TREE_SHA}?recursive=1`],
      ["POST", `${apiRoot}/git/blobs`],
      ["POST", `${apiRoot}/git/blobs`],
      ["POST", `${apiRoot}/git/blobs`],
      ["POST", `${apiRoot}/git/trees`],
      ["POST", `${apiRoot}/git/commits`],
      ["PATCH", `${apiRoot}/git/refs/heads/main`],
    ],
  );
  assert.equal(fixture.remoteHeadAfterSync, "d".repeat(40));
});

test("source sync stops before writes if GitHub returns a truncated tree", (t) => {
  const branchSha = "a".repeat(40);
  const fixture = runSyncWithBranchSha(t, branchSha, "tree-truncated");
  const apiRoot = "https://api.github.com/repos/vitalitychems-dot/GitMesh";

  assert.equal(fixture.result.status, 1, fixture.output);
  assert.equal(fixture.output.trim(), "GitHub returned an incomplete base tree; sync stopped.");
  assert.deepEqual(
    fixture.requests.map(({ method, url }) => [method, url]),
    [
      ["GET", `${apiRoot}/git/ref/heads/main`],
      ["GET", `${apiRoot}/git/commits/${branchSha}`],
      ["GET", `${apiRoot}/git/trees/${MOCK_BASE_TREE_SHA}?recursive=1`],
    ],
  );
  assert.equal(fixture.remoteHeadAfterSync, branchSha);
});

test("README text that is invalid JavaScript is still synced without syntax-checking it", (t) => {
  const branchSha = "a".repeat(40);
  const fixture = runSyncWithBranchSha(t, branchSha, "readme-invalid-js");
  const apiRoot = "https://api.github.com/repos/vitalitychems-dot/GitMesh";
  const targetPaths = [
    "projects/local-vault/gitmesh-ultimate-core.mjs",
    "projects/local-vault/README.md",
    "projects/local-vault/sync-public-source.mjs",
  ];

  assert.equal(fixture.result.status, 0, fixture.output);
  assert.ok(fixture.output.includes("Synced 3 allowlisted source files"));
  assert.deepEqual(fixture.requests[6].treePaths, targetPaths);
  assert.equal(fixture.requests[6].treeEntries.length, targetPaths.length);
  assert.equal(fixture.requests.length, 9, "sync did not complete entirely through the mocked API");
  assert.ok(fixture.requests.every(({ url }) => url.startsWith(`${apiRoot}/`)));

  const syntaxInvocations = fs
    .readFileSync(fixture.syntaxInvocationLog, "utf8")
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));
  assert.equal(syntaxInvocations.length, 2, "README was incorrectly sent to the syntax checker");
  assert.ok(
    syntaxInvocations.every(({ status, inputHasSourceSentinel }) =>
      status === 0 && !inputHasSourceSentinel,
    ),
    "a JavaScript check failed or received README content",
  );

  const readmeBlobRequest = fixture.requests.filter(
    ({ method, url }) => method === "POST" && url.endsWith("/git/blobs"),
  )[1];
  assert.equal(
    Buffer.from(readmeBlobRequest.blob.content, "base64").toString("utf8"),
    fixture.expectedSources["projects/local-vault/README.md"],
  );
  assert.ok(
    fixture.expectedSources["projects/local-vault/README.md"].includes(
      `export const ${fixture.privateSource} = ;`,
    ),
    "the README fixture did not contain invalid JavaScript text",
  );
});

test("normal sync rejects invalid UTF-8 in README before any GitHub request", (t) => {
  const fixture = runSyncWithBranchSha(t, "a".repeat(40), "readme-invalid-utf8");

  assert.equal(fixture.result.status, 1, fixture.output);
  assert.equal(
    fixture.output.trim(),
    "Source file README.md is not valid UTF-8. " +
      "Save it as valid UTF-8 text and retry the source sync. " +
      "No GitHub requests were made.",
  );
  assert.deepEqual(fixture.requests, []);
  assert.equal(
    fs.readFileSync(fixture.privateSymlinkReadLog, "utf8"),
    "",
    "the sync followed the symlink and read the private target",
  );
  assert.ok(!fixture.output.includes(fixture.privateSource), "source content leaked in output");
  assert.ok(!fixture.output.includes(fixture.fakeToken), "GitHub credential leaked in output");
  assert.ok(!fixture.output.includes(fixture.privateResponseBody), "server details leaked in output");
  assert.ok(!fixture.output.includes("\uFFFD"), "decoded replacement bytes leaked in output");
  assert.ok(!fixture.output.includes("SyntaxError"), "parser diagnostics leaked in output");
});

test("normal sync rejects an allowlisted symlink without reading or exposing its target", (t) => {
  const fixture = runSyncWithBranchSha(t, "a".repeat(40), "readme-symlink");

  assert.equal(fixture.result.status, 1, fixture.output);
  assert.equal(
    fixture.output.trim(),
    "Refusing to sync a symbolic-link source file: README.md. " +
      "Restore it as a regular file; no GitHub requests were made.",
  );
  assert.deepEqual(fixture.requests, []);
  assert.ok(
    !fixture.output.includes(fixture.privateSymlinkTargetPath),
    "private symlink target path leaked in output",
  );
  assert.ok(
    !fixture.output.includes(fixture.privateSymlinkTargetContents),
    "private symlink target contents leaked in output",
  );
  assert.ok(!fixture.output.includes(fixture.privateSource), "source content leaked in output");
  assert.ok(!fixture.output.includes(fixture.fakeToken), "GitHub credential leaked in output");
});

test("sync uploads the initial source snapshot when a local file changes during GitHub requests", (t) => {
  const branchSha = "a".repeat(40);
  const fixture = runSyncWithBranchSha(t, branchSha, "change-source-after-read");
  const apiRoot = "https://api.github.com/repos/vitalitychems-dot/GitMesh";
  const corePath = "projects/local-vault/gitmesh-ultimate-core.mjs";

  assert.equal(fixture.result.status, 0, fixture.output);
  const coreBlobRequest = fixture.requests.find(
    ({ method, url }) => method === "POST" && url.endsWith("/git/blobs"),
  );
  assert.ok(coreBlobRequest, "the mock did not capture the core source blob");
  const uploadedCore = Buffer.from(coreBlobRequest.blob.content, "base64").toString("utf8");
  assert.equal(uploadedCore, fixture.expectedSources[corePath]);
  assert.notEqual(uploadedCore, fixture.changedSourceDuringRequest);
  assert.equal(fixture.localCoreAfterSync, fixture.changedSourceDuringRequest);
  assert.equal(fixture.requests.length, 9, "sync did not complete entirely through the mocked API");
  assert.ok(
    fixture.requests.every(({ url }) => url.startsWith(`${apiRoot}/`)),
    "sync attempted an unexpected network request",
  );
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

test("normal sync stops when the tree response JSON is unreadable", (t) => {
  const branchSha = "a".repeat(40);
  const fixture = runSyncWithBranchSha(t, branchSha, "tree-invalid-json");
  const apiRoot = "https://api.github.com/repos/vitalitychems-dot/GitMesh";

  assert.equal(fixture.result.status, 1, fixture.output);
  assert.equal(
    fixture.output.trim(),
    "GitHub returned an invalid response during POST /git/trees.",
  );
  assert.deepEqual(
    fixture.requests.map(({ method, url }) => [method, url]),
    [
      ["GET", `${apiRoot}/git/ref/heads/main`],
      ["GET", `${apiRoot}/git/commits/${branchSha}`],
      ["GET", `${apiRoot}/git/trees/${MOCK_BASE_TREE_SHA}?recursive=1`],
      ["POST", `${apiRoot}/git/blobs`],
      ["POST", `${apiRoot}/git/blobs`],
      ["POST", `${apiRoot}/git/blobs`],
      ["POST", `${apiRoot}/git/trees`],
    ],
  );
  assert.ok(!fixture.output.includes(fixture.privateResponseBody), "response sentinel leaked in output");
  assert.ok(!fixture.output.includes(fixture.fakeToken), "GitHub token leaked in output");
  assert.ok(!fixture.output.includes(fixture.privateSource), "source content leaked in output");
  assert.equal(
    fixture.remoteHeadAfterSync,
    branchSha,
    "branch was updated after the unreadable tree response",
  );
});

test("normal sync stops when the created-commit response JSON is unreadable", (t) => {
  const branchSha = "a".repeat(40);
  const fixture = runSyncWithBranchSha(t, branchSha, "commit-invalid-json");
  const apiRoot = "https://api.github.com/repos/vitalitychems-dot/GitMesh";

  assert.equal(fixture.result.status, 1, fixture.output);
  assert.equal(
    fixture.output.trim(),
    "GitHub returned an invalid response during POST /git/commits.",
  );
  assert.deepEqual(
    fixture.requests.map(({ method, url }) => [method, url]),
    [
      ["GET", `${apiRoot}/git/ref/heads/main`],
      ["GET", `${apiRoot}/git/commits/${branchSha}`],
      ["GET", `${apiRoot}/git/trees/${MOCK_BASE_TREE_SHA}?recursive=1`],
      ["POST", `${apiRoot}/git/blobs`],
      ["POST", `${apiRoot}/git/blobs`],
      ["POST", `${apiRoot}/git/blobs`],
      ["POST", `${apiRoot}/git/trees`],
      ["POST", `${apiRoot}/git/commits`],
    ],
  );
  assert.ok(!fixture.output.includes(fixture.privateResponseBody), "response sentinel leaked in output");
  assert.ok(!fixture.output.includes(fixture.fakeToken), "GitHub token leaked in output");
  assert.ok(!fixture.output.includes(fixture.privateSource), "source content leaked in output");
  assert.equal(
    fixture.remoteHeadAfterSync,
    branchSha,
    "branch was updated after the unreadable created-commit response",
  );
});

for (const [mode, label, retryGuidance] of [
  [
    "blob-http-429",
    "valid Retry-After value",
    "Wait 120 seconds, then rerun the sync; sync stopped.",
  ],
  [
    "blob-http-429-invalid",
    "untrusted Retry-After value",
    "Check GitHub's rate-limit status, wait for the limit to reset, then rerun the sync; sync stopped.",
  ],
  [
    "blob-http-429-negative",
    "negative Retry-After value",
    "Check GitHub's rate-limit status, wait for the limit to reset, then rerun the sync; sync stopped.",
  ],
  [
    "blob-http-429-over-limit",
    "excessive Retry-After value",
    "Check GitHub's rate-limit status, wait for the limit to reset, then rerun the sync; sync stopped.",
  ],
]) {
  test(`normal sync gives safe retry guidance for a rate limit with ${label}`, (t) => {
    const branchSha = "a".repeat(40);
    const fixture = runSyncWithBranchSha(t, branchSha, mode);
    const apiRoot = "https://api.github.com/repos/vitalitychems-dot/GitMesh";

    assert.equal(fixture.result.status, 1, fixture.output);
    assert.equal(
      fixture.output.trim(),
      `GitHub rate limit reached during POST /git/blobs. ${retryGuidance}`,
    );
    assert.deepEqual(
      fixture.requests.map(({ method, url }) => [method, url]),
      [
        ["GET", `${apiRoot}/git/ref/heads/main`],
        ["GET", `${apiRoot}/git/commits/${branchSha}`],
        ["GET", `${apiRoot}/git/trees/${MOCK_BASE_TREE_SHA}?recursive=1`],
        ["POST", `${apiRoot}/git/blobs`],
        ["POST", `${apiRoot}/git/blobs`],
      ],
    );
    assert.ok(!fixture.output.includes(fixture.privateResponseBody), "response body leaked in output");
    assert.ok(!fixture.output.includes(fixture.privateRetryAfterHeader), "untrusted retry header leaked in output");
    assert.ok(!fixture.output.includes(fixture.fakeToken), "GitHub token leaked in output");
    assert.ok(!fixture.output.includes(fixture.privateSource), "source content leaked in output");
    if (mode !== "blob-http-429") {
      assert.ok(!fixture.output.includes(fixture.retryAfterHeader), "invalid retry delay was used in output");
    }
    assert.equal(
      fixture.remoteHeadAfterSync,
      branchSha,
      "branch was updated after the rate-limit response",
    );
  });
}

for (const status of [401, 403]) {
  test(`normal sync gives safe repository-access guidance for GitHub HTTP ${status}`, (t) => {
    const branchSha = "a".repeat(40);
    const fixture = runSyncWithBranchSha(t, branchSha, `blob-http-${status}`);
    const apiRoot = "https://api.github.com/repos/vitalitychems-dot/GitMesh";
    const expectedMessage =
      `GitHub denied authentication or repository access with HTTP ${status} during POST /git/blobs. ` +
      "Verify GITHUB_TOKEN is active and has Contents write access to vitalitychems-dot/GitMesh; " +
      "update it through Replit Secrets if needed; sync stopped.";

    assert.equal(fixture.result.status, 1, fixture.output);
    assert.equal(fixture.output.trim(), expectedMessage);
    assert.deepEqual(
      fixture.requests.map(({ method, url }) => [method, url]),
      [
        ["GET", `${apiRoot}/git/ref/heads/main`],
        ["GET", `${apiRoot}/git/commits/${branchSha}`],
        ["GET", `${apiRoot}/git/trees/${MOCK_BASE_TREE_SHA}?recursive=1`],
        ["POST", `${apiRoot}/git/blobs`],
        ["POST", `${apiRoot}/git/blobs`],
      ],
    );
    assert.ok(!fixture.output.includes(fixture.privateResponseBody), "response body leaked in output");
    assert.ok(!fixture.output.includes(fixture.fakeToken), "GitHub token leaked in output");
    assert.ok(!fixture.output.includes(fixture.privateSource), "source content leaked in output");
    assert.equal(
      fixture.remoteHeadAfterSync,
      branchSha,
      `branch was updated after GitHub HTTP ${status}`,
    );
  });
}

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

test("unrecognized Node syntax diagnostics are sanitized and stop source sync", (t) => {
  const fixture = runSyncWithSyntaxResult(t, "unrecognized-diagnostic");
  assertSafeSyntaxFailure(
    fixture,
    "Refusing to sync JavaScript that fails Node syntax validation: " +
      "gitmesh-ultimate-core.mjs. Correct the JavaScript and retry the source sync. " +
      "No GitHub requests were made.",
  );

  const invocations = fs
    .readFileSync(fixture.syntaxInvocationLog, "utf8")
    .trim()
    .split("\n")
    .map((entry) => JSON.parse(entry));
  assert.equal(invocations.length, 1, "the unrecognized diagnostic fixture was not exercised");
  assert.equal(invocations[0].status, 1, "the parser fixture did not return a failure");
  assert.equal(invocations[0].error, null, "the parser fixture must be a syntax failure, not a spawn error");
  assert.equal(invocations[0].unrecognizedDiagnostic, true);
});

test("Node startup failure stays private and stops source sync before GitHub", (t) => {
  const fixture = runSyncWithSyntaxResult(t, "spawn-failure");
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

test("a genuinely hung syntax child is terminated and kept private before GitHub", (t) => {
  const fixture = runSyncWithSyntaxResult(t, "hung-child");
  const invocations = fs
    .readFileSync(fixture.syntaxInvocationLog, "utf8")
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));

  assert.equal(fixture.result.status, 1, fixture.output);
  assert.equal(
    fixture.output.trim(),
    "Node syntax validation timed out for gitmesh-ultimate-core.mjs. " +
      "Retry the source sync. No GitHub requests were made.",
  );
  assert.ok(fs.existsSync(fixture.syntaxMarker), "syntax validation did not launch the child fixture");
  assert.ok(fs.existsSync(fixture.fetchMarker) === false, "source sync attempted a GitHub request");
  assert.ok(fs.existsSync(path.join(path.dirname(fixture.syntaxMarker), "hung-child-started")), "the child fixture never started");
  assert.equal(invocations.length, 1, "expected one actual child-process timeout");
  assert.equal(invocations[0].error, "ETIMEDOUT");
  assert.equal(invocations[0].status, null);
  assert.equal(invocations[0].childOutputContainsSentinel, true, "fixture did not produce its private output marker");
  assert.ok(Number.isInteger(invocations[0].pid), "timed child process did not have a process ID");
  assert.throws(() => process.kill(invocations[0].pid, 0), { code: "ESRCH" }, "timeout left the child process running");
  for (const text of fixture.privateTexts) {
    assert.ok(!fixture.output.includes(text), `hung child output or source content leaked: ${text}`);
  }
});

test("interrupted syntax-check is distinct from invalid JavaScript and stops source sync", (t) => {
  const fixture = runSyncWithSyntaxResult(t, "interrupted");
  assertSafeSyntaxFailure(
    fixture,
    "Node syntax validation was interrupted for gitmesh-ultimate-core.mjs. " +
      "Retry the source sync. No GitHub requests were made.",
  );
});

test("syntax checks keep source text out of parser arguments and environment", (t) => {
  const fixture = runSyncWithSyntaxResult(t, "syntax");
  const invalidLine = `export const ${fixture.privateSource} = ;`;
  const invalidColumn = invalidLine.indexOf(";") + 1;
  assertSafeSyntaxFailure(
    fixture,
    "Refusing to sync JavaScript with syntax errors:\n" +
      `- gitmesh-ultimate-core.mjs:1:${invalidColumn}\n` +
      "Correct each file and retry the source sync. No GitHub requests were made.",
  );
  const invocations = fs
    .readFileSync(fixture.syntaxInvocationLog, "utf8")
    .trim()
    .split("\n")
    .map((entry) => JSON.parse(entry));

  assert.ok(invocations.length > 0, "the parser invocation was not captured");
  assert.ok(
    invocations.some((invocation) => invocation.inputHasSourceSentinel),
    "the syntax failure did not receive the sentinel source through stdin",
  );
  for (const invocation of invocations) {
    assert.equal(invocation.command, process.execPath);
    assert.ok(
      !JSON.stringify(invocation.args).includes(fixture.privateSource),
      "source content appeared in parser arguments",
    );
    assert.ok(
      !JSON.stringify(invocation.env).includes(fixture.privateSource),
      "source content appeared in the parser environment",
    );
  }
});

test("normal sync reports all syntax errors in stable order without leaking source or parser output", (t) => {
  const firstFixture = runSyncWithSyntaxResult(t, "multiple-syntax");
  const secondFixture = runSyncWithSyntaxResult(t, "multiple-syntax");
  const firstInvalidLine = "export const FIRST_PRIVATE_SYNTAX_SENTINEL = ;";
  const secondInvalidLine = "export const SECOND_PRIVATE_SYNTAX_SENTINEL = ;";
  const expected =
    "Refusing to sync JavaScript with syntax errors:\n" +
    `- gitmesh-ultimate-core.mjs:2:${firstInvalidLine.indexOf(";") + 1}\n` +
    `- sync-public-source.mjs:2:${secondInvalidLine.indexOf(";") + 1}\n` +
    "Correct each file and retry the source sync. No GitHub requests were made.";

  assertSafeSyntaxFailure(firstFixture, expected);
  assertSafeSyntaxFailure(secondFixture, expected);
  assert.equal(firstFixture.output, secondFixture.output, "diagnostic ordering was unstable");
});

test("--check-syntax reports every syntax error in stable order without leaking source or parser output", (t) => {
  const firstFixture = runSyncWithSyntaxResult(t, "multiple-syntax", { checkOnly: true });
  const secondFixture = runSyncWithSyntaxResult(t, "multiple-syntax", { checkOnly: true });
  const firstInvalidLine = "export const FIRST_PRIVATE_SYNTAX_SENTINEL = ;";
  const secondInvalidLine = "export const SECOND_PRIVATE_SYNTAX_SENTINEL = ;";
  const expected =
    "JavaScript syntax validation found errors:\n" +
    `- gitmesh-ultimate-core.mjs:2:${firstInvalidLine.indexOf(";") + 1}\n` +
    `- sync-public-source.mjs:2:${secondInvalidLine.indexOf(";") + 1}\n` +
    "Correct each file and rerun --check-syntax. No GitHub requests were made.";

  assert.equal(firstFixture.tokenPresent, false, "offline syntax validation unexpectedly required a token");
  assertSafeSyntaxFailure(firstFixture, expected);
  assertSafeSyntaxFailure(secondFixture, expected);
  assert.equal(firstFixture.output, secondFixture.output, "offline diagnostic ordering was unstable");

  for (const fixture of [firstFixture, secondFixture]) {
    const invocations = fs
      .readFileSync(fixture.syntaxInvocationLog, "utf8")
      .trim()
      .split("\n")
      .map((entry) => JSON.parse(entry));
    assert.equal(invocations.length, 2, "not every allowlisted JavaScript file was checked");
    assert.deepEqual(
      invocations.map(({ status }) => status),
      [1, 1],
      "both invalid JavaScript files must be rejected",
    );
  }
});

test("sync checks an earlier JavaScript file before safely rejecting a later file", (t) => {
  const fixture = runSyncWithSyntaxResult(t, "later-syntax");
  const invalidLine = `export const ${fixture.privateSource}_LATER = ;`;
  const invocations = fs
    .readFileSync(fixture.syntaxInvocationLog, "utf8")
    .trim()
    .split("\n")
    .map((entry) => JSON.parse(entry));

  assertSafeSyntaxFailure(
    fixture,
    "Refusing to sync JavaScript with syntax errors:\n" +
      `- sync-public-source.mjs:1:${invalidLine.indexOf(";") + 1}\n` +
      "Correct each file and retry the source sync. No GitHub requests were made.",
  );
  assert.equal(invocations.length, 2, "not every allowlisted JavaScript file was checked");
  assert.deepEqual(
    invocations.map(({ status, inputHasSourceSentinel }) => [status, inputHasSourceSentinel]),
    [[0, false], [1, true]],
    "the earlier module did not pass before the later module failed",
  );
});

test("normal sync stops safely when an allowlisted source cannot be opened", (t) => {
  const fixture = runSyncWithSyntaxResult(t, "eacces-open");
  const { output, result, syntaxMarker, fetchMarker, scriptPath, privateTexts } = fixture;

  assert.notEqual(result.status, 0, output);
  assert.equal(
    output.trim(),
    "JavaScript source sync-public-source.mjs could not be opened. " +
      "Check its permissions and confirm the file still exists, then retry the source sync. " +
      "No GitHub requests were made.",
  );
  assert.ok(fs.existsSync(syntaxMarker), "earlier source validation was not reached");
  assert.ok(!fs.existsSync(fetchMarker), "source sync attempted a GitHub request");
  assert.ok(!output.includes(scriptPath), "absolute filesystem path leaked");
  for (const privateText of privateTexts) {
    assert.ok(!output.includes(privateText), `private diagnostic leaked: ${privateText}`);
  }
});

test("normal sync stops safely when allowlisted source metadata cannot be read", (t) => {
  const fixture = runSyncWithSyntaxResult(t, "eacces-metadata", { tokenPresent: true });
  const { output, result, syntaxMarker, fetchMarker, metadataMarker, scriptPath, privateTexts } = fixture;

  assert.notEqual(result.status, 0, output);
  assert.equal(
    output.trim(),
    "JavaScript source sync-public-source.mjs could not be inspected. " +
      "Check its permissions and confirm the file still exists, then retry the source sync. " +
      "No GitHub requests were made.",
  );
  assert.ok(fs.existsSync(metadataMarker), "the metadata access-denied fixture was not exercised");
  assert.ok(fs.existsSync(syntaxMarker), "earlier source validation was not reached");
  assert.ok(!fs.existsSync(fetchMarker), "source sync attempted a GitHub request");
  assert.ok(!output.includes(scriptPath), "absolute filesystem path leaked");
  for (const privateText of privateTexts) {
    assert.ok(!output.includes(privateText), `private diagnostic leaked: ${privateText}`);
  }
});

test("--check-syntax gives safe guidance when an allowlisted JavaScript source cannot be opened", (t) => {
  const fixture = runSyncWithSyntaxResult(t, "eacces-open", {
    checkOnly: true,
    tokenPresent: false,
  });

  assert.equal(fixture.tokenPresent, false, "offline syntax checking must not require a GitHub token");
  assertSafeSyntaxFailure(
    fixture,
    "JavaScript source sync-public-source.mjs could not be opened. " +
      "Check its permissions and confirm the file still exists, then rerun --check-syntax. " +
      "No GitHub requests were made.",
  );
  assert.ok(fs.existsSync(fixture.sourceReadMarker), "the access-denied read was not exercised");
  assert.ok(
    !fixture.output.includes(fixture.scriptPath),
    "absolute filesystem path leaked in offline syntax-check output",
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

  assert.equal(fixture.tokenPresent, false, "offline syntax checking must not require a token");
  assert.equal(fixture.result.error, undefined);
  assert.equal(fixture.result.status, 0, fixture.output);
  assert.equal(
    fixture.output.trim(),
    "JavaScript syntax validation passed for 2 files: " +
      "gitmesh-ultimate-core.mjs, sync-public-source.mjs.",
  );
  assert.ok(!fixture.output.includes("README.md"), "a non-JavaScript file was listed");
  assert.ok(fs.existsSync(fixture.sourceReadMarker), "offline syntax checking did not read its source files");
  assert.ok(fs.existsSync(fixture.syntaxMarker), "the syntax subprocess was not exercised");
  assert.ok(!fs.existsSync(fixture.fetchMarker), "syntax check attempted a GitHub request");
  for (const privateText of fixture.privateTexts) {
    assert.ok(!fixture.output.includes(privateText), `source content leaked: ${privateText}`);
  }
});

test("--preview lists exactly the approved target paths without a token or network request", (t) => {
  const fixtures = [
    runSyncWithSyntaxResult(t, "success", {
      extraArgs: ["--preview"],
      tokenPresent: false,
    }),
    runSyncWithSyntaxResult(t, "success", {
      extraArgs: ["--preview"],
      tokenPresent: true,
    }),
  ];
  const expectedPaths = [
    "projects/local-vault/gitmesh-ultimate-core.mjs",
    "projects/local-vault/README.md",
    "projects/local-vault/sync-public-source.mjs",
  ].join("\n");

  for (const fixture of fixtures) {
    assert.equal(fixture.result.status, 0, fixture.output);
    assert.equal(fixture.output.trim(), expectedPaths);
    assert.ok(fs.existsSync(fixture.sourceReadMarker), "preview did not inspect its source files");
    assert.ok(fs.existsSync(fixture.syntaxMarker), "preview did not validate JavaScript syntax");
    assert.ok(!fs.existsSync(fixture.fetchMarker), "preview attempted a GitHub request");
    for (const privateText of fixture.privateTexts) {
      assert.ok(!fixture.output.includes(privateText), `preview leaked private material: ${privateText}`);
    }
  }
});

test("--preview rejects invalid source before listing targets or contacting GitHub", (t) => {
  const fixture = runSyncWithSyntaxResult(t, "syntax", {
    extraArgs: ["--preview"],
    tokenPresent: true,
  });
  const invalidLine = `export const ${fixture.privateSource} = ;`;

  assert.equal(fixture.result.status, 1, fixture.output);
  assert.equal(
    fixture.output.trim(),
    "Refusing to sync JavaScript with syntax errors:\n" +
      `- gitmesh-ultimate-core.mjs:1:${invalidLine.indexOf(";") + 1}\n` +
      "Correct each file and retry the source sync. No GitHub requests were made.",
  );
  assert.ok(!fs.existsSync(fixture.fetchMarker), "invalid preview attempted a GitHub request");
  assert.ok(!fixture.output.includes(fixture.fakeToken), "preview error leaked the GitHub token");
  assert.ok(!fixture.output.includes(fixture.privateSource), "preview error leaked source text");
  assert.ok(!fixture.output.includes("projects/local-vault/"), "invalid preview printed target paths");
});

test("--check-syntax succeeds with a GitHub token and performs no sync requests", (t) => {
  const fixture = runSyncWithSyntaxResult(t, "success", {
    checkOnly: true,
    tokenPresent: true,
  });

  assert.equal(fixture.tokenPresent, true, "the parent process did not receive a fake token");
  assert.equal(fixture.result.status, 0, fixture.output);
  assert.equal(
    fixture.output.trim(),
    "JavaScript syntax validation passed for 2 files: " +
      "gitmesh-ultimate-core.mjs, sync-public-source.mjs.",
  );
  assert.ok(!fixture.output.includes(fixture.fakeToken), "GitHub token leaked in output");
  assert.ok(fs.existsSync(fixture.syntaxMarker), "the syntax subprocess was not exercised");
  assert.ok(!fs.existsSync(fixture.fetchMarker), "syntax-only command attempted a GitHub request or write");

  const invocations = fs
    .readFileSync(fixture.syntaxInvocationLog, "utf8")
    .trim()
    .split("\n")
    .map((entry) => JSON.parse(entry));
  assert.equal(invocations.length, 2, "not every JavaScript file received a syntax check");
  assert.ok(
    invocations.every((invocation) => !Object.hasOwn(invocation.env, "GITHUB_TOKEN")),
    "syntax subprocess inherited the GitHub token",
  );
});

test("--check-syntax rejects invalid JavaScript with a GitHub token without publishing", (t) => {
  const fixture = runSyncWithSyntaxResult(t, "syntax", {
    checkOnly: true,
    tokenPresent: true,
  });
  const invalidLine = `export const ${fixture.privateSource} = ;`;
  const invalidColumn = invalidLine.indexOf(";") + 1;

  assert.equal(fixture.tokenPresent, true, "the parent process did not receive a fake token");
  assertSafeSyntaxFailure(
    fixture,
    "JavaScript syntax validation found errors:\n" +
      `- gitmesh-ultimate-core.mjs:1:${invalidColumn}\n` +
      "Correct each file and rerun --check-syntax. No GitHub requests were made.",
  );
  assert.ok(
    !fixture.output.includes(fixture.fakeToken),
    "GitHub token leaked in syntax-check output",
  );

  const invocations = fs
    .readFileSync(fixture.syntaxInvocationLog, "utf8")
    .trim()
    .split("\n")
    .map((entry) => JSON.parse(entry));
  assert.ok(invocations.some((invocation) => invocation.status === 1), "invalid JavaScript was not rejected");
  assert.ok(
    invocations.every((invocation) => !Object.hasOwn(invocation.env, "GITHUB_TOKEN")),
    "syntax subprocess inherited the GitHub token",
  );
});

test("--check-syntax rejects unexpected arguments before any GitHub request", (t) => {
  const fixture = runSyncWithSyntaxResult(t, "success", {
    checkOnly: true,
    tokenPresent: true,
    extraArgs: ["unexpected-argument"],
  });

  assert.equal(fixture.tokenPresent, true, "the parent process did not receive a fake token");
  assert.equal(fixture.result.status, 2, fixture.output);
  assert.equal(
    fixture.output.trim(),
    "This program does not accept command-line arguments.",
  );
  assert.ok(!fixture.output.includes(fixture.fakeToken), "GitHub token leaked in usage output");
  assert.ok(!fs.existsSync(fixture.sourceReadMarker), "invalid arguments caused source files to be read");
  assert.ok(!fs.existsSync(fixture.syntaxMarker), "invalid arguments launched syntax validation");
  assert.ok(!fs.existsSync(fixture.fetchMarker), "invalid arguments attempted a GitHub request or publish write");
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
      'const state = { requests: [], configuredTimeouts: [] };',
      'const statePath = process.env.GITMESH_TEST_REQUEST_LOG;',
      'const saveState = () => fs.writeFileSync(statePath, JSON.stringify(state));',
      'const timers = new Map();',
      'globalThis.AbortSignal.timeout = (milliseconds) => {',
      '  state.configuredTimeouts.push(milliseconds);',
      '  const controller = new AbortController();',
      `  const timer = setTimeout(() => controller.abort(new DOMException("${privateFetchError}", "TimeoutError")), 40);`,
      '  timers.set(controller.signal, timer);',
      '  saveState();',
      '  return controller.signal;',
      '};',
      "globalThis.fetch = async (url, options = {}) => {",
      "  const request = { method: options.method ?? \"GET\", url, timeoutSignalAttached: options.signal instanceof AbortSignal, signalInitiallyAborted: options.signal?.aborted ?? null, authorizationHeaderIsExpected: options.headers?.Authorization === `Bearer ${process.env.GITHUB_TOKEN}` };",
      '  state.requests.push(request);',
      '  saveState();',
      '  if (url.endsWith("/git/ref/heads/main")) {',
      '    clearTimeout(timers.get(options.signal));',
      '    return { ok: true, json: async () => ({ object: { sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" } }) };',
      "  }",
      '  if (url.endsWith("/git/commits/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")) {',
      '    clearTimeout(timers.get(options.signal));',
      '    return { ok: true, json: async () => ({ tree: { sha: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" } }) };',
      "  }",
      '  if (url.endsWith("/git/trees/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb?recursive=1")) {',
      '    clearTimeout(timers.get(options.signal));',
      '    return { ok: true, json: async () => ({ truncated: false, tree: [] }) };',
      "  }",
      '  return new Promise((resolve, reject) => {',
      '    const onAbort = () => {',
      '      request.signalAborted = options.signal.aborted;',
      '      request.abortReasonName = options.signal.reason?.name;',
      '      saveState();',
      '      reject(options.signal.reason);',
      '    };',
      '    if (options.signal?.aborted) onAbort();',
      '    else options.signal?.addEventListener("abort", onAbort, { once: true });',
      '  });',
      "};",
    ].join("\n"),
  );
  fs.writeFileSync(requestLog, JSON.stringify({ requests: [], configuredTimeouts: [] }));

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
  const observations = JSON.parse(fs.readFileSync(requestLog, "utf8"));
  assert.deepEqual(observations.requests.map(({ method, url }) => ({ method, url })), [
    {
      method: "GET",
      url: "https://api.github.com/repos/vitalitychems-dot/GitMesh/git/ref/heads/main",
    },
    {
      method: "GET",
      url: "https://api.github.com/repos/vitalitychems-dot/GitMesh/git/commits/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    },
    {
      method: "GET",
      url: "https://api.github.com/repos/vitalitychems-dot/GitMesh/git/trees/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb?recursive=1",
    },
    {
      method: "POST",
      url: "https://api.github.com/repos/vitalitychems-dot/GitMesh/git/blobs",
    },
  ]);
  assert.deepEqual(observations.configuredTimeouts, [20_000, 20_000, 20_000, 20_000], "the configured timeout was not attached to each request");
  assert.ok(observations.requests.every(({ timeoutSignalAttached, authorizationHeaderIsExpected }) => timeoutSignalAttached && authorizationHeaderIsExpected), "request was missing its abort signal or expected credential");
  assert.ok(observations.requests.every(({ signalInitiallyAborted }) => signalInitiallyAborted === false), "a request did not start with a live signal");
  assert.equal(observations.requests.at(-1).signalAborted, true, "stalled fetch did not receive the timeout abort");
  assert.equal(observations.requests.at(-1).abortReasonName, "TimeoutError");
  assert.ok(observations.requests.every(({ signalAborted }) => signalAborted === undefined || signalAborted === true), "a completed request unexpectedly aborted");
  assert.ok(!output.includes(fakeToken), "GitHub token leaked in timeout output");
  assert.ok(!output.includes(privateSource), "source content leaked in timeout output");
  assert.ok(!output.includes(privateFetchError), "raw fetch error leaked in timeout output");
});

test("a later blob timeout prevents tree, commit, and branch writes", (t) => {
  const branchSha = "a".repeat(40);
  const fixture = runSyncWithBranchSha(t, branchSha, "later-blob-timeout");
  const apiRoot = "https://api.github.com/repos/vitalitychems-dot/GitMesh";
  const blobRequests = fixture.requests.filter(
    ({ method, url }) => method === "POST" && url.endsWith("/git/blobs"),
  );

  assert.equal(fixture.result.status, 1, fixture.output);
  assert.equal(
    fixture.output.trim(),
    "GitHub request timed out during POST /git/blobs. " +
      "Check the connection and retry; sync stopped.",
  );
  assert.deepEqual(
    fixture.requests.map(({ method, url }) => [method, url]),
    [
      ["GET", `${apiRoot}/git/ref/heads/main`],
      ["GET", `${apiRoot}/git/commits/${branchSha}`],
      ["GET", `${apiRoot}/git/trees/${MOCK_BASE_TREE_SHA}?recursive=1`],
      ["POST", `${apiRoot}/git/blobs`],
      ["POST", `${apiRoot}/git/blobs`],
    ],
  );
  assert.equal(blobRequests.length, 2, "the later blob request was not attempted");
  assert.equal(
    Buffer.from(blobRequests[0].blob.content, "base64").toString("utf8"),
    fixture.expectedSources["projects/local-vault/gitmesh-ultimate-core.mjs"],
    "the first blob did not complete with the expected source",
  );
  assert.equal(
    Buffer.from(blobRequests[1].blob.content, "base64").toString("utf8"),
    fixture.expectedSources["projects/local-vault/README.md"],
    "the timeout was not on the second blob request",
  );
  assert.ok(fixture.requests.every(({ url }) => url.startsWith(`${apiRoot}/`)));
  assert.ok(
    !fixture.output.includes(fixture.fakeToken),
    "GitHub token leaked in timeout output",
  );
  assert.ok(
    !fixture.output.includes(fixture.privateNetworkError),
    "raw timeout diagnostic leaked in output",
  );
  assert.ok(
    !fixture.output.includes(fixture.privateSource),
    "source content leaked in timeout output",
  );
});

test("retry after an ambiguous ref timeout reads the latest head and never forces an update", (t) => {
  const originalSha = "a".repeat(40);
  const latestRemoteSha = "f".repeat(40);
  const firstAttempt = runSyncWithBranchSha(
    t,
    originalSha,
    "ref-update-timeout-after-accept",
  );
  const apiRoot = "https://api.github.com/repos/vitalitychems-dot/GitMesh";

  assert.equal(firstAttempt.result.status, 1, firstAttempt.output);
  assert.equal(
    firstAttempt.output.trim(),
    "GitHub request timed out during PATCH /git/refs/heads/main. " +
      "Check the connection and retry; sync stopped.",
  );
  assert.equal(firstAttempt.requests.length, 9);
  assert.deepEqual(firstAttempt.requests[7].commit.parents, [originalSha]);
  assert.equal(firstAttempt.requests[8].refUpdate.force, false);
  assert.equal(firstAttempt.remoteHeadAfterSync, firstAttempt.requests[8].refUpdate.sha);
  assert.ok(!firstAttempt.output.includes(firstAttempt.fakeToken));
  assert.ok(!firstAttempt.output.includes(firstAttempt.privateNetworkError));
  assert.ok(!firstAttempt.output.includes(firstAttempt.privateSource));

  // Simulate another writer advancing the branch before the operator retries.
  fs.writeFileSync(firstAttempt.remoteHeadPath, latestRemoteSha);
  const retry = runSyncWithBranchSha(
    t,
    latestRemoteSha,
    "retry-after-ref-timeout",
    { remoteHeadPath: firstAttempt.remoteHeadPath },
  );

  assert.equal(retry.result.status, 0, retry.output);
  assert.ok(retry.output.includes("Synced 3 allowlisted source files"));
  assert.deepEqual(
    retry.requests.map(({ method, url }) => [method, url]),
    [
      ["GET", `${apiRoot}/git/ref/heads/main`],
      ["GET", `${apiRoot}/git/commits/${latestRemoteSha}`],
      ["GET", `${apiRoot}/git/trees/${MOCK_BASE_TREE_SHA}?recursive=1`],
      ["POST", `${apiRoot}/git/blobs`],
      ["POST", `${apiRoot}/git/blobs`],
      ["POST", `${apiRoot}/git/blobs`],
      ["POST", `${apiRoot}/git/trees`],
      ["POST", `${apiRoot}/git/commits`],
      ["PATCH", `${apiRoot}/git/refs/heads/main`],
    ],
  );
  assert.deepEqual(retry.requests[7].commit.parents, [latestRemoteSha]);
  assert.equal(retry.requests[8].refUpdate.force, false);
  assert.equal(retry.remoteHeadAfterSync, retry.requests[8].refUpdate.sha);
  assert.ok(!retry.output.includes(retry.fakeToken));
  assert.ok(!retry.output.includes(retry.privateNetworkError));
  assert.ok(!retry.output.includes(retry.privateSource));
});

test("a branch advance before ref update is rejected without overwriting the new head", (t) => {
  const originalSha = "a".repeat(40);
  const fixture = runSyncWithBranchSha(t, originalSha, "branch-advance-before-ref-update");
  const apiRoot = "https://api.github.com/repos/vitalitychems-dot/GitMesh";

  assert.equal(fixture.result.status, 1, fixture.output);
  assert.equal(
    fixture.output.trim(),
    "GitHub request failed with HTTP 422 during PATCH /git/refs/heads/main. " +
      "The branch may have advanced; rerun the sync to read the latest head; sync stopped.",
  );
  assert.deepEqual(
    fixture.requests.map(({ method, url }) => [method, url]),
    [
      ["GET", `${apiRoot}/git/ref/heads/main`],
      ["GET", `${apiRoot}/git/commits/${originalSha}`],
      ["GET", `${apiRoot}/git/trees/${MOCK_BASE_TREE_SHA}?recursive=1`],
      ["POST", `${apiRoot}/git/blobs`],
      ["POST", `${apiRoot}/git/blobs`],
      ["POST", `${apiRoot}/git/blobs`],
      ["POST", `${apiRoot}/git/trees`],
      ["POST", `${apiRoot}/git/commits`],
      ["PATCH", `${apiRoot}/git/refs/heads/main`],
    ],
  );
  assert.deepEqual(fixture.requests[7].commit.parents, [originalSha]);
  assert.equal(fixture.requests[8].refUpdate.force, false);
  assert.notEqual(fixture.requests[8].refUpdate.sha, fixture.advancedHeadSha);
  assert.equal(fixture.remoteHeadAfterSync, fixture.advancedHeadSha);
  assert.ok(!fixture.output.includes(fixture.privateResponseBody));
  assert.ok(!fixture.output.includes(fixture.fakeToken));
  assert.ok(!fixture.output.includes(fixture.privateSource));
});
