import fs from "node:fs";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { TextDecoder } from "node:util";
import { fileURLToPath } from "node:url";

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const OWNER = "vitalitychems-dot";
const REPOSITORY = "GitMesh";
const BRANCH = "main";
const API_ROOT = `https://api.github.com/repos/${OWNER}/${REPOSITORY}`;
const MAX_SOURCE_BYTES = 512 * 1024;
const ALLOWED_FILES = [
  {
    source: "gitmesh-ultimate-core.mjs",
    target: "projects/local-vault/gitmesh-ultimate-core.mjs",
  },
  {
    source: "README.md",
    target: "projects/local-vault/README.md",
  },
  {
    source: "sync-public-source.mjs",
    target: "projects/local-vault/sync-public-source.mjs",
  },
];

function validateJavaScriptSyntax(content, source, { syntaxOnly = false } = {}) {
  const retryInstruction = syntaxOnly
    ? "Save the intended file and rerun --check-syntax."
    : "Retry the source sync.";
  const result = spawnSync(process.execPath, ["--input-type=module", "--check"], {
    input: content,
    encoding: "utf8",
    timeout: 10_000,
    maxBuffer: 64 * 1024,
    env: { PATH: process.env.PATH ?? "" },
  });
  if (result.error?.code === "ETIMEDOUT") {
    throw new Error(
      `Node syntax validation timed out for ${source}. ` +
      `${retryInstruction} No GitHub requests were made.`,
    );
  }
  if (result.signal) {
    throw new Error(
      `Node syntax validation was interrupted for ${source}. ` +
      `${retryInstruction} No GitHub requests were made.`,
    );
  }
  if (result.error || result.status !== 0) {
    const location = result.error ? null : syntaxErrorLocation(result.stderr);
    if (location) return location;
    if (syntaxOnly) {
      throw new Error(
        `JavaScript syntax validation failed for ${source}. ` +
        "Correct the JavaScript and rerun --check-syntax. No GitHub requests were made.",
      );
    }
    throw new Error(
      `Refusing to sync JavaScript that fails Node syntax validation: ${source}. ` +
      "Correct the JavaScript and retry the source sync. No GitHub requests were made.",
    );
  }
}

function syntaxErrorLocation(stderr) {
  if (typeof stderr !== "string") return null;
  const match = /^(?:\[stdin\]|stdin):(\d+)\r?\n[^\r\n]*\r?\n([ \t]*)\^/m.exec(stderr);
  if (!match) return null;
  const line = Number(match[1]);
  const column = match[2].length + 1;
  return Number.isSafeInteger(line) && line > 0 && Number.isSafeInteger(column)
    ? { line, column }
    : null;
}

function getToken() {
  const token = process.env.GITHUB_TOKEN;
  if (!token || token.length > 4096 || /[\r\n]/.test(token)) {
    throw new Error("Set GITHUB_TOKEN through Replit Secrets before running source sync.");
  }
  return token;
}

function sameFileSnapshot(before, after) {
  return before.dev === after.dev
    && before.ino === after.ino
    && before.mode === after.mode
    && before.size === after.size
    && before.mtimeNs === after.mtimeNs
    && before.ctimeNs === after.ctimeNs;
}

function requireSha(value, label) {
  if (typeof value !== "string" || !/^[a-f0-9]{40}$/.test(value)) {
    throw new Error(`GitHub returned an invalid ${label}; sync stopped.`);
  }
  return value;
}

function invalidSourceMessage(source, fileInfo, syntaxOnly) {
  if (!syntaxOnly) {
    if (fileInfo.isSymbolicLink()) {
      return (
        `Refusing to sync a symbolic-link source file: ${source}. ` +
        "Restore it as a regular file; no GitHub requests were made."
      );
    }
    return `Refusing to sync an invalid or oversized source file: ${source}`;
  }
  if (fileInfo.isSymbolicLink()) {
    return (
      `JavaScript source ${source} is a symbolic link. ` +
      "Replace it with a regular file, then rerun --check-syntax. " +
      "No GitHub requests were made."
    );
  }
  if (fileInfo.size > BigInt(MAX_SOURCE_BYTES)) {
    return (
      `JavaScript source ${source} exceeds the ${MAX_SOURCE_BYTES / 1024} KiB limit. ` +
      `Reduce it to ${MAX_SOURCE_BYTES / 1024} KiB or less, then rerun --check-syntax. ` +
      "No GitHub requests were made."
    );
  }
  return (
    `JavaScript source ${source} is not a regular file. ` +
    "Restore it as a regular file, then rerun --check-syntax. " +
    "No GitHub requests were made."
  );
}

function readSourceMetadata(sourcePath, source, isJavaScript, syntaxOnly) {
  try {
    return fs.lstatSync(sourcePath, { bigint: true });
  } catch {
    const fileLabel = isJavaScript ? "JavaScript source" : "Source file";
    const repairInstruction = syntaxOnly
      ? "Check its permissions and confirm the file still exists, then rerun --check-syntax."
      : "Check its permissions and confirm the file still exists, then retry the source sync.";
    throw new Error(
      `${fileLabel} ${source} could not be inspected. ${repairInstruction} ` +
      "No GitHub requests were made.",
    );
  }
}

function readSourceFiles({ syntaxOnly = false } = {}) {
  const sourceFiles = syntaxOnly
    ? ALLOWED_FILES.filter(({ source }) => path.extname(source) === ".mjs")
    : ALLOWED_FILES;
  const syntaxDiagnostics = [];
  const files = sourceFiles.map(({ source, target }) => {
    const sourcePath = path.join(ROOT, source);
    const isJavaScript = path.extname(source) === ".mjs";
    const fileInfo = readSourceMetadata(sourcePath, source, isJavaScript, syntaxOnly);
    if (fileInfo.isSymbolicLink() || fileInfo.size > BigInt(MAX_SOURCE_BYTES) || !fileInfo.isFile()) {
      throw new Error(invalidSourceMessage(source, fileInfo, syntaxOnly));
    }
    let content;
    try {
      content = fs.readFileSync(sourcePath);
    } catch {
      const fileLabel = isJavaScript ? "JavaScript source" : "Source file";
      const repairInstruction = syntaxOnly
        ? "Check its permissions and confirm the file still exists, then rerun --check-syntax."
        : "Check its permissions and confirm the file still exists, then retry the source sync.";
      throw new Error(
        `${fileLabel} ${source} could not be opened. ${repairInstruction} ` +
        "No GitHub requests were made.",
      );
    }
    const currentInfo = readSourceMetadata(sourcePath, source, isJavaScript, syntaxOnly);
    if (!sameFileSnapshot(fileInfo, currentInfo) || BigInt(content.length) !== fileInfo.size) {
      const retryInstruction = syntaxOnly
        ? "Save the intended file and rerun --check-syntax."
        : "Save the intended file and retry the source sync; syntax validation will run again.";
      throw new Error(
        `JavaScript source changed during syntax validation: ${source}. ` +
        `${retryInstruction} No GitHub requests were made.`,
      );
    }
    if (content.includes(0)) {
      if (isJavaScript) {
        throw new Error(
          `JavaScript source ${source} contains NUL bytes. ` +
          "Save it as valid UTF-8 text and rerun --check-syntax. " +
          "No GitHub requests were made.",
        );
      }
      throw new Error(`Refusing to sync a non-text source file: ${source}`);
    }
    try {
      new TextDecoder("utf-8", { fatal: true }).decode(content);
    } catch {
      if (!isJavaScript) {
        throw new Error(
          `Source file ${source} is not valid UTF-8. ` +
          "Save it as valid UTF-8 text and retry the source sync. " +
          "No GitHub requests were made.",
        );
      }
      throw new Error(
        `JavaScript source ${source} is not valid UTF-8. ` +
        "Save it as valid UTF-8 text and rerun --check-syntax. " +
        "No GitHub requests were made.",
      );
    }
    if (isJavaScript) {
      const location = validateJavaScriptSyntax(content, source, { syntaxOnly });
      if (location) syntaxDiagnostics.push({ source, ...location });
    }
    return { target, content };
  });
  if (syntaxDiagnostics.length > 0) {
    const orderedDiagnostics = syntaxDiagnostics
      .slice()
      .sort((left, right) => left.source < right.source ? -1 : left.source > right.source ? 1 : 0);
    const lines = orderedDiagnostics
      .map(({ source, line, column }) => `- ${source}:${line}:${column}`)
      .join("\n");
    const heading = syntaxOnly
      ? "JavaScript syntax validation found errors:"
      : "Refusing to sync JavaScript with syntax errors:";
    const instruction = syntaxOnly
      ? "Correct each file and rerun --check-syntax."
      : "Correct each file and retry the source sync.";
    throw new Error(
      `${heading}\n${lines}\n${instruction} No GitHub requests were made.`,
    );
  }
  return files;
}

function validatedRetryAfterSeconds(response) {
  let value;
  try {
    value = response.headers?.get?.("retry-after");
  } catch {
    return null;
  }
  if (typeof value !== "string" || !/^[0-9]{1,5}$/.test(value)) return null;
  const seconds = Number(value);
  return Number.isSafeInteger(seconds) && seconds > 0 && seconds <= 3600 ? seconds : null;
}

async function githubRequest(token, route, method = "GET", body = undefined) {
  let response;
  try {
    response = await fetch(`${API_ROOT}${route}`, {
      method,
      headers: {
        Accept: "application/vnd.github+json",
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "GitMesh-Source-Sync",
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      signal: AbortSignal.timeout(20_000),
    });
  } catch (error) {
    if (error instanceof Error && error.name === "TimeoutError") {
      throw new Error(
        `GitHub request timed out during ${method} ${route}. ` +
        "Check the connection and retry; sync stopped.",
      );
    }
    throw new Error(
      `GitHub request failed during ${method} ${route}. ` +
      "Check the connection and retry; sync stopped.",
    );
  }
  if (!response.ok) {
    const status =
      Number.isInteger(response.status) && response.status >= 100 && response.status <= 599
        ? response.status
        : null;
    const statusText = status === null ? "unknown" : status;
    const retryAfterSeconds = status === 429 ? validatedRetryAfterSeconds(response) : null;
    const retryGuidance =
      status === 429
        ? retryAfterSeconds === null
          ? " Check GitHub's rate-limit status, wait for the limit to reset, then rerun the sync; sync stopped."
          : ` Wait ${retryAfterSeconds} seconds, then rerun the sync; sync stopped.`
        : status !== null && status >= 500
          ? " Check the connection and retry; sync stopped."
          : method === "PATCH" &&
              route === "/git/refs/heads/main" &&
              (status === 409 || status === 422)
            ? " The branch may have advanced; rerun the sync to read the latest head; sync stopped."
            : "";
    const failureMessage =
      status === 429
        ? `GitHub rate limit reached during ${method} ${route}.`
        : status === 401 || status === 403
          ? `GitHub denied authentication or repository access with HTTP ${status} during ${method} ${route}. ` +
            `Verify GITHUB_TOKEN is active and has Contents write access to ${OWNER}/${REPOSITORY}; ` +
            "update it through Replit Secrets if needed; sync stopped."
        : `GitHub request failed with HTTP ${statusText} during ${method} ${route}.`;
    throw new Error(
      `${failureMessage}${retryGuidance}`,
    );
  }
  try {
    return await response.json();
  } catch {
    throw new Error(`GitHub returned an invalid response during ${method} ${route}.`);
  }
}

async function syncSource() {
  const token = getToken();
  const files = readSourceFiles();
  const ref = await githubRequest(token, `/git/ref/heads/${BRANCH}`);
  const parentSha = requireSha(ref?.object?.sha, "main branch commit");
  const parentCommit = await githubRequest(token, `/git/commits/${parentSha}`);
  const baseTreeSha = requireSha(parentCommit?.tree?.sha, "base tree");

  const blobs = [];
  for (const { content } of files) {
    const blob = await githubRequest(token, "/git/blobs", "POST", {
      content: content.toString("base64"),
      encoding: "base64",
    });
    blobs.push(requireSha(blob?.sha, "blob SHA"));
  }

  const tree = await githubRequest(token, "/git/trees", "POST", {
    base_tree: baseTreeSha,
    tree: files.map(({ target }, index) => ({
      path: target,
      mode: "100644",
      type: "blob",
      sha: blobs[index],
    })),
  });
  const treeSha = requireSha(tree?.sha, "tree SHA");

  const commit = await githubRequest(token, "/git/commits", "POST", {
    message: "Sync GitMesh local-vault source",
    tree: treeSha,
    parents: [parentSha],
  });
  const commitSha = requireSha(commit?.sha, "commit SHA");

  const updatedRef = await githubRequest(token, `/git/refs/heads/${BRANCH}`, "PATCH", {
    sha: commitSha,
    force: false,
  });
  if (updatedRef?.object?.sha !== commitSha) {
    throw new Error("GitHub did not confirm the source sync commit.");
  }

  console.log(`Synced ${files.length} allowlisted source files to ${OWNER}/${REPOSITORY}@${BRANCH}.`);
  console.log(`Commit: ${commitSha}`);
}

function checkJavaScriptSyntax() {
  const files = readSourceFiles({ syntaxOnly: true });
  const names = files.map(({ target }) => path.basename(target));
  console.log(
    `JavaScript syntax validation passed for ${names.length} files: ${names.join(", ")}.`,
  );
}

if (process.argv.length === 3 && process.argv[2] === "--check-syntax") {
  try {
    checkJavaScriptSyntax();
  } catch (error) {
    console.error(error instanceof Error ? error.message : "JavaScript syntax validation failed.");
    process.exitCode = 1;
  }
} else if (process.argv.length !== 2) {
  console.error("This program does not accept command-line arguments.");
  process.exitCode = 2;
} else {
  syncSource().catch((error) => {
    console.error(error instanceof Error ? error.message : "Source sync failed.");
    process.exitCode = 1;
  });
}
