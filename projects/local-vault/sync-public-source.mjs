import fs from "node:fs";
import { spawnSync } from "node:child_process";
import path from "node:path";
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

function validateJavaScriptSyntax(content, source) {
  const result = spawnSync(process.execPath, ["--input-type=module", "--check"], {
    input: content,
    encoding: "utf8",
    timeout: 10_000,
    maxBuffer: 64 * 1024,
    env: { PATH: process.env.PATH ?? "" },
  });
  if (result.error || result.status !== 0) {
    throw new Error(
      `Refusing to sync JavaScript that fails Node syntax validation: ${source}. ` +
      "Correct the JavaScript and retry the source sync. No GitHub requests were made.",
    );
  }
}

function getToken() {
  const token = process.env.GITHUB_TOKEN;
  if (!token || token.length > 4096 || /[\r\n]/.test(token)) {
    throw new Error("Set GITHUB_TOKEN through Replit Secrets before running source sync.");
  }
  return token;
}

function requireSha(value, label) {
  if (typeof value !== "string" || !/^[a-f0-9]{40}$/.test(value)) {
    throw new Error(`GitHub returned an invalid ${label}; sync stopped.`);
  }
  return value;
}

function readSourceFiles() {
  return ALLOWED_FILES.map(({ source, target }) => {
    const sourcePath = path.join(ROOT, source);
    const fileInfo = fs.lstatSync(sourcePath);
    if (!fileInfo.isFile() || fileInfo.isSymbolicLink() || fileInfo.size > MAX_SOURCE_BYTES) {
      throw new Error(`Refusing to sync an invalid or oversized source file: ${source}`);
    }
    const content = fs.readFileSync(sourcePath);
    if (content.includes(0)) {
      throw new Error(`Refusing to sync a non-text source file: ${source}`);
    }
    if (path.extname(source) === ".mjs") {
      validateJavaScriptSyntax(content, source);
    }
    return { target, content };
  });
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
  } catch {
    throw new Error(`GitHub request failed during ${method} ${route}.`);
  }
  if (!response.ok) {
    throw new Error(`GitHub request failed with HTTP ${response.status} during ${method} ${route}.`);
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

  const blobs = await Promise.all(files.map(async ({ content }) => {
    const blob = await githubRequest(token, "/git/blobs", "POST", {
      content: content.toString("base64"),
      encoding: "base64",
    });
    return requireSha(blob?.sha, "blob SHA");
  }));

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

if (process.argv.length !== 2) {
  console.error("This program does not accept command-line arguments.");
  process.exitCode = 2;
} else {
  syncSource().catch((error) => {
    console.error(error instanceof Error ? error.message : "Source sync failed.");
    process.exitCode = 1;
  });
}
