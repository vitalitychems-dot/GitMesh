import fs from "node:fs";
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
    return { target, content };
  });
}

async function githubRequest(token, route, method = "GET", body = undefined, { allowNotFound = false } = {}) {
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
    throw new Error(
      `Could not reach GitHub during ${method} ${route}. Check the connection and retry; no force update is attempted.`,
    );
  }
  if (allowNotFound && response.status === 404) return null;
  if (!response.ok) {
    const context = `${method} ${route} (HTTP ${response.status})`;
    if (response.status === 401) {
      throw new Error(
        `GitHub rejected authentication during ${context}. Check that the GITHUB_TOKEN Secret is current and grants access to ${OWNER}/${REPOSITORY}.`,
      );
    }
    if (response.status === 403 || response.status === 429) {
      const retryAfter = response.headers?.get("retry-after");
      const remaining = response.headers?.get("x-ratelimit-remaining");
      if (response.status === 429 ||
          (typeof retryAfter === "string" && retryAfter.length > 0) ||
          remaining === "0") {
        throw new Error(
          `GitHub rate limit reached during ${context}. Wait for the limit to reset, then retry.`,
        );
      }
      const contentsPermission = method === "GET" ? "Contents:read" : "Contents:write";
      throw new Error(
        `GitHub denied access during ${context}. Check repository access and the token's ${contentsPermission} permission.`,
      );
    }
    if (response.status === 409 && method === "PATCH" && route.startsWith("/git/refs/heads/")) {
      throw new Error(
        `GitHub rejected the non-force branch update during ${context}. The branch changed while syncing; review it and retry. No force update was attempted.`,
      );
    }
    if (response.status === 404) {
      throw new Error(
        `GitHub could not find the target during ${context}. Check the repository, branch, and token access.`,
      );
    }
    if (response.status >= 500) {
      throw new Error(
        `GitHub is temporarily unavailable during ${context}. Wait briefly and retry; no force update was attempted.`,
      );
    }
    throw new Error(
      `GitHub rejected the request during ${context}. Check repository permissions and source-sync configuration, then retry.`,
    );
  }
  try {
    return await response.json();
  } catch {
    throw new Error(`GitHub returned an invalid response during ${method} ${route}.`);
  }
}

async function readRemoteSourceFile(token, target) {
  const encodedPath = target.split("/").map(encodeURIComponent).join("/");
  const remote = await githubRequest(
    token,
    `/contents/${encodedPath}?ref=${encodeURIComponent(BRANCH)}`,
    "GET",
    undefined,
    { allowNotFound: true },
  );
  if (remote === null) return null;
  if (remote.type !== "file" || remote.encoding !== "base64" || typeof remote.content !== "string") {
    throw new Error(`GitHub returned an invalid source file for ${target}; sync stopped.`);
  }

  const encodedContent = remote.content.replace(/\s/g, "");
  const content = Buffer.from(encodedContent, "base64");
  if (content.toString("base64") !== encodedContent || content.length > MAX_SOURCE_BYTES) {
    throw new Error(`GitHub returned invalid or oversized source content for ${target}; sync stopped.`);
  }
  return content;
}

async function findChangedFiles(token, files) {
  const changedFiles = [];
  for (const file of files) {
    const remoteContent = await readRemoteSourceFile(token, file.target);
    if (remoteContent === null || !remoteContent.equals(file.content)) {
      changedFiles.push(file);
    }
  }
  return changedFiles;
}

function parseArguments(args) {
  if (args.length === 0) return { dryRun: false };
  if (args.length === 1 && args[0] === "--dry-run") return { dryRun: true };
  throw new Error("Usage: node ./sync-public-source.mjs [--dry-run].");
}

async function syncSource({ dryRun }) {
  const token = getToken();
  const files = readSourceFiles();
  const ref = await githubRequest(token, `/git/ref/heads/${BRANCH}`);
  const parentSha = requireSha(ref?.object?.sha, "main branch commit");

  const changedFiles = await findChangedFiles(token, files);
  if (changedFiles.length === 0) {
    if (dryRun) {
      console.log(
        `Dry run: all ${files.length} allowlisted source files already match ${OWNER}/${REPOSITORY}@${BRANCH}; no changes would be published and no commit was created.`,
      );
      return;
    }
    console.log(`All ${files.length} allowlisted source files already match ${OWNER}/${REPOSITORY}@${BRANCH}; no commit created.`);
    return;
  }

  if (dryRun) {
    console.log(
      `Dry run: ${changedFiles.length} allowlisted source files would be published to ${OWNER}/${REPOSITORY}@${BRANCH}; no GitHub changes were made.`,
    );
    console.log("Changed files:");
    for (const { target } of changedFiles) {
      console.log(`- ${target}`);
    }
    return;
  }

  const parentCommit = await githubRequest(token, `/git/commits/${parentSha}`);
  const baseTreeSha = requireSha(parentCommit?.tree?.sha, "base tree");
  const blobs = await Promise.all(changedFiles.map(async ({ content }) => {
    const blob = await githubRequest(token, "/git/blobs", "POST", {
      content: content.toString("base64"),
      encoding: "base64",
    });
    return requireSha(blob?.sha, "blob SHA");
  }));

  const tree = await githubRequest(token, "/git/trees", "POST", {
    base_tree: baseTreeSha,
    tree: changedFiles.map(({ target }, index) => ({
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

  console.log(`Synced ${changedFiles.length} changed allowlisted source files to ${OWNER}/${REPOSITORY}@${BRANCH}.`);
  console.log("Changed files:");
  for (const { target } of changedFiles) {
    console.log(`- ${target}`);
  }
  console.log(`Commit: ${commitSha}`);
}

try {
  const options = parseArguments(process.argv.slice(2));
  syncSource(options).catch((error) => {
    console.error(error instanceof Error ? error.message : "Source sync failed.");
    process.exitCode = 1;
  });
} catch (error) {
  console.error(error instanceof Error ? error.message : "Source sync failed.");
  process.exitCode = 2;
}
