import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { TextDecoder } from "node:util";
import { fileURLToPath } from "node:url";

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const HOOK_DIRECTORY = path.join(ROOT, "hooks");
const HOOK_FILE = path.join(HOOK_DIRECTORY, "pre-commit");
const SYNC_SCRIPT = path.join(ROOT, "sync-public-source.mjs");

function runGit(args, cwd) {
  const env = { ...process.env };
  delete env.GITHUB_TOKEN;
  const result = spawnSync("git", args, {
    cwd,
    encoding: null,
    timeout: 15_000,
    maxBuffer: 64 * 1024,
    env,
  });
  if (result.error || result.signal || result.status === null) {
    throw new Error("Could not run Git to inspect or update local hook settings.");
  }
  return { status: result.status, stdout: result.stdout ?? Buffer.alloc(0) };
}

function decodeGitOutput(output, message) {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(output).replace(/\r?\n$/, "");
  } catch {
    throw new Error(message);
  }
}

function readHookPathValues(scopeArgs, repoRoot) {
  const result = runGit(
    ["config", ...scopeArgs, "--get-all", "core.hooksPath"],
    repoRoot,
  );
  if (result.status === 1) return [];
  if (result.status !== 0) {
    throw new Error("Could not inspect the existing Git hooks configuration.");
  }
  const text = decodeGitOutput(
    result.stdout,
    "Could not safely read the existing Git hooks configuration.",
  );
  if (result.stdout.length === 0) return [""];
  return text.split(/\r?\n/);
}

function requireHookFile() {
  let hookInfo;
  try {
    hookInfo = fs.statSync(HOOK_FILE);
  } catch {
    throw new Error("The GitMesh pre-commit hook file is missing; no Git configuration was changed.");
  }
  if (!hookInfo.isFile() || (process.platform !== "win32" && (hookInfo.mode & 0o111) === 0)) {
    throw new Error(
      "The GitMesh pre-commit hook is not an executable file; no Git configuration was changed.",
    );
  }
}

function pathIsInsideRoot(repoRoot, targetPath) {
  const relativePath = path.relative(repoRoot, targetPath);
  return !path.isAbsolute(relativePath) &&
    relativePath !== ".." &&
    !relativePath.startsWith(`..${path.sep}`);
}

function existingHookGuidance(repoRoot, reason, sharedHooksPath = false) {
  const syncCommand = path.relative(repoRoot, SYNC_SCRIPT).split(path.sep).join("/");
  const quotedSyncCommand = `'${syncCommand.replaceAll("'", "'\\''")}'`;
  const integrationGuidance = sharedHooksPath
    ? `Use a repository-specific hook or wrapper that preserves the shared hook and also runs ` +
      `node ${quotedSyncCommand} --check-staged-credentials.`
    : `Add this command to your existing pre-commit hook: ` +
      `node ${quotedSyncCommand} --check-staged-credentials`;
  return new Error(
    `${reason} No Git configuration was changed. ${integrationGuidance}`,
  );
}

function inspectDefaultHooks(repoRoot) {
  const result = runGit(["rev-parse", "--git-path", "hooks"], repoRoot);
  if (result.status !== 0) {
    throw new Error("Could not inspect Git's default hooks directory; no Git configuration was changed.");
  }
  const hooksPathText = decodeGitOutput(
    result.stdout,
    "Could not safely inspect Git's default hooks directory; no Git configuration was changed.",
  );
  const hooksPath = path.resolve(repoRoot, hooksPathText);
  let entries;
  try {
    entries = fs.readdirSync(hooksPath);
  } catch (error) {
    if (error?.code === "ENOENT") return;
    throw new Error(
      "Could not inspect Git's default hooks directory; no Git configuration was changed.",
    );
  }
  if (entries.some((entry) => !entry.endsWith(".sample"))) {
    throw existingHookGuidance(
      repoRoot,
      "Custom files already exist in Git's default hooks directory.",
    );
  }
}

function refuseSharedWorktreeSettings(repoRoot) {
  const gitDirResult = runGit(["rev-parse", "--absolute-git-dir"], repoRoot);
  const commonDirResult = runGit(["rev-parse", "--git-common-dir"], repoRoot);
  if (gitDirResult.status !== 0 || commonDirResult.status !== 0) {
    throw new Error("Could not determine the Git worktree scope; no Git configuration was changed.");
  }
  const gitDir = path.resolve(repoRoot, decodeGitOutput(
    gitDirResult.stdout,
    "Could not determine the Git worktree scope; no Git configuration was changed.",
  ));
  const commonDir = path.resolve(repoRoot, decodeGitOutput(
    commonDirResult.stdout,
    "Could not determine the Git worktree scope; no Git configuration was changed.",
  ));
  if (gitDir !== commonDir) {
    const syncCommand = path.relative(repoRoot, SYNC_SCRIPT).split(path.sep).join("/");
    const quotedSyncCommand = `'${syncCommand.replaceAll("'", "'\\''")}'`;
    throw new Error(
      "This is a linked Git worktree, so repository-local hook settings could affect other worktrees. " +
      "No Git configuration was changed. Use a hook configuration scoped to this worktree and run " +
      `node ${quotedSyncCommand} --check-staged-credentials there.`,
    );
  }
}

function installHook() {
  requireHookFile();
  const rootResult = runGit(["rev-parse", "--show-toplevel"], ROOT);
  if (rootResult.status !== 0) {
    throw new Error("Run this setup from inside a Git working tree; no Git configuration was changed.");
  }
  const rootText = decodeGitOutput(
    rootResult.stdout,
    "Could not safely locate the Git working tree; no Git configuration was changed.",
  );
  if (!rootText) {
    throw new Error("Could not locate the Git working tree; no Git configuration was changed.");
  }
  const repoRoot = path.resolve(rootText);
  if (!pathIsInsideRoot(repoRoot, HOOK_DIRECTORY) || !pathIsInsideRoot(repoRoot, SYNC_SCRIPT)) {
    throw new Error(
      "The GitMesh hook files are outside this Git working tree; no Git configuration was changed.",
    );
  }
  const desiredHooksPath = path.relative(repoRoot, HOOK_DIRECTORY).split(path.sep).join("/");
  const localValues = readHookPathValues(["--local"], repoRoot);
  if (localValues.length > 0) {
    if (
      localValues.length === 1 &&
      localValues[0] &&
      path.resolve(repoRoot, localValues[0]) === path.resolve(repoRoot, desiredHooksPath)
    ) {
      console.log("The GitMesh pre-commit check is already enabled for this repository.");
      return;
    }
    throw existingHookGuidance(repoRoot, "A repository-local Git hooks path is already configured.");
  }

  const effectiveValues = readHookPathValues([], repoRoot);
  if (effectiveValues.length > 0) {
    throw existingHookGuidance(
      repoRoot,
      "A Git hooks path is configured outside this repository.",
      true,
    );
  }
  refuseSharedWorktreeSettings(repoRoot);
  inspectDefaultHooks(repoRoot);

  const result = runGit(
    ["config", "--local", "core.hooksPath", desiredHooksPath],
    repoRoot,
  );
  if (result.status !== 0) {
    throw new Error("Could not enable the GitMesh pre-commit check; no global Git settings were changed.");
  }
  console.log(
    `Enabled the GitMesh pre-commit check for this repository only. ` +
    "To disable it, run: git config --local --unset core.hooksPath",
  );
}

try {
  installHook();
} catch (error) {
  const message = error instanceof Error ? error.message : "GitMesh hook setup failed safely.";
  console.error(message);
  process.exitCode = 1;
}
