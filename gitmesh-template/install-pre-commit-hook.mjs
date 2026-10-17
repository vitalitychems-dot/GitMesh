import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { TextDecoder } from "node:util";
import { fileURLToPath } from "node:url";

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const HOOK_DIRECTORY = path.join(ROOT, "hooks");
const HOOK_FILE = path.join(HOOK_DIRECTORY, "pre-commit");
const PRE_PUSH_HOOK_FILE = path.join(HOOK_DIRECTORY, "pre-push");
const SYNC_SCRIPT = path.join(ROOT, "sync-public-source.mjs");
const DISPATCH_DIRECTORY_NAME = "gitmesh-hooks";
const DISPATCH_MARKER_NAME = ".gitmesh-dispatch";
const DISPATCH_MARKER = "GitMesh hook dispatcher v1\n";
const DISPATCH_MANIFEST_HEADER = `${DISPATCH_MARKER}files-sha256-v1\n`;
const PRE_PUSH_DISPATCH_MARKER = "GitMesh pre-push dispatcher v1";

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

function parseOptions(args) {
  const acceptedOptions = new Set([
    "--worktree-local",
    "--chain-existing",
    "--status",
    "--disable-chain",
  ]);
  if (
    args.length <= acceptedOptions.size &&
    new Set(args).size === args.length &&
    args.every((argument) => acceptedOptions.has(argument)) &&
    (!args.includes("--status") || args.length === 1) &&
    (!args.includes("--disable-chain") || !args.includes("--chain-existing"))
  ) {
    return {
      worktreeLocal: args.includes("--worktree-local"),
      chainExisting: args.includes("--chain-existing"),
      status: args.includes("--status"),
      disableChain: args.includes("--disable-chain"),
    };
  }
  throw new Error(
    "Usage: node install-pre-commit-hook.mjs [--status | [--worktree-local] [--chain-existing] | [--worktree-local] --disable-chain]. No Git configuration was changed.",
  );
}

function isLinkedWorktree(repoRoot) {
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
  return gitDir !== commonDir;
}

function shellQuote(value) {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function samePath(left, right) {
  const resolve = candidate => {
    try {
      return fs.realpathSync(candidate);
    } catch {
      return path.resolve(candidate);
    }
  };
  return resolve(left) === resolve(right);
}

function effectiveHooksDirectory(repoRoot) {
  const configuredValues = readHookPathValues([], repoRoot);
  let configuredPath;
  if (configuredValues.length > 0) {
    const result = runGit(
      ["config", "--path", "--get", "core.hooksPath"],
      repoRoot,
    );
    if (result.status !== 0) {
      throw new Error("Could not safely locate the active Git hooks directory; no Git configuration was changed.");
    }
    configuredPath = decodeGitOutput(
      result.stdout,
      "Could not safely locate the active Git hooks directory; no Git configuration was changed.",
    );
  } else {
    const result = runGit(["rev-parse", "--git-path", "hooks"], repoRoot);
    if (result.status !== 0) {
      throw new Error("Could not safely locate Git's default hooks directory; no Git configuration was changed.");
    }
    configuredPath = decodeGitOutput(
      result.stdout,
      "Could not safely locate Git's default hooks directory; no Git configuration was changed.",
    );
  }
  if (!configuredPath || /[\r\n\0]/.test(configuredPath)) {
    throw new Error("The active Git hooks directory is not a usable path; no Git configuration was changed.");
  }
  return path.resolve(repoRoot, configuredPath);
}

function hookPathSettingScopeFallback(repoRoot, activeHooksDirectory, fallbackValue) {
  const scopes = [];
  if (worktreeConfigIsEnabled(repoRoot)) {
    scopes.push(["--worktree", "worktree"]);
  }
  scopes.push(
    ["--local", "local"],
    ["--global", "global"],
    ["--system", "system"],
  );

  for (const [scopeFlag, scopeName] of scopes) {
    const rawValues = readHookPathValues([scopeFlag], repoRoot);
    if (rawValues.length === 0) continue;
    const result = runGit(
      ["config", scopeFlag, "--path", "--get", "core.hooksPath"],
      repoRoot,
    );
    if (result.status !== 0) {
      throw new Error("Could not safely determine the active Git hook scope.");
    }
    const scopedPath = decodeGitOutput(
      result.stdout,
      "Could not safely determine the active Git hook scope.",
    );
    if (samePath(path.resolve(repoRoot, scopedPath), activeHooksDirectory)) {
      return { scope: scopeName, value: rawValues.at(-1) };
    }
  }
  return { scope: "unknown", value: fallbackValue };
}

function activeHookPathSetting(repoRoot, activeHooksDirectory) {
  const values = readHookPathValues([], repoRoot);
  if (values.length === 0) return { scope: "default", value: null };

  const result = runGit(
    ["config", "--show-scope", "--get", "core.hooksPath"],
    repoRoot,
  );
  if (result.status === 129) {
    return hookPathSettingScopeFallback(
      repoRoot,
      activeHooksDirectory,
      values.at(-1),
    );
  }
  if (result.status !== 0) {
    throw new Error("Could not safely determine the active Git hook scope.");
  }
  const text = decodeGitOutput(
    result.stdout,
    "Could not safely determine the active Git hook scope.",
  );
  const separator = text.indexOf("\t");
  if (separator < 1) {
    throw new Error("Could not safely determine the active Git hook scope.");
  }
  const scope = text.slice(0, separator);
  const value = text.slice(separator + 1);
  if (!value || /[\r\n\0]/.test(value)) {
    throw new Error("The active Git hook setting is not a usable path.");
  }
  return { scope, value };
}

function absoluteGitDirectory(repoRoot) {
  const result = runGit(["rev-parse", "--absolute-git-dir"], repoRoot);
  if (result.status !== 0) {
    throw new Error("Could not safely locate this worktree's Git directory; no Git configuration was changed.");
  }
  const gitDirectory = decodeGitOutput(
    result.stdout,
    "Could not safely locate this worktree's Git directory; no Git configuration was changed.",
  );
  if (!path.isAbsolute(gitDirectory) || /[\r\n\0]/.test(gitDirectory)) {
    throw new Error("Could not safely locate this worktree's Git directory; no Git configuration was changed.");
  }
  return gitDirectory;
}

function inspectExecutableHook(hookPath) {
  try {
    const hookInfo = fs.statSync(hookPath);
    return {
      exists: true,
      executable: hookInfo.isFile() &&
        (process.platform === "win32" || (hookInfo.mode & 0o111) !== 0),
    };
  } catch (error) {
    if (error?.code === "ENOENT" || error?.code === "ENOTDIR") {
      return { exists: false, executable: false };
    }
    throw new Error("Could not safely inspect existing Git hooks; no Git configuration was changed.");
  }
}

function isExecutableFile(filePath) {
  try {
    const hookInfo = fs.statSync(filePath);
    return hookInfo.isFile() &&
      (process.platform === "win32" || (hookInfo.mode & 0o111) !== 0);
  } catch {
    return false;
  }
}

function isCopyOfGitMeshHook(hookPath) {
  if (!isExecutableFile(hookPath) || !isExecutableFile(HOOK_FILE)) return false;
  if (samePath(hookPath, HOOK_FILE)) return true;
  try {
    return fs.readFileSync(hookPath).equals(fs.readFileSync(HOOK_FILE));
  } catch {
    return false;
  }
}

function manuallyRunsGitMeshCheck(hookPath) {
  if (!isExecutableFile(hookPath)) return false;
  try {
    const contents = fs.readFileSync(hookPath, "utf8");
    return contents.includes(path.basename(SYNC_SCRIPT)) &&
      contents.includes("--check-staged-credentials");
  } catch {
    return false;
  }
}

function describeHookScope(scope, repoRoot) {
  if (scope === "worktree") return "worktree-local";
  if (scope === "local") {
    return isLinkedWorktree(repoRoot)
      ? "shared (repository-local across linked worktrees)"
      : "repository-local";
  }
  if (scope === "global" || scope === "system") return `shared (${scope})`;
  if (scope === "command") return "shared (temporary command-level setting)";
  if (scope === "default") {
    return isLinkedWorktree(repoRoot)
      ? "shared (Git default hooks directory)"
      : "repository-local (Git default hooks directory)";
  }
  return `shared (${scope} Git configuration scope)`;
}

function chainedDisableCommand(repoRoot, worktreeLocal) {
  const installerPath = path.relative(
    repoRoot,
    fileURLToPath(import.meta.url),
  ).split(path.sep).join("/");
  if (
    !installerPath ||
    path.isAbsolute(installerPath) ||
    !pathIsInsideRoot(repoRoot, path.resolve(repoRoot, installerPath))
  ) {
    return null;
  }
  const scopeOption = worktreeLocal ? "--worktree-local " : "";
  return `node ${shellQuote(installerPath)} ${scopeOption}--disable-chain`;
}

function hookSettingDisableCommand(setting, hookPath, copiedHook, repoRoot, managedDispatcher) {
  if (copiedHook || setting.scope === "default") {
    return `rm -- ${shellQuote(hookPath)}`;
  }
  if (
    managedDispatcher &&
    (setting.scope === "local" || setting.scope === "worktree")
  ) {
    const expectedDispatchDirectory = path.join(
      absoluteGitDirectory(repoRoot),
      DISPATCH_DIRECTORY_NAME,
    );
    const localScopeIsWorktreeShared =
      setting.scope === "local" && isLinkedWorktree(repoRoot);
    if (
      !localScopeIsWorktreeShared &&
      samePath(path.dirname(hookPath), expectedDispatchDirectory)
    ) {
      return chainedDisableCommand(repoRoot, setting.scope === "worktree");
    }
  }
  const scopeFlag = {
    worktree: "--worktree",
    local: "--local",
    global: "--global",
    system: "--system",
  }[setting.scope];
  if (!scopeFlag || !setting.value) return null;
  const valuePattern = `^${escapeRegex(setting.value)}$`;
  return `git config ${scopeFlag} --unset core.hooksPath ${shellQuote(valuePattern)}`;
}

function reportHookStatus(repoRoot) {
  const activeHooksDirectory = effectiveHooksDirectory(repoRoot);
  const setting = activeHookPathSetting(repoRoot, activeHooksDirectory);
  const preCommitPath = path.join(activeHooksDirectory, "pre-commit");
  const pointsToGitMeshDirectory = samePath(activeHooksDirectory, HOOK_DIRECTORY);
  const managedDispatcher = dispatcherIsManaged(activeHooksDirectory) &&
    isExecutableFile(preCommitPath);
  const copiedHook = !pointsToGitMeshDirectory && isCopyOfGitMeshHook(preCommitPath);
  const manualIntegration = !pointsToGitMeshDirectory && !copiedHook && !managedDispatcher &&
    manuallyRunsGitMeshCheck(preCommitPath);
  const active = managedDispatcher || copiedHook || (
    pointsToGitMeshDirectory && isExecutableFile(HOOK_FILE)
  ) || manualIntegration;
  const configuredButUnavailable = !active && (
    pointsToGitMeshDirectory ||
    (dispatcherIsManaged(activeHooksDirectory) && !isExecutableFile(preCommitPath))
  );

  if (active) {
    console.log("GitMesh pre-commit check: active");
    console.log(`Scope: ${describeHookScope(setting.scope, repoRoot)}`);
    console.log(`Active hooks directory: ${activeHooksDirectory}`);
    if (manualIntegration) {
      console.log(`GitMesh check found in the existing hook: ${preCommitPath}`);
      console.log(
        `To disable only the GitMesh check, remove its command from ${shellQuote(preCommitPath)} and keep the other hook commands.`,
      );
      return;
    }
    const disableCommand = hookSettingDisableCommand(
      setting,
      preCommitPath,
      copiedHook,
      repoRoot,
      managedDispatcher,
    );
    if (disableCommand) {
      console.log(`To disable this GitMesh setup, run: ${disableCommand}`);
    } else {
      console.log(
        "This GitMesh hook is active through a temporary or unclassified Git setting; no persistent disable command is available.",
      );
    }
    return;
  }

  console.log(
    configuredButUnavailable
      ? "GitMesh pre-commit check: configured but unavailable"
      : "GitMesh pre-commit check: inactive",
  );
  console.log("Scope: inactive");
  if (setting.scope !== "default") {
    console.log(
      `Git's active hooks path is ${describeHookScope(setting.scope, repoRoot)} at ${activeHooksDirectory}, but it does not contain a recognized GitMesh hook.`,
    );
    if (configuredButUnavailable) {
      const disableCommand = hookSettingDisableCommand(
        setting,
        preCommitPath,
        false,
        repoRoot,
        false,
      );
      if (disableCommand) {
        console.log(`To remove this inactive GitMesh setting, run: ${disableCommand}`);
      } else {
        console.log("No persistent disable command is available for this hook setting.");
      }
    } else {
      console.log(
        "No GitMesh-specific disable command is available; the existing hook setting was left untouched.",
      );
    }
  } else if (configuredButUnavailable) {
    console.log(
      `The configured GitMesh hooks directory has no executable pre-commit hook at ${preCommitPath}.`,
    );
    const disableCommand = hookSettingDisableCommand(
      setting,
      preCommitPath,
      false,
      repoRoot,
      false,
    );
    if (disableCommand) {
      console.log(`To remove this inactive GitMesh setting, run: ${disableCommand}`);
    }
  } else {
    console.log("No GitMesh hook was found in Git's default hooks directory.");
    console.log("No GitMesh-specific disable command is needed.");
  }
}

function writeExecutableHook(filePath, contents) {
  fs.writeFileSync(filePath, contents, { mode: 0o755, flag: "wx" });
  fs.chmodSync(filePath, 0o755);
}

function createPassThroughHook(originalHookPath) {
  return `#!/bin/sh\n# ${DISPATCH_MARKER.trim()}\nexec ${shellQuote(originalHookPath)} "$@"\n`;
}

function createPreCommitDispatcher(originalHookPath) {
  const lines = ["#!/bin/sh", `# ${DISPATCH_MARKER.trim()}`, "set -u"];
  if (originalHookPath) {
    lines.push("hook_status=0");
    lines.push(`${shellQuote(originalHookPath)} "$@" || hook_status=$?`);
    lines.push('if [ "$hook_status" -ne 0 ]; then');
    lines.push('  exit "$hook_status"');
    lines.push("fi");
  }
  lines.push(`exec ${shellQuote(HOOK_FILE)} "$@"`);
  return `${lines.join("\n")}\n`;
}

function createPrePushDispatcher(originalHookPath) {
  const lines = [
    "#!/bin/sh",
    `# ${DISPATCH_MARKER.trim()}`,
    `# ${PRE_PUSH_DISPATCH_MARKER}`,
    "set -u",
    "umask 077",
    'hook_input=$(mktemp "${TMPDIR:-/tmp}/gitmesh-pre-push.XXXXXX") || {',
    '  printf \'%s\\n\' "GitMesh could not safely preserve pre-push ref data; push stopped." >&2',
    "  exit 1",
    "}",
    'cleanup() { rm -f "$hook_input"; }',
    "trap cleanup EXIT",
    "trap 'exit 129' HUP",
    "trap 'exit 130' INT",
    "trap 'exit 143' TERM",
    'if ! cat > "$hook_input"; then',
    '  printf \'%s\\n\' "GitMesh could not safely read pre-push ref data; push stopped." >&2',
    "  exit 1",
    "fi",
  ];
  if (originalHookPath) {
    lines.push("hook_status=0");
    lines.push(`${shellQuote(originalHookPath)} "$@" < "$hook_input" || hook_status=$?`);
    lines.push('if [ "$hook_status" -ne 0 ]; then');
    lines.push('  exit "$hook_status"');
    lines.push("fi");
  }
  lines.push("hook_status=0");
  lines.push(`${shellQuote(PRE_PUSH_HOOK_FILE)} "$@" < "$hook_input" || hook_status=$?`);
  lines.push('exit "$hook_status"');
  return `${lines.join("\n")}\n`;
}

function hasCurrentPrePushDispatcher(dispatchDirectory) {
  const hookPath = path.join(dispatchDirectory, "pre-push");
  try {
    const hookStatus = inspectExecutableHook(hookPath);
    if (!hookStatus.executable) return false;
    const contents = fs.readFileSync(hookPath, "utf8");
    return contents.startsWith(
      `#!/bin/sh\n# ${DISPATCH_MARKER.trim()}\n# ${PRE_PUSH_DISPATCH_MARKER}\n`,
    );
  } catch {
    return false;
  }
}

function upgradeManagedPrePushDispatcher(dispatchDirectory) {
  const hookPath = path.join(dispatchDirectory, "pre-push");
  const existingStatus = inspectExecutableHook(hookPath);
  let originalPrePushPath = null;
  if (existingStatus.exists) {
    if (!existingStatus.executable) {
      throw new Error(
        "Could not safely update the existing GitMesh pre-push dispatcher; no Git configuration was changed.",
      );
    }
    let existingContents;
    try {
      existingContents = fs.readFileSync(hookPath, "utf8");
    } catch {
      throw new Error(
        "Could not safely update the existing GitMesh pre-push dispatcher; no Git configuration was changed.",
      );
    }
    const backupPath = path.join(dispatchDirectory, "pre-push.gitmesh-original");
    let backupStatus;
    try {
      backupStatus = inspectExecutableHook(backupPath);
    } catch {
      throw new Error(
        "Could not safely update the existing GitMesh pre-push dispatcher; no Git configuration was changed.",
      );
    }
    if (backupStatus.exists) {
      let backupContents;
      try {
        backupContents = fs.readFileSync(backupPath, "utf8");
      } catch {
        throw new Error(
          "Could not safely update the existing GitMesh pre-push dispatcher; no Git configuration was changed.",
        );
      }
      if (!backupStatus.executable || backupContents !== existingContents) {
        throw new Error(
          "Could not safely preserve the existing pre-push hook; no Git configuration was changed.",
        );
      }
    } else {
      try {
        writeExecutableHook(backupPath, existingContents);
      } catch {
        throw new Error(
          "Could not safely preserve the existing pre-push hook; no Git configuration was changed.",
        );
      }
    }
    originalPrePushPath = backupPath;
  }

  let temporaryDirectory;
  try {
    const gitMeshHookStatus = inspectExecutableHook(PRE_PUSH_HOOK_FILE);
    if (!gitMeshHookStatus.executable) {
      throw new Error("missing-hook");
    }
    temporaryDirectory = fs.mkdtempSync(
      path.join(dispatchDirectory, ".gitmesh-pre-push-"),
    );
    const temporaryHookPath = path.join(temporaryDirectory, "pre-push");
    writeExecutableHook(
      temporaryHookPath,
      createPrePushDispatcher(originalPrePushPath),
    );
    fs.renameSync(temporaryHookPath, hookPath);
    fs.rmSync(temporaryDirectory, { recursive: true, force: true });
    writeDispatcherManifest(dispatchDirectory);
  } catch {
    if (temporaryDirectory) {
      try {
        fs.rmSync(temporaryDirectory, { recursive: true, force: true });
      } catch {
        // Keep filesystem diagnostics out of installer output.
      }
    }
    throw new Error(
      "Could not safely add the GitMesh pre-push check to the existing dispatcher; no Git configuration was changed.",
    );
  }
}

function writeDispatcherManifest(dispatchDirectory) {
  const hookEntries = fs.readdirSync(dispatchDirectory)
    .filter((entry) => entry !== DISPATCH_MARKER_NAME)
    .sort();
  if (
    !hookEntries.includes("pre-commit") ||
    !hookEntries.includes("pre-push") ||
    hookEntries.some((entry) => !/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(entry))
  ) {
    throw new Error("Could not safely record the GitMesh dispatcher file set.");
  }
  const manifestEntries = hookEntries.map((entry) => {
    const hookPath = path.join(dispatchDirectory, entry);
    const hookInfo = fs.lstatSync(hookPath);
    if (!hookInfo.isFile() || (process.platform !== "win32" && (hookInfo.mode & 0o111) === 0)) {
      throw new Error("Could not safely record the GitMesh dispatcher file set.");
    }
    const contents = fs.readFileSync(hookPath);
    const digest = createHash("sha256").update(contents).digest("hex");
    return `${entry}\t${digest}`;
  });
  const markerPath = path.join(dispatchDirectory, DISPATCH_MARKER_NAME);
  const temporaryMarkerPath = `${markerPath}.tmp`;
  let temporaryMarkerCreated = false;
  try {
    fs.writeFileSync(
      temporaryMarkerPath,
      `${DISPATCH_MANIFEST_HEADER}${manifestEntries.join("\n")}\n`,
      { flag: "wx", mode: 0o600 },
    );
    temporaryMarkerCreated = true;
    fs.renameSync(temporaryMarkerPath, markerPath);
  } catch {
    if (temporaryMarkerCreated) {
      try {
        fs.rmSync(temporaryMarkerPath, { force: true });
      } catch {
        // Keep filesystem diagnostics out of installer output.
      }
    }
    throw new Error("Could not safely record the GitMesh dispatcher file set.");
  }
}

function dispatcherIsManaged(dispatchDirectory) {
  try {
    const directoryInfo = fs.lstatSync(dispatchDirectory);
    if (!directoryInfo.isDirectory()) return false;
    const entries = fs.readdirSync(dispatchDirectory);
    if (!entries.includes(DISPATCH_MARKER_NAME)) return false;
    const markerPath = path.join(dispatchDirectory, DISPATCH_MARKER_NAME);
    const markerInfo = fs.lstatSync(markerPath);
    if (!markerInfo.isFile() || markerInfo.size > 1024 * 1024) {
      return false;
    }
    const markerContents = fs.readFileSync(markerPath, "utf8");
    let expectedHashes = null;
    if (markerContents !== DISPATCH_MARKER) {
      if (
        !markerContents.startsWith(DISPATCH_MANIFEST_HEADER) ||
        !markerContents.endsWith("\n")
      ) {
        return false;
      }
      const manifestLines = markerContents
        .slice(DISPATCH_MANIFEST_HEADER.length, -1)
        .split("\n");
      expectedHashes = new Map();
      let priorName = "";
      for (const line of manifestLines) {
        const match = /^([A-Za-z0-9][A-Za-z0-9._-]*)\t([a-f0-9]{64})$/.exec(line);
        if (!match || match[1] <= priorName) return false;
        priorName = match[1];
        expectedHashes.set(match[1], match[2]);
      }
    }
    const hookEntries = entries.filter((entry) => entry !== DISPATCH_MARKER_NAME).sort();
    if (
      !hookEntries.includes("pre-commit") ||
      !hookEntries.includes("pre-push") ||
      (expectedHashes !== null &&
        (hookEntries.length !== expectedHashes.size ||
          hookEntries.some((entry) => !expectedHashes.has(entry))))
    ) {
      return false;
    }
    return hookEntries.every((entry) => {
      if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(entry)) return false;
      const hookInfo = fs.lstatSync(path.join(dispatchDirectory, entry));
      if (
        !hookInfo.isFile() ||
        hookInfo.size > 1024 * 1024 ||
        (process.platform !== "win32" && (hookInfo.mode & 0o111) === 0)
      ) {
        return false;
      }
      const contents = fs.readFileSync(path.join(dispatchDirectory, entry));
      if (!contents.toString("utf8").startsWith(
        `#!/bin/sh\n# ${DISPATCH_MARKER.trim()}\n`,
      )) {
        return false;
      }
      if (expectedHashes === null) return true;
      return createHash("sha256").update(contents).digest("hex") ===
        expectedHashes.get(entry);
    });
  } catch {
    return false;
  }
}

function createDispatcherDirectory(existingHooksDirectory, gitDirectory) {
  const dispatchDirectory = path.join(gitDirectory, DISPATCH_DIRECTORY_NAME);
  const temporaryDirectoryPrefix = path.join(gitDirectory, ".gitmesh-hooks-");
  let temporaryDirectory;
  try {
    temporaryDirectory = fs.mkdtempSync(temporaryDirectoryPrefix);
    let originalPreCommitPath = null;
    let originalPrePushPath = null;
    let entries;
    try {
      entries = fs.readdirSync(existingHooksDirectory);
    } catch (error) {
      if (error?.code === "ENOENT") {
        entries = [];
      } else {
        throw new Error("Could not safely inspect existing Git hooks; no Git configuration was changed.");
      }
    }

    for (const entry of entries) {
      if (
        entry === "pre-commit" ||
        entry === "pre-push" ||
        entry.endsWith(".sample") ||
        !/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(entry)
      ) {
        continue;
      }
      const originalHookPath = path.join(existingHooksDirectory, entry);
      let hookStatus;
      try {
        hookStatus = inspectExecutableHook(originalHookPath);
      } catch {
        throw new Error("Could not safely inspect existing Git hooks; no Git configuration was changed.");
      }
      if (hookStatus.executable) {
        writeExecutableHook(
          path.join(temporaryDirectory, entry),
          createPassThroughHook(originalHookPath),
        );
      }
    }

    const existingPreCommitPath = path.join(existingHooksDirectory, "pre-commit");
    let preCommitStatus;
    try {
      preCommitStatus = inspectExecutableHook(existingPreCommitPath);
    } catch {
      throw new Error("Could not safely inspect the existing pre-commit hook; no Git configuration was changed.");
    }
    if (preCommitStatus.exists && !preCommitStatus.executable) {
      throw new Error(
        "The existing pre-commit hook is not an executable file. Make it executable or leave the hook settings unchanged; no Git configuration was changed.",
      );
    }
    if (preCommitStatus.executable) {
      if (samePath(existingPreCommitPath, HOOK_FILE)) {
        throw new Error(
          "The active pre-commit hook already points to GitMesh. No dispatcher or Git configuration was changed.",
        );
      }
      originalPreCommitPath = existingPreCommitPath;
    }
    const existingPrePushPath = path.join(existingHooksDirectory, "pre-push");
    let prePushStatus;
    try {
      prePushStatus = inspectExecutableHook(existingPrePushPath);
    } catch {
      throw new Error("Could not safely inspect the existing pre-push hook; no Git configuration was changed.");
    }
    if (prePushStatus.exists && !prePushStatus.executable) {
      throw new Error(
        "The existing pre-push hook is not an executable file. Make it executable or leave the hook settings unchanged; no Git configuration was changed.",
      );
    }
    if (prePushStatus.executable) {
      originalPrePushPath = existingPrePushPath;
    }
    let gitMeshPrePushStatus;
    try {
      gitMeshPrePushStatus = inspectExecutableHook(PRE_PUSH_HOOK_FILE);
    } catch {
      throw new Error("Could not safely inspect the GitMesh pre-push hook; no Git configuration was changed.");
    }
    if (!gitMeshPrePushStatus.executable) {
      throw new Error(
        "The GitMesh pre-push hook is missing or is not executable; no Git configuration was changed.",
      );
    }
    writeExecutableHook(
      path.join(temporaryDirectory, "pre-commit"),
      createPreCommitDispatcher(originalPreCommitPath),
    );
    writeExecutableHook(
      path.join(temporaryDirectory, "pre-push"),
      createPrePushDispatcher(originalPrePushPath),
    );
    writeDispatcherManifest(temporaryDirectory);
    fs.renameSync(temporaryDirectory, dispatchDirectory);
    return dispatchDirectory;
  } catch (error) {
    if (temporaryDirectory) {
      try {
        fs.rmSync(temporaryDirectory, { recursive: true, force: true });
      } catch {
        // Keep filesystem diagnostics out of installer output.
      }
    }
    if (error instanceof Error && error.message.startsWith("The existing pre-commit hook")) {
      throw error;
    }
    if (error instanceof Error && error.message.startsWith("The active pre-commit hook")) {
      throw error;
    }
    throw new Error(
      "Could not safely create the GitMesh hook dispatcher; no Git configuration was changed.",
    );
  }
}

function installChainedHook(repoRoot, worktreeLocal) {
  const scopeArgs = worktreeLocal ? ["--worktree"] : ["--local"];
  const scopeLabel = worktreeLocal ? "this worktree only" : "this repository only";
  const disableCommand = chainedDisableCommand(repoRoot, worktreeLocal);
  if (!disableCommand) {
    throw new Error(
      "Could not safely construct the GitMesh chaining disable command; no Git configuration was changed.",
    );
  }
  if (worktreeLocal) {
    if (!isLinkedWorktree(repoRoot)) {
      throw new Error(
        "The --worktree-local option is only available in a linked Git worktree. No Git configuration was changed.",
      );
    }
    if (!worktreeConfigIsEnabled(repoRoot)) {
      throw new Error(
        "Worktree-local setup requires extensions.worktreeConfig=true in this repository. " +
        "The setting is not enabled. No Git configuration was changed.",
      );
    }
  } else {
    refuseSharedWorktreeSettings(repoRoot);
  }

  const existingHooksDirectory = effectiveHooksDirectory(repoRoot);
  const gitDirectory = absoluteGitDirectory(repoRoot);
  const dispatchDirectory = path.join(gitDirectory, DISPATCH_DIRECTORY_NAME);
  if (samePath(existingHooksDirectory, HOOK_DIRECTORY)) {
    console.log(
      worktreeLocal
        ? "The GitMesh pre-commit check is already enabled for this worktree."
        : "The GitMesh pre-commit check is already enabled for this repository.",
    );
    return;
  }
  if (samePath(existingHooksDirectory, dispatchDirectory)) {
    if (dispatcherIsManaged(dispatchDirectory)) {
      if (!hasCurrentPrePushDispatcher(dispatchDirectory)) {
        upgradeManagedPrePushDispatcher(dispatchDirectory);
        console.log(
          worktreeLocal
            ? "Updated the existing GitMesh dispatcher for this worktree with the optional pre-push check."
            : "Updated the existing GitMesh dispatcher for this repository with the optional pre-push check.",
        );
        return;
      }
      console.log(
        worktreeLocal
          ? "The GitMesh dispatcher is already enabled for this worktree."
          : "The GitMesh dispatcher is already enabled for this repository.",
      );
      return;
    }
    throw new Error(
      "An unmanaged Git hooks directory already occupies the dispatcher path; no Git configuration was changed.",
    );
  }
  try {
    fs.lstatSync(dispatchDirectory);
    if (!dispatcherIsManaged(dispatchDirectory)) {
      throw new Error(
        "An existing file or directory prevents creation of the GitMesh dispatcher; no Git configuration was changed.",
      );
    }
    fs.rmSync(dispatchDirectory, { recursive: true, force: true });
  } catch (error) {
    if (error?.code !== "ENOENT") {
      if (error instanceof Error &&
          error.message.startsWith("An existing file or directory")) {
        throw error;
      }
      throw new Error(
        "Could not safely prepare the GitMesh dispatcher directory; no Git configuration was changed.",
      );
    }
  }

  const createdDirectory = createDispatcherDirectory(
    existingHooksDirectory,
    gitDirectory,
  );
  const result = runGit(
    ["config", ...scopeArgs, "--add", "core.hooksPath", createdDirectory],
    repoRoot,
  );
  if (result.status !== 0) {
    try {
      fs.rmSync(createdDirectory, { recursive: true, force: true });
    } catch {
      // Keep filesystem diagnostics out of installer output.
    }
    throw new Error(
      `Could not enable the GitMesh dispatcher for ${scopeLabel}; no global or sibling-worktree settings were changed.`,
    );
  }

  console.log(
    `Enabled the GitMesh dispatcher for ${scopeLabel}. The existing pre-commit hook, if present, runs first, then GitMesh; other executable hooks are forwarded to their original files. ` +
    `The existing pre-push hook, if present, also runs before GitMesh's optional pre-push check. ` +
    `No global or sibling-worktree settings were changed. To disable it, run: ${disableCommand}`,
  );
}

function disableChainedHook(repoRoot, worktreeLocal) {
  const scopeArgs = worktreeLocal ? ["--worktree"] : ["--local"];
  const scopeLabel = worktreeLocal ? "this worktree" : "this repository";
  if (worktreeLocal) {
    if (!isLinkedWorktree(repoRoot)) {
      throw new Error(
        "The --worktree-local option is only available in a linked Git worktree. No Git configuration or files were changed.",
      );
    }
    if (!worktreeConfigIsEnabled(repoRoot)) {
      throw new Error(
        "Worktree-local cleanup requires extensions.worktreeConfig=true in this repository. " +
        "No Git configuration or files were changed.",
      );
    }
  } else {
    refuseSharedWorktreeSettings(repoRoot);
  }

  const dispatchDirectory = path.join(
    absoluteGitDirectory(repoRoot),
    DISPATCH_DIRECTORY_NAME,
  );
  const configuredValues = readHookPathValues(scopeArgs, repoRoot);
  const matchingIndexes = configuredValues
    .map((value, index) => {
      if (!value || /[\r\n\0]/.test(value)) return -1;
      return path.resolve(repoRoot, value) === dispatchDirectory ? index : -1;
    })
    .filter((index) => index >= 0);
  if (
    matchingIndexes.length !== 1 ||
    matchingIndexes[0] !== configuredValues.length - 1 ||
    !samePath(effectiveHooksDirectory(repoRoot), dispatchDirectory)
  ) {
    throw new Error(
      `Could not identify one active GitMesh dispatcher in the selected scope; no Git configuration or files were changed.`,
    );
  }
  if (!dispatcherIsManaged(dispatchDirectory)) {
    throw new Error(
      "Refusing to remove the GitMesh dispatcher because its marker or file set is missing or unexpected; no Git configuration or files were changed.",
    );
  }

  const selectedValue = configuredValues[matchingIndexes[0]];
  const removalPattern = `^${escapeRegex(selectedValue)}$`;
  const unsetResult = runGit(
    ["config", ...scopeArgs, "--unset", "core.hooksPath", removalPattern],
    repoRoot,
  );
  if (unsetResult.status !== 0) {
    throw new Error(
      `Could not remove the GitMesh dispatcher setting for ${scopeLabel}; no dispatcher files were removed.`,
    );
  }

  const remainingValues = readHookPathValues(scopeArgs, repoRoot);
  const expectedRemainingValues = configuredValues.filter(
    (_value, index) => index !== matchingIndexes[0],
  );
  if (
    remainingValues.length !== expectedRemainingValues.length ||
    remainingValues.some((value, index) => value !== expectedRemainingValues[index])
  ) {
    throw new Error(
      `The GitMesh dispatcher setting was removed for ${scopeLabel}, but the remaining settings could not be verified; dispatcher files were left in place.`,
    );
  }
  if (!dispatcherIsManaged(dispatchDirectory)) {
    throw new Error(
      `GitMesh chaining was disabled for ${scopeLabel}, but the dispatcher changed during cleanup; its files were left in place.`,
    );
  }
  try {
    fs.rmSync(dispatchDirectory, { recursive: true, force: false });
  } catch {
    throw new Error(
      `GitMesh chaining was disabled for ${scopeLabel}, but the verified dispatcher directory could not be removed.`,
    );
  }
  console.log(
    `Disabled GitMesh chaining for ${scopeLabel} and removed the verified dispatcher directory. Other configuration scopes and hooks were left unchanged.`,
  );
}

function worktreeConfigIsEnabled(repoRoot) {
  const result = runGit(
    ["config", "--bool", "--local", "--get", "extensions.worktreeConfig"],
    repoRoot,
  );
  if (result.status === 1) return false;
  if (result.status !== 0) {
    throw new Error(
      "Could not verify Git's worktree configuration support; no Git configuration was changed.",
    );
  }
  const value = decodeGitOutput(
    result.stdout,
    "Could not safely inspect Git's worktree configuration support; no Git configuration was changed.",
  );
  return value.toLowerCase() === "true";
}

function readWorktreeHookPathValues(repoRoot) {
  try {
    return readHookPathValues(["--worktree"], repoRoot);
  } catch {
    throw new Error(
      "Git could not safely inspect worktree-local hook settings. Confirm Git supports worktree configuration; no Git configuration was changed.",
    );
  }
}

function installWorktreeLocalHook(repoRoot, desiredHooksPath) {
  if (!isLinkedWorktree(repoRoot)) {
    throw new Error(
      "The --worktree-local option is only available in a linked Git worktree. No Git configuration was changed.",
    );
  }
  if (!worktreeConfigIsEnabled(repoRoot)) {
    throw new Error(
      "Worktree-local setup requires extensions.worktreeConfig=true in this repository. " +
      "The setting is not enabled. No Git configuration was changed.",
    );
  }

  const worktreeValues = readWorktreeHookPathValues(repoRoot);
  if (worktreeValues.length > 0) {
    if (
      worktreeValues.length === 1 &&
      worktreeValues[0] &&
      path.resolve(repoRoot, worktreeValues[0]) === path.resolve(repoRoot, desiredHooksPath)
    ) {
      console.log("The GitMesh pre-commit check is already enabled for this worktree.");
      return;
    }
    throw existingHookGuidance(
      repoRoot,
      "A worktree-local Git hooks path is already configured.",
    );
  }

  const localValues = readHookPathValues(["--local"], repoRoot);
  if (localValues.length > 0) {
    throw existingHookGuidance(
      repoRoot,
      "A repository-local Git hooks path is already configured.",
    );
  }
  const effectiveValues = readHookPathValues([], repoRoot);
  if (effectiveValues.length > 0) {
    throw existingHookGuidance(
      repoRoot,
      "A Git hooks path is configured outside this worktree.",
      true,
    );
  }

  inspectDefaultHooks(repoRoot);
  const result = runGit(
    ["config", "--worktree", "core.hooksPath", desiredHooksPath],
    repoRoot,
  );
  if (result.status !== 0) {
    throw new Error(
      "Could not enable the GitMesh pre-commit check for this worktree; no global Git settings were changed.",
    );
  }
  console.log(
    "Enabled the GitMesh pre-commit check for this worktree only. " +
    "To disable it, run: git config --worktree --unset core.hooksPath",
  );
}

function installHook(args = process.argv.slice(2)) {
  const { worktreeLocal, chainExisting, status, disableChain } = parseOptions(args);
  if (!status && !disableChain) requireHookFile();
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
  if (status) {
    reportHookStatus(repoRoot);
    return;
  }
  if (disableChain) {
    disableChainedHook(repoRoot, worktreeLocal);
    return;
  }
  const desiredHooksPath = path.relative(repoRoot, HOOK_DIRECTORY).split(path.sep).join("/");
  if (chainExisting) {
    installChainedHook(repoRoot, worktreeLocal);
    return;
  }
  if (worktreeLocal) {
    installWorktreeLocalHook(repoRoot, desiredHooksPath);
    return;
  }

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
