import { spawnSync } from "node:child_process";
import fs from "node:fs";
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
const EMBEDDED_CREDENTIAL_PATTERNS = [
  { id: "github-prefixed-token", pattern: /\bgh[pousr]_[A-Za-z0-9]{30,}\b/ },
  { id: "github-fine-grained-token", pattern: /\bgithub_pat_[A-Za-z0-9_]{30,}\b/ },
  { id: "gitlab-token", pattern: /\bglpat-[A-Za-z0-9_-]{20,}\b/ },
  { id: "npm-token", pattern: /\bnpm_[A-Za-z0-9]{30,}\b/ },
  { id: "slack-token", pattern: /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/ },
  { id: "google-api-key", pattern: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { id: "openai-prefixed-key", pattern: /\bsk-(?:proj|admin|svcacct)-[A-Za-z0-9_-]{20,}\b/ },
  { id: "openai-legacy-key", pattern: /\bsk-[A-Za-z0-9]{40,}\b/ },
  { id: "stripe-secret-key", pattern: /\bsk_(?:live|test)_[A-Za-z0-9]{20,}\b/ },
  {
    id: "private-key-header",
    pattern: /-----BEGIN (?:ENCRYPTED |RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/,
  },
];
const SAFE_PREFLIGHT_TEST_CLASSES = new Set([
  "SigilRotationTests",
  "GitHubSyncTests",
  "PreCommitHookTests",
  "HookInstallerTests",
]);
const SAFE_PREFLIGHT_TEST_NAMES = new Set([
  "test_rotation_failure_recovery_and_never_reuses_active_sigil",
  "test_sync_publishes_only_the_fixed_source_allowlist",
  "test_sync_stops_safely_when_object_creation_returns_unreadable_json",
  "test_normal_sync_stops_safely_on_malformed_object_ids",
  "test_unchanged_source_skips_blob_tree_commit_and_branch_update",
  "test_dry_run_with_no_changes_reports_no_commit_and_makes_no_writes",
  "test_dry_run_lists_only_changed_paths_without_contents_or_writes",
  "test_dry_run_rejects_malformed_initial_and_first_comparison_commit_ids",
  "test_unknown_sync_option_stops_before_github_request",
  "test_malformed_remote_files_stop_before_any_github_write",
  "test_unsafe_local_sources_stop_before_github_and_do_not_leak_contents",
  "test_hard_linked_private_source_is_rejected_before_read_or_github_request",
  "test_source_replaced_after_metadata_check_is_not_followed_or_read",
  "test_in_place_source_edit_during_read_is_rejected_before_github",
  "test_invalid_javascript_stops_before_github_without_printing_source",
  "test_embedded_credentials_stop_before_github_without_leaking_values",
  "test_credentials_in_multiple_sources_are_all_reported_without_leaking",
  "test_embedded_credentials_report_lines_for_crlf_and_bare_cr_without_leaking",
  "test_dry_run_refreshes_once_when_main_advances",
  "test_dry_run_stops_after_second_head_advance",
  "test_dry_run_stops_safely_when_refreshed_commit_id_is_invalid",
  "test_dry_run_refresh_failure_requests_rerun",
  "test_changed_source_updates_only_the_changed_allowlisted_file",
  "test_missing_secret_fails_before_any_github_request",
  "test_local_credential_check_passes_without_token_or_github_requests",
  "test_local_javascript_syntax_check_passes_and_rejects_invalid_source_safely",
  "test_local_credential_check_reports_location_without_exposing_value",
  "test_local_credential_check_guides_non_text_repair_without_leaking",
  "test_precommit_hook_blocks_staged_credentials_without_exposing_them",
  "test_precommit_hook_blocks_every_supported_credential_pattern",
  "test_precommit_hook_vectors_cover_every_scanner_pattern",
  "test_precommit_hook_reports_credentials_from_every_staged_source_file",
  "test_precommit_hook_blocks_when_node_is_too_old_without_leaking_output",
  "test_precommit_hook_rejects_non_text_staged_files_without_leaking_contents",
  "test_precommit_hook_reports_unicode_separator_lines_without_exposing_content",
  "test_precommit_hook_blocks_when_node_is_missing",
  "test_precommit_hook_blocks_when_staged_index_cannot_be_read",
  "test_precommit_hook_reports_staged_git_timeout_safely_without_github_token",
  "test_precommit_hook_passes_clean_source_and_ignores_unrelated_files",
  "test_hook_setup_enables_only_repository_local_path_when_safe",
  "test_hook_setup_preserves_existing_local_hooks_path",
  "test_hook_setup_preserves_multiple_local_hooks_paths",
  "test_hook_setup_preserves_existing_global_hooks_path",
  "test_hook_setup_preserves_existing_default_hooks",
  "test_hook_setup_refuses_linked_worktree_without_changing_config",
  "test_hook_setup_enables_only_selected_linked_worktree_when_supported",
  "test_hook_setup_keeps_selected_worktree_check_after_move",
  "test_hook_status_reports_repository_local_setup_without_writing_config",
  "test_hook_status_reports_shared_setup_without_writing_config",
  "test_hook_status_reports_inactive_setup_without_writing_config",
  "test_hook_status_reports_manual_hook_integration_without_writing_config",
  "test_chain_existing_hooks_run_first_and_preserve_configuration",
  "test_chain_existing_hook_failure_stops_before_gitmesh",
  "test_chain_existing_gitmesh_failure_happens_after_existing_hook",
  "test_chain_existing_worktree_scope_does_not_change_sibling_settings",
  "test_hook_setup_refuses_worktree_opt_in_without_worktree_config_support",
  "test_hook_setup_uses_local_hooks_path_when_gitmesh_is_repository_root",
  "test_hook_setup_uses_standalone_hooks_path_only_for_selected_worktree",
  "test_embedded_credentials_report_lines_for_unicode_separators_without_leaking",
  "test_embedded_credentials_report_lines_for_mixed_line_breaks_without_leaking",
  "test_embedded_credentials_report_lines_for_blank_boundary_separators_without_leaking",
  "test_embedded_credentials_report_lines_for_blank_boundary_separators_without_leaking",
  "test_failed_security_preflight_stops_before_github_without_leaking_output",
  "test_preflight_safe_name_allowlist_matches_regression_tests",
  "test_missing_preflight_harness_has_safe_recovery_guidance",
  "test_outdated_python_version_stops_before_preflight_and_github_without_leaking_output",
  "test_malformed_credentials_fail_before_reading_sources_or_requesting_github",
  "test_http_and_network_failures_stop_without_printing_token",
  "test_branch_conflict_uses_non_force_update_and_stops",
  "test_authentication_and_permission_errors_give_safe_recovery_guidance",
  "test_rate_limit_and_transient_errors_give_safe_retry_guidance",
  "test_gitignore_excludes_local_vault_from_normal_git_operations",
]);
const PREFLIGHT_REPRO_COMMAND = "python3 gitmesh-template/tests/test_security_regressions.py";
// The regression suite uses os.waitstatus_to_exitcode, introduced in Python 3.9.
const MINIMUM_PYTHON_VERSION = { major: 3, minor: 9 };
const PYTHON_VERSION_CHECK_COMMAND =
  "import sys; print('%s.%s' % (sys.version_info[0], sys.version_info[1]))";

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

function findEmbeddedCredentialLines(text) {
  return text
    .split(/\r\n|[\n\r\u2028\u2029]/)
    .flatMap((line, index) =>
      EMBEDDED_CREDENTIAL_PATTERNS.some(({ pattern }) => pattern.test(line))
        ? [index + 1]
        : [],
    );
}

function nonTextSourceError(source, operation = "sync") {
  const isLocalCheck = operation === "local-check";
  const isSyntaxCheck = operation === "syntax-check";
  return new Error(
    `Refusing to ${
      isSyntaxCheck ? "check JavaScript in" : isLocalCheck ? "check" : "sync"
    } a non-text source file: ${source}. ` +
      "Save the intended source as valid UTF-8 plain text, then " +
      (isSyntaxCheck
        ? "rerun the local syntax check with --check-syntax. "
        : isLocalCheck
          ? "rerun the local credential check with --check-credentials. "
          : "rerun sync. ") +
      "No GitHub requests were made.",
  );
}

function withPreflightRerun(summary, failedTests = []) {
  const rerunOnly = failedTests.length > 0;
  return {
    summary,
    rerunOnly,
    rerunCommand: rerunOnly
      ? `${PREFLIGHT_REPRO_COMMAND} ${failedTests.join(" ")}`
      : PREFLIGHT_REPRO_COMMAND,
  };
}

function pythonVersionRecoveryMessage(reason, detectedVersion = null) {
  const detected = detectedVersion ? ` Detected Python ${detectedVersion}.` : "";
  return (
    `${reason}.${detected} Python ${MINIMUM_PYTHON_VERSION.major}.` +
    `${MINIMUM_PYTHON_VERSION.minor} or newer is required for the security regression preflight. ` +
    `Install or upgrade Python to ${MINIMUM_PYTHON_VERSION.major}.` +
    `${MINIMUM_PYTHON_VERSION.minor} or newer using your operating system's package manager or python.org, ` +
    `then confirm python3 --version reports ${MINIMUM_PYTHON_VERSION.major}.` +
    `${MINIMUM_PYTHON_VERSION.minor} or newer. ` +
    `Run locally from the workspace root: ${PREFLIGHT_REPRO_COMMAND}. ` +
    "No GitHub requests were made."
  );
}

function checkMinimumPythonVersion() {
  const result = spawnSync(
    "python3",
    ["-c", PYTHON_VERSION_CHECK_COMMAND],
    {
      cwd: ROOT,
      encoding: "utf8",
      timeout: 10_000,
      maxBuffer: 64 * 1024,
      env: {
        PATH: process.env.PATH ?? "",
        ...(process.env.HOME ? { HOME: process.env.HOME } : {}),
        ...(process.env.TMPDIR ? { TMPDIR: process.env.TMPDIR } : {}),
      },
    },
  );
  if (result.error || result.status !== 0 || result.signal) {
    const reason = result.error?.code === "ETIMEDOUT"
      ? "Python version check timed out"
      : result.error?.code === "ENOBUFS"
        ? "Python version check exceeded its output limit"
        : result.error
          ? "Could not start python3 to check the security regression preflight version"
          : result.signal
            ? "Python version check was interrupted"
            : "Python version check failed";
    throw new Error(pythonVersionRecoveryMessage(reason));
  }

  const match = /^(\d{1,2})\.(\d{1,2})$/.exec(
    typeof result.stdout === "string" ? result.stdout.trim() : "",
  );
  if (!match) {
    throw new Error(
      pythonVersionRecoveryMessage(
        "Could not safely determine the python3 version for the security regression preflight",
      ),
    );
  }

  const major = Number(match[1]);
  const minor = Number(match[2]);
  if (
    major < MINIMUM_PYTHON_VERSION.major ||
    (major === MINIMUM_PYTHON_VERSION.major && minor < MINIMUM_PYTHON_VERSION.minor)
  ) {
    throw new Error(
      pythonVersionRecoveryMessage(
        "The installed Python version is too old",
        `${major}.${minor}`,
      ),
    );
  }
}

function summarizePreflightFailure(result) {
  if (
    result.error?.code === "ETIMEDOUT" ||
    result.signal === "SIGTERM" ||
    result.signal === "SIGKILL"
  ) {
    return withPreflightRerun("Security regression preflight timed out");
  }
  if (result.error?.code === "ENOBUFS") {
    return withPreflightRerun("Security regression preflight exceeded its output limit");
  }
  if (result.error) {
    return withPreflightRerun(
      "Python could not start the security regression preflight. " +
      "Install or upgrade Python to 3.9 or newer, make python3 available on PATH, then rerun the regression checks and sync",
    );
  }
  if (result.signal) {
    return withPreflightRerun("Python security regression preflight was interrupted");
  }

  const output = [result.stdout, result.stderr]
    .filter((chunk) => typeof chunk === "string")
    .join("\n");
  const failedTests = new Map();
  for (const match of output.matchAll(
    /^(?:FAIL|ERROR): (test_[A-Za-z0-9_]+) \(__main__\.([A-Za-z0-9_]+)\.(test_[A-Za-z0-9_]+)\)/gm,
  )) {
    const [, testName, testClass, qualifiedName] = match;
    if (
      testName === qualifiedName &&
      SAFE_PREFLIGHT_TEST_NAMES.has(testName) &&
      SAFE_PREFLIGHT_TEST_CLASSES.has(testClass)
    ) {
      failedTests.set(testName, `${testClass}.${testName}`);
    }
  }
  if (failedTests.size > 0) {
    return withPreflightRerun(
      `Security regression preflight failed in: ${[...failedTests.keys()].join(", ")}`,
      [...failedTests.values()],
    );
  }
  return withPreflightRerun(
    "Security regression preflight failed; no safe failing test name was available",
  );
}

function runSecurityPreflight() {
  const preflightPath = path.join(ROOT, "tests", "test_security_regressions.py");
  let preflightHarnessExists = false;
  try {
    preflightHarnessExists = fs.statSync(preflightPath).isFile();
  } catch {
    // Report a safe repair step instead of forwarding Python's missing-file output.
  }
  if (!preflightHarnessExists) {
    throw new Error(
      "Security regression preflight harness is missing: tests/test_security_regressions.py. " +
      "Restore it from the complete GitMesh workspace, then rerun sync. " +
      `Run locally from the workspace root: ${PREFLIGHT_REPRO_COMMAND}. No GitHub requests were made.`,
    );
  }

  checkMinimumPythonVersion();

  const result = spawnSync(
    "python3",
    [preflightPath],
    {
      cwd: ROOT,
      encoding: "utf8",
      timeout: 180_000,
      maxBuffer: 1024 * 1024,
      env: {
        PATH: process.env.PATH ?? "",
        ...(process.env.HOME ? { HOME: process.env.HOME } : {}),
        ...(process.env.TMPDIR ? { TMPDIR: process.env.TMPDIR } : {}),
      },
    },
  );
  if (result.error || result.status !== 0) {
    const { summary, rerunOnly, rerunCommand } = summarizePreflightFailure(result);
    const rerunInstruction = rerunOnly
      ? "Rerun only the named checks from the workspace root"
      : "Run locally from the workspace root";
    throw new Error(
      `${summary}. ${rerunInstruction}: ${rerunCommand}. ` +
      "No GitHub requests were made.",
    );
  }
}

function validateJavaScriptSyntax(content, source, operation = "sync") {
  const result = spawnSync(process.execPath, ["--input-type=module", "--check"], {
    input: content,
    encoding: "utf8",
    timeout: 10_000,
    maxBuffer: 64 * 1024,
    env: { PATH: process.env.PATH ?? "" },
  });
  if (result.error || result.status !== 0) {
    const isSyntaxCheck = operation === "syntax-check";
    const location = syntaxErrorLocation(result.stderr);
    const locationText = location
      ? ` (line ${location.line}, column ${location.column})`
      : "";
    throw new Error(
      `Refusing to ${isSyntaxCheck ? "check" : "sync"} JavaScript that fails Node syntax validation: ${source}${locationText}. ` +
      (isSyntaxCheck
        ? "Review and correct this file, save it, then rerun the local syntax check with --check-syntax. "
        : "Review and correct this file, save it, then rerun sync. ") +
      "No GitHub requests were made.",
    );
  }
}

function syntaxErrorLocation(nodeDiagnostics) {
  if (typeof nodeDiagnostics !== "string") return null;
  const lines = nodeDiagnostics.split(/\r\n|\n|\r/);
  for (let index = 0; index < lines.length - 2; index += 1) {
    const header = /^\[stdin\]:(\d+)(?::(\d+))?$/.exec(lines[index]);
    if (!header) continue;

    const line = Number(header[1]);
    const caret = /^[\t ]*\^/.exec(lines[index + 2]);
    const column = header[2] ? Number(header[2]) : caret?.[0].length;
    if (
      Number.isSafeInteger(line) &&
      line > 0 &&
      Number.isSafeInteger(column) &&
      column > 0
    ) {
      return { line, column };
    }
  }
  return null;
}

function validateSourceFileInfo(fileInfo, source, operation = "sync") {
  if (!fileInfo.isFile() ||
      fileInfo.isSymbolicLink() ||
      fileInfo.nlink > 1n ||
      fileInfo.size > BigInt(MAX_SOURCE_BYTES)) {
    if (operation === "syntax-check") {
      throw new Error(
        `Refusing to check an invalid, linked, or oversized JavaScript source file: ${source}. ` +
        "Save it as a regular file within the size limit, then rerun the local syntax check with --check-syntax. " +
        "No GitHub requests were made.",
      );
    }
    throw new Error(
      `Refusing to sync an invalid, linked, or oversized source file: ${source}. ` +
      "Review and save the intended file as a regular file within the size limit, then rerun sync. " +
      "No GitHub requests were made.",
    );
  }
}

function sameFileSnapshot(left, right) {
  return left.dev === right.dev &&
    left.ino === right.ino &&
    left.nlink === right.nlink &&
    left.size === right.size &&
    left.mtimeNs === right.mtimeNs &&
    left.ctimeNs === right.ctimeNs;
}

function readSourceContent(sourcePath, source, operation = "sync") {
  let pathInfo;
  try {
    pathInfo = fs.lstatSync(sourcePath, { bigint: true });
  } catch {
    if (operation === "syntax-check") {
      throw new Error(
        `Refusing to check an unavailable JavaScript source file: ${source}. ` +
        "Review and save the intended file state, then rerun the local syntax check with --check-syntax. No GitHub requests were made.",
      );
    }
    throw new Error(
      `Refusing to sync an unavailable source file: ${source}. ` +
      "Review and save the intended file state, then rerun sync. No GitHub requests were made.",
    );
  }
  validateSourceFileInfo(pathInfo, source, operation);

  let descriptor;
  try {
    if (typeof fs.constants.O_NOFOLLOW !== "number") {
      throw new Error("No-follow file opening is unavailable.");
    }
    descriptor = fs.openSync(
      sourcePath,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW,
    );
    const openedInfo = fs.fstatSync(descriptor, { bigint: true });
    validateSourceFileInfo(openedInfo, source, operation);
    if (!sameFileSnapshot(pathInfo, openedInfo)) {
      throw new Error("The source file changed after its metadata check.");
    }

    const content = fs.readFileSync(descriptor);
    const finalInfo = fs.fstatSync(descriptor, { bigint: true });
    if (!sameFileSnapshot(openedInfo, finalInfo)) {
      throw new Error("The source file changed while it was being read.");
    }
    return content;
  } catch {
    if (operation === "syntax-check") {
      throw new Error(
        `Refusing to check a JavaScript source file that changed or could not be safely opened: ${source}. ` +
        "Review and save the intended file state, then rerun the local syntax check with --check-syntax. No GitHub requests were made.",
      );
    }
    throw new Error(
      `Refusing to sync a source file that changed or could not be safely opened: ${source}. ` +
      "Review and save the intended file state, then rerun sync. No GitHub requests were made.",
    );
  } finally {
    if (descriptor !== undefined) {
      try {
        fs.closeSync(descriptor);
      } catch {
        // Keep raw filesystem diagnostics out of sync output.
      }
    }
  }
}

function readSourceFiles({
  validateSyntax = true,
  validateCredentials = true,
  javascriptOnly = false,
  operation = "sync",
} = {}) {
  const allowlistedFiles = javascriptOnly
    ? ALLOWED_FILES.filter(({ source }) => path.extname(source) === ".mjs")
    : ALLOWED_FILES;
  const sourceFiles = allowlistedFiles.map(({ source, target }) => {
    const sourcePath = path.join(ROOT, source);
    const content = readSourceContent(sourcePath, source, operation);
    if (content.includes(0)) {
      throw nonTextSourceError(source, operation);
    }
    let text;
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(content);
    } catch {
      throw nonTextSourceError(source, operation);
    }
    return {
      source,
      target,
      content,
      credentialLines: validateCredentials ? findEmbeddedCredentialLines(text) : [],
    };
  });
  const credentialFindings = sourceFiles.filter(({ credentialLines }) =>
    credentialLines.length > 0
  );
  if (validateCredentials && credentialFindings.length > 0) {
    const locations = credentialFindings.map(({ source, credentialLines }) => {
      const lineLabel = credentialLines.length === 1
        ? `line ${credentialLines[0]}`
        : `lines ${credentialLines.join(", ")}`;
      return `${source} (${lineLabel})`;
    });
    const hasMultipleLocations = credentialFindings.some(
      ({ credentialLines }) => credentialLines.length > 1,
    ) || credentialFindings.length > 1;
    const removalGuidance = credentialFindings.length > 1
      ? "Remove the values from these files"
      : hasMultipleLocations
        ? "Remove the values from this file"
        : "Remove the value from this file";
    const rotationGuidance = hasMultipleLocations
      ? "Rotate them only if they were already shared or published elsewhere."
      : "Rotate it only if it was already shared or published elsewhere.";
    throw new Error(
      `Refusing to sync source files containing a credential-like value: ${locations.join("; ")}. ` +
      `${removalGuidance}; use Replit Secrets for runtime credentials. ` +
      `${rotationGuidance} No GitHub requests were made.`,
    );
  }
  if (validateSyntax) {
    for (const { source, content } of sourceFiles) {
      if (path.extname(source) === ".mjs") {
        validateJavaScriptSyntax(content, source, operation);
      }
    }
  }
  return sourceFiles.map(({ target, content }) => ({ target, content }));
}

function checkLocalCredentials() {
  const files = readSourceFiles({
    validateSyntax: false,
    operation: "local-check",
  });
  console.log(
    `Credential check passed: no credential-like values found in ${files.length} allowlisted source files.`,
  );
}

function checkLocalJavaScriptSyntax() {
  const files = readSourceFiles({
    validateSyntax: true,
    validateCredentials: false,
    javascriptOnly: true,
    operation: "syntax-check",
  });
  console.log(
    `JavaScript syntax check passed for ${files.length} allowlisted JavaScript source files. No GitHub requests were made.`,
  );
}

function runStagedGitCommand(args, cwd, failureMessage) {
  const env = { ...process.env };
  delete env.GITHUB_TOKEN;
  for (const name of ["GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_PREFIX"]) {
    delete env[name];
  }
  const result = spawnSync("git", args, {
    cwd,
    encoding: null,
    timeout: 15_000,
    maxBuffer: 1024 * 1024,
    env,
  });
  if (result.error?.code === "ETIMEDOUT") {
    throw new Error(
      "Git timed out while checking staged source files. Check whether another Git process is stuck and whether the repository is responsive, then retry the commit. The staged credential check failed closed. No GitHub requests were made.",
    );
  }
  if (result.error || result.status !== 0 || !Buffer.isBuffer(result.stdout)) {
    throw new Error(`${failureMessage} No GitHub requests were made.`);
  }
  return result.stdout;
}

function checkStagedCredentials() {
  const gitRootOutput = runStagedGitCommand(
    ["rev-parse", "--show-toplevel"],
    ROOT,
    "Could not locate the Git repository to inspect staged source files.",
  );
  let gitRootText;
  try {
    gitRootText = new TextDecoder("utf-8", { fatal: true }).decode(gitRootOutput).trim();
  } catch {
    throw new Error(
      "Could not locate the Git repository to inspect staged source files. No GitHub requests were made.",
    );
  }
  if (!gitRootText) {
    throw new Error(
      "Could not locate the Git repository to inspect staged source files. No GitHub requests were made.",
    );
  }
  const gitRoot = path.resolve(gitRootText);
  const sourceByGitPath = new Map();
  for (const { source } of ALLOWED_FILES) {
    const sourcePath = path.resolve(ROOT, source);
    const relativePath = path.relative(gitRoot, sourcePath);
    if (
      path.isAbsolute(relativePath) ||
      relativePath === ".." ||
      relativePath.startsWith(`..${path.sep}`)
    ) {
      throw new Error(
        "Could not map allowlisted source files to the Git repository. No GitHub requests were made.",
      );
    }
    sourceByGitPath.set(relativePath.split(path.sep).join("/"), source);
  }

  const stagedNames = runStagedGitCommand(
    [
      "diff",
      "--cached",
      "--name-only",
      "--no-ext-diff",
      "--no-textconv",
      "-z",
      "--diff-filter=ACMRT",
      "--",
      ...sourceByGitPath.keys(),
    ],
    gitRoot,
    "Could not inspect staged allowlisted source files. Check that the staged index is readable and not locked, resolve any Git index errors, then stage the intended files again and retry the commit.",
  ).toString("utf8").split("\0").filter(Boolean);
  const stagedSources = [...new Set(
    stagedNames.map((name) => sourceByGitPath.get(name)).filter(Boolean),
  )];
  if (stagedSources.length === 0) {
    console.log("Credential check passed: no allowlisted source files are staged.");
    return;
  }

  const credentialFindings = [];
  for (const source of stagedSources) {
    const gitPath = [...sourceByGitPath].find(([, stagedSource]) => stagedSource === source)?.[0];
    if (!gitPath) {
      throw new Error(
        `Could not map staged source file ${source} to the Git index. No GitHub requests were made.`,
      );
    }
    const content = runStagedGitCommand(
      ["show", `:0:${gitPath}`],
      gitRoot,
      `Could not safely read staged source file: ${source}. Check that the staged index is readable, resolve any conflicts or Git index errors, then stage the intended file state again and retry the commit.`,
    );
    if (content.length > MAX_SOURCE_BYTES) {
      throw new Error(
        `Refusing to check an oversized staged source file: ${source}. ` +
        "Review the file and stage a version within the size limit. No GitHub requests were made.",
      );
    }
    if (content.includes(0)) {
      throw new Error(
        `Refusing to check a non-text staged source file: ${source}. ` +
        "Save it as UTF-8 text and stage it again. No GitHub requests were made.",
      );
    }
    let text;
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(content);
    } catch {
      throw new Error(
        `Refusing to check a non-text staged source file: ${source}. ` +
        "Save it as UTF-8 text and stage it again. No GitHub requests were made.",
      );
    }
    const credentialLines = findEmbeddedCredentialLines(text);
    if (credentialLines.length > 0) {
      credentialFindings.push({ source, credentialLines });
    }
  }

  if (credentialFindings.length > 0) {
    const locations = credentialFindings.map(({ source, credentialLines }) => {
      const lineLabel = credentialLines.length === 1
        ? `line ${credentialLines[0]}`
        : `lines ${credentialLines.join(", ")}`;
      return `${source} (${lineLabel})`;
    });
    const hasMultipleLocations = credentialFindings.some(
      ({ credentialLines }) => credentialLines.length > 1,
    ) || credentialFindings.length > 1;
    const removalGuidance = credentialFindings.length > 1
      ? "Remove the values from these staged files"
      : hasMultipleLocations
        ? "Remove the values from this staged file"
        : "Remove the value from this staged file";
    const rotationGuidance = hasMultipleLocations
      ? "Rotate them only if they were already shared or published elsewhere."
      : "Rotate it only if it was already shared or published elsewhere.";
    throw new Error(
      `Refusing to commit staged source files containing a credential-like value: ${locations.join("; ")}. ` +
      `${removalGuidance} and stage the fix; use Replit Secrets for runtime credentials. ` +
      `${rotationGuidance} No GitHub requests were made.`,
    );
  }

  const fileLabel = stagedSources.length === 1 ? "file" : "files";
  console.log(
    `Credential check passed: no credential-like values found in ${stagedSources.length} staged allowlisted source ${fileLabel}.`,
  );
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

async function readRemoteSourceFile(token, target, refSha) {
  const encodedPath = target.split("/").map(encodeURIComponent).join("/");
  const remote = await githubRequest(
    token,
    `/contents/${encodedPath}?ref=${encodeURIComponent(refSha)}`,
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

async function findChangedFiles(token, files, refSha) {
  const changedFiles = [];
  for (const file of files) {
    const remoteContent = await readRemoteSourceFile(token, file.target, refSha);
    if (remoteContent === null || !remoteContent.equals(file.content)) {
      changedFiles.push(file);
    }
  }
  return changedFiles;
}

async function previewSource(token, files) {
  let parentSha;
  let changedFiles;
  let branchAdvancedToSha;
  try {
    const ref = await githubRequest(token, `/git/ref/heads/${BRANCH}`);
    parentSha = requireSha(ref?.object?.sha, "main branch commit");
    changedFiles = await findChangedFiles(token, files, parentSha);

    const latestRef = await githubRequest(token, `/git/ref/heads/${BRANCH}`);
    const latestSha = requireSha(latestRef?.object?.sha, "main branch commit");
    if (latestSha !== parentSha) {
      parentSha = latestSha;
      changedFiles = await findChangedFiles(token, files, parentSha);

      const refreshedRef = await githubRequest(token, `/git/ref/heads/${BRANCH}`);
      const refreshedSha = requireSha(refreshedRef?.object?.sha, "main branch commit");
      if (refreshedSha !== parentSha) {
        branchAdvancedToSha = refreshedSha;
      }
    }
  } catch (error) {
    const detail = error instanceof Error ? error.message : "A GitHub request failed.";
    throw new Error(
      `Dry run could not complete a consistent comparison. ${detail} ` +
      "Rerun the dry run before publishing. No GitHub changes were made.",
    );
  }
  if (branchAdvancedToSha) {
    throw new Error(
      `GitHub branch advanced again from commit ${parentSha.slice(0, 7)} ` +
      `to ${branchAdvancedToSha.slice(0, 7)} during the one automatic refresh. ` +
      "Rerun the dry run before publishing. No GitHub changes were made.",
    );
  }

  const shortParentSha = parentSha.slice(0, 7);
  if (changedFiles.length === 0) {
    console.log(
      `Dry run: all ${files.length} allowlisted source files already match ${OWNER}/${REPOSITORY}@${BRANCH} (commit ${shortParentSha}); ` +
      "no changes would be published and no commit was created.",
    );
    return;
  }

  console.log(
    `Dry run: ${changedFiles.length} allowlisted source files would be published to ${OWNER}/${REPOSITORY}@${BRANCH}, ` +
    `compared with commit ${shortParentSha}; no GitHub changes were made.`,
  );
  console.log("Changed files:");
  for (const { target } of changedFiles) {
    console.log(`- ${target}`);
  }
}

function parseArguments(args) {
  if (args.length === 0) {
    return {
      dryRun: false,
      checkCredentials: false,
      checkStagedCredentials: false,
      checkSyntax: false,
    };
  }
  if (args.length === 1 && args[0] === "--dry-run") {
    return {
      dryRun: true,
      checkCredentials: false,
      checkStagedCredentials: false,
      checkSyntax: false,
    };
  }
  if (args.length === 1 && args[0] === "--check-credentials") {
    return {
      dryRun: false,
      checkCredentials: true,
      checkStagedCredentials: false,
      checkSyntax: false,
    };
  }
  if (args.length === 1 && args[0] === "--check-staged-credentials") {
    return {
      dryRun: false,
      checkCredentials: false,
      checkStagedCredentials: true,
      checkSyntax: false,
    };
  }
  if (args.length === 1 && args[0] === "--check-syntax") {
    return {
      dryRun: false,
      checkCredentials: false,
      checkStagedCredentials: false,
      checkSyntax: true,
    };
  }
  throw new Error(
    "Usage: node ./sync-public-source.mjs [--dry-run | --check-credentials | --check-staged-credentials | --check-syntax].",
  );
}

async function syncSource({ dryRun }) {
  const token = getToken();
  const files = readSourceFiles();
  runSecurityPreflight();
  if (dryRun) {
    await previewSource(token, files);
    return;
  }

  const ref = await githubRequest(token, `/git/ref/heads/${BRANCH}`);
  const parentSha = requireSha(ref?.object?.sha, "main branch commit");
  const changedFiles = await findChangedFiles(token, files, parentSha);
  if (changedFiles.length === 0) {
    console.log(`All ${files.length} allowlisted source files already match ${OWNER}/${REPOSITORY}@${BRANCH}; no commit created.`);
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
  if (options.checkStagedCredentials) {
    checkStagedCredentials();
  } else if (options.checkCredentials) {
    checkLocalCredentials();
  } else if (options.checkSyntax) {
    checkLocalJavaScriptSyntax();
  } else {
    syncSource(options).catch((error) => {
      console.error(error instanceof Error ? error.message : "Source sync failed.");
      process.exitCode = 1;
    });
  }
} catch (error) {
  console.error(error instanceof Error ? error.message : "Source sync failed.");
  process.exitCode = 2;
}
