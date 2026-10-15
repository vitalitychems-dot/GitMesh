# Local vault CLI

An offline-first Node.js command-line project for keeping local JSON records and moving snapshots between machines with Git bundles. The vault CLI opens no network ports and has no third-party runtime dependencies. A separate, explicitly run source-sync script can publish only allowlisted source files.

## Run

From the GitMesh repository root:

```sh
node projects/local-vault/gitmesh-ultimate-core.mjs
```

Or use the launcher in this folder: `run-mesh.bat` on Windows, or `sh run-mesh.sh` on macOS/Linux. On iPhone/iPad, this is not a native app and cannot auto-run when downloaded; shell support depends on compatible Node.js and Git being available.

Requirements: Node.js 20 or newer, Git on `PATH`, and an interactive terminal.

On first launch, choose an initial admin sigil of at least 12 characters. Later launches ask for it without echoing it. After a successful sign-in, GitMesh displays a new, randomly generated sigil once. Save it, then type `SAVED` to activate it and open the console. The prior sigil is invalidated when the replacement is saved. If you cancel instead, the prior sigil remains valid and the console stays locked.

The local credential file stores a salted scrypt verifier and hashes of consumed sigils, never the active sigil itself. Generated sigils use a persistent increasing generation number and are checked against the consumed-key history to prevent reuse. The menu can also set a new sigil; prior sigils cannot be reused. There is no in-app recovery if the active sigil is lost. Existing version-1 passphrase verifier files are accepted and migrate to rotating sigils on the next successful sign-in.

## Local data

Runtime data lives under `projects/local-vault/SovereignMeshVault/`:

- `ledger_matrix/` — local JSON records.
- `drops_inbound/` — bundles available for manual import.
- `bundles_outbound/` — exported bundles.
- `active_sigil.hash` — local verifier, rotation counter, and hashes of consumed sigils.

The `.gitignore` in this folder excludes the entire vault from the public repository. The source code and documentation are intended to be committed; runtime records, credentials, and bundles are not.

## Behavior and limits

- Checks each record's SHA-256 checksum when listing or importing it.
- Imports only a bundle explicitly selected from `drops_inbound`; it does not watch folders or execute incoming content.
- Limits the ledger to 1,000 records and imported bundles to 100 MiB.
- Does not sync, publish, or push local data to GitHub.
- The separate source-sync script sends only the CLI source, README, and sync script to `vitalitychems-dot/GitMesh`; it never reads or uploads `SovereignMeshVault/`.
- Rotates the admin sigil after each successful sign-in; the replacement is displayed once and must be saved before access is granted.
- A restored older copy of the local vault can restore an older sigil verifier and rotation history. Protect backups and avoid restoring stale copies if you need to keep prior sigils permanently invalid.

The scrypt verifier is local access control, not device encryption or account authentication. The sigil is shown in the terminal once per rotation, so store it somewhere secure. A checksum can detect accidental changes but is not a digital signature. Git bundles are unencrypted and readable by anyone who obtains them. File deletion cannot guarantee forensic erasure on SSDs, filesystems with journals, backups, or snapshots. Keep secrets and sensitive personal data out of records unless you have separately assessed the storage and transfer risks.

## Sync source to GitHub

This is separate from vault data transfer and makes an outbound HTTPS request to GitHub. On Replit, store a fine-grained token as the `GITHUB_TOKEN` Secret, limited to the `vitalitychems-dot/GitMesh` repository with Contents write access. Replit Secrets are project-level and available to processes running in the project; they are not folder-scoped. The sync script reads the token from `process.env.GITHUB_TOKEN` only when run and never writes or prints it.

Run from this folder with `node ./sync-public-source.mjs`. Before any GitHub request, it validates the local source files and runs the full mocked security regression suite. The suite's output is suppressed, and sync stops without contacting GitHub if the suite fails or cannot start. This preflight requires Python 3, Node.js 20 or newer, and Git on `PATH`. It also checks each allowlisted `.mjs` file with Node's syntax checker and suppresses diagnostics so source lines are not printed. It compares the three fixed source paths with `main`, creates no commit if they already match, and uses a non-force ref update when changes are needed. After a successful sync, it reports only the changed allowlisted file paths. To inspect the planned paths without publishing, run `node ./sync-public-source.mjs --dry-run`; this performs the same preflight, then read-only GitHub comparisons and makes no GitHub changes. A preview can become stale if `main` changes; a normal sync compares the files again before writing. Do not put the token in a `.env` file, source file, Git remote URL, or command-line argument.

If GitHub rejects a sync, the error message gives a safe next step without printing the token, authorization header, or request body:

- **Authentication rejected:** Check that the `GITHUB_TOKEN` Secret is current and has access to `vitalitychems-dot/GitMesh`.
- **Access denied:** Check repository access and the required Contents permission (read for lookups, write for updates).
- **Rate limit:** Wait for the limit to reset, then retry.
- **Network or temporary GitHub error:** Check the connection, wait briefly, and retry.
- **Branch conflict:** Review `main` and retry after resolving the conflict. Sync never force-updates the branch.

## Security regression checks

The regression harness is maintained in the Replit workspace and is not included in the GitHub source sync. The sync preflight expects `tests/test_security_regressions.py` alongside the workspace copy of this script; a downloaded copy without that local harness will fail closed. From the Replit workspace root, run `python3 gitmesh-template/tests/test_security_regressions.py`. The checks use a disposable fixture and a mocked GitHub API; they do not read the active vault or make network requests. Python 3, Node.js, and Git must be available.
