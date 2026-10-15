# Local vault CLI

An offline-first Node.js command-line project for keeping local JSON records and moving snapshots between machines with Git bundles. It opens no network ports and has no third-party runtime dependencies.

## Run

From the GitMesh repository root:

```sh
node projects/local-vault/gitmesh-ultimate-core.mjs
```

Or use the launcher in this folder: `run-mesh.bat` on Windows, or `sh run-mesh.sh` on macOS/Linux. On iPhone/iPad, this is not a native app and cannot auto-run when downloaded; shell support depends on compatible Node.js and Git being available.

Requirements: Node.js 20 or newer, Git on `PATH`, and an interactive terminal.

On first launch, choose a passphrase of at least 12 characters. Later launches ask for it without echoing it. The local credential file stores a random salt and scrypt-derived verifier, never the passphrase. Use the menu to change the passphrase. There is no in-app recovery if it is forgotten.

## Local data

Runtime data lives under `projects/local-vault/SovereignMeshVault/`:

- `ledger_matrix/` — local JSON records.
- `drops_inbound/` — bundles available for manual import.
- `bundles_outbound/` — exported bundles.
- `active_sigil.hash` — local passphrase verifier.

The `.gitignore` in this folder excludes the entire vault from the public repository. The source code and documentation are intended to be committed; runtime records, credentials, and bundles are not.

## Behavior and limits

- Checks each record's SHA-256 checksum when listing or importing it.
- Imports only a bundle explicitly selected from `drops_inbound`; it does not watch folders or execute incoming content.
- Limits the ledger to 1,000 records and imported bundles to 100 MiB.
- Does not sync, publish, or push local data to GitHub.

The scrypt verifier is local access control, not device encryption or account authentication. A checksum can detect accidental changes but is not a digital signature. Git bundles are unencrypted and readable by anyone who obtains them. File deletion cannot guarantee forensic erasure on SSDs, filesystems with journals, backups, or snapshots. Keep secrets and sensitive personal data out of records unless you have separately assessed the storage and transfer risks.
