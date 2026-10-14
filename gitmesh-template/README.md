# GitMesh local template

A small, offline-first Node.js command-line starter for keeping local JSON records and moving snapshots between machines with Git bundles. It opens no network ports and has no third-party runtime dependencies.

## Requirements

- Node.js 20 or newer
- Git available on your `PATH`
- A terminal window

## Run it

- Windows: double-click `run-mesh.bat`.
- macOS/Linux: run `sh ./run-mesh.sh` from a terminal. You can also make it executable with `chmod +x run-mesh.sh` and run `./run-mesh.sh`.
- iPhone/iPad: this is not an iOS app and cannot auto-run when downloaded. In an iSH shell with compatible Node.js and Git installed, use `sh ./run-mesh.sh`. Support depends on the packages available in that environment.

On first launch, choose a passphrase of at least 12 characters. Later launches ask for it without echoing it in the terminal. The app stores a random salt and a scrypt-derived verifier, never the passphrase. Use the menu's passphrase-change action to replace it. If you lose the passphrase, there is no reset or recovery mechanism; back up your data separately.

## What it does

- Stores records under `SovereignMeshVault/ledger_matrix/`.
- Checks each record's SHA-256 checksum when listing or importing it.
- Creates and imports Git bundle files under the vault's outbound and inbound folders.
- Requires you to choose a bundle to import; it does not watch folders or execute incoming content.
- Limits the local ledger to 1,000 records and limits an imported bundle to 100 MiB.

## Important security limits

- The passphrase verifier uses Node.js `scrypt` with a random salt. This is local access control, not device encryption, account authentication, or a defense against malware or someone with full access to your logged-in device.
- A record checksum detects accidental changes, but it is not a digital signature. Someone who can edit a record can also recalculate its checksum.
- Git bundles are not encrypted. Anyone who obtains one can read its records. Transfer them only through a channel you trust.
- Deleting a file does not securely erase it. This tool does not claim to shred data; SSD wear-leveling, backups, journals, and snapshots prevent software from guaranteeing forensic erasure.
- The vault and its bundles are local files. This tool does not sync, publish, or push anything to GitHub.
- Keep secrets, credentials, and sensitive personal data out of records unless you have separately assessed the risks and storage protections you need.

## Put this template in a separate GitHub repository

The Replit workspace may already have its own Git repository. To keep this standalone template separate, copy the contents of `gitmesh-template/` into a new, empty local folder first. Then, from that new folder:

```sh
git init -b main
git add .gitignore README.md gitmesh-ultimate-core.mjs run-mesh.sh run-mesh.bat
git commit -m "Add GitMesh local template"
git remote add origin https://github.com/OWNER/REPOSITORY.git
git push -u origin main
```

Replace `OWNER/REPOSITORY` with the URL of a repository you created. Git will prompt for or use your configured GitHub authentication; do not put a password or token in the URL. The `.gitignore` keeps the local vault out of the repository.

## Local data locations

```text
SovereignMeshVault/
├── active_sigil.hash
├── .gitignore
├── ledger_matrix/
├── drops_inbound/
└── bundles_outbound/
```

The vault is ignored by the template's outer `.gitignore`; only its internal Git repository tracks validated ledger records and its fixed ignore file.
