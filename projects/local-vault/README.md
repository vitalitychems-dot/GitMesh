# Local vault CLI

An offline-first Node.js command-line project for keeping local JSON records and moving snapshots between machines with Git bundles. The vault CLI opens no network ports and has no third-party runtime dependencies. A separate, explicitly run source-sync script can publish only allowlisted source files.

## Run

From the GitMesh repository root:

```sh
node projects/local-vault/gitmesh-ultimate-core.mjs
```

Or use the launcher in this folder: `run-mesh.bat` on Windows, or `sh run-mesh.sh` on macOS/Linux. The terminal CLI is not a native iPhone/iPad app; use the browser keypad tunnel described below instead.

Requirements: Node.js 20 or newer, Git on `PATH`, and an interactive terminal.

Run the automated sigil security tests from the repository root with `node --test gitmesh-template/test/sigil-auth.test.mjs`.

On first launch, choose an initial admin sigil of at least 12 characters. Later launches ask for it without echoing it. After a successful sign-in, GitMesh displays a new, randomly generated sigil once. Save it, then type `SAVED` to activate it and open the console. The prior sigil is invalidated when the replacement is saved. If you cancel instead, the prior sigil remains valid and the console stays locked.

The local credential file stores a salted scrypt verifier and hashes of consumed sigils, never the active sigil itself. Generated sigils use a persistent increasing generation number and are checked against the consumed-key history to prevent reuse. The menu can also set a new sigil; prior sigils cannot be reused. There is no in-app recovery if the active sigil is lost. Existing version-1 passphrase verifier files are accepted and migrate to rotating sigils on the next successful sign-in.

## Local browser keypad

From the GitMesh repository root, start the optional browser console:

```sh
node projects/local-vault/keypad-server.mjs
```

Then open `http://127.0.0.1:8782` in a browser on the same machine running Node. The server binds only to the loopback interface; do not change it to `0.0.0.0`, publish the port, or treat Replit's hosted preview as a private tunnel. Stop it with Ctrl+C when finished. The browser keypad displays English keys, creates a fresh randomized mapping for each page session, and lets you hold a key to view its temporary session code. It does not accept sigils from the physical keyboard. The generated sigil is displayed once after sign-in and must be saved before the vault unlocks; cancelling keeps the old sigil active.

### iPhone access without exposing the HTTP service

Use an SSH local-port forward from an iPhone only when the vault is running on a trusted Mac or Linux computer that you control:

1. On a trusted Mac or Linux computer, install Git and Node.js 20+, place the approved GitMesh source there, and start the local keypad with the command above. The `SovereignMeshVault/` directory is excluded from Git, so a fresh clone creates a separate, empty vault; it does not bring over the Replit workspace's local records or sigil.
2. Enable SSH on that computer for a dedicated key-only account. Restrict that account to local TCP forwarding for `127.0.0.1:8782` only; an OpenSSH account rule should include:

   ```text
   Match User gitmesh-tunnel
     AuthenticationMethods publickey
     AllowTcpForwarding local
     PermitOpen 127.0.0.1:8782
     GatewayPorts no
     PermitTTY no
     X11Forwarding no
     ForceCommand /usr/bin/false
   ```

   Restrict the iPhone key in that account's `authorized_keys` as well, for example: `restrict,port-forwarding,permitopen="127.0.0.1:8782",command="/usr/bin/false" ssh-ed25519 <iPhone-public-key>`. Generate the key pair in the iPhone SSH client and install only its public key on the host; never copy the private key into GitMesh. Verify the SSH host key on the iPhone. Make SSH reachable only over trusted Wi-Fi or an existing private VPN; do not create router port forwards or expose SSH publicly. Validate the host's SSH configuration (for OpenSSH, `sshd -t`) before reloading it, and do not risk disabling your existing administrator access.
3. Install an iOS SSH client that explicitly supports forwarding a local port for use by Safari and a tunnel-only/no-shell session. Configure the iPhone's local port `8782` to forward to `127.0.0.1:8782` on the SSH host. Some clients require their documented device-wide SSH/VPN feature for Safari to use the tunnel; review that feature's traffic-routing behavior before enabling it. Keep the tunnel active.
4. In Safari on the iPhone, open `http://127.0.0.1:8782`. Use the same local and host port: the server checks the request origin and rejects mismatched ports.

The HTTP server still listens only on the host's loopback address. The SSH tunnel carries browser traffic to that loopback socket; sigil verification and vault reads/writes remain on the host. This does not make a Replit workspace's loopback port reachable from an iPhone, and the current Replit preview is not a private tunnel. If the only copy of the vault is in Replit, do not expose the HTTP service to make it reachable; the steps above require running the source and vault on a computer you control. Moving vault state is a separate operation and must use an encrypted bundle or an encrypted backup, never GitHub.

Use an SSH key only for the tunnel account and keep the phone locked. The tunnel protects traffic in transit, not data at rest; enable full-disk encryption on the host (such as FileVault, BitLocker, or LUKS). Compromised devices, screen recording, malicious browser extensions, keyloggers, or a person with access to an unlocked device can capture sigils and displayed records. The rotating keypad is input obfuscation, not encryption or a secure hardware keyboard.

The keypad accepts only ASCII letters, digits, hyphen, and underscore. If an existing legacy sigil contains other characters, use the terminal CLI to sign in and rotate it to a generated sigil before using the browser keypad.

The changing key labels are input obfuscation only. They are not a real language, encryption, a secure keyboard extension, or protection against a compromised device or software that can inspect the screen or browser. Sigil characters are entered through the visible buttons; a hardware keyboard can still navigate and activate those buttons for accessibility. The local browser console can add and list records and manually export/import Git bundles. New exports are encrypted before download; the existing terminal menu remains available.

## Local data

Runtime data lives under `projects/local-vault/SovereignMeshVault/`:

- `ledger_matrix/` — local JSON records.
- `drops_inbound/` — bundles available for manual import.
- `bundles_outbound/` — newly exported encrypted bundles (`.bundle.enc`); older `.bundle` files, if present, are unencrypted.
- `active_sigil.hash` — local verifier, rotation counter, and hashes of consumed sigils.

The `.gitignore` in this folder excludes the entire vault from the public repository. The source code and documentation are intended to be committed; runtime records, credentials, and bundles are not.

## Behavior and limits

- Checks each record's SHA-256 checksum when listing or importing it.
- Imports only a bundle explicitly selected from `drops_inbound`; it does not watch folders or execute incoming content. Encrypted bundles must authenticate and decrypt before records can be imported.
- Encrypts exports with AES-256-GCM and a per-bundle key derived from a user-held passphrase using scrypt. Passphrases must be 16–256 characters, are used transiently by the loopback-only local process, and are never saved or logged. Share the passphrase through a separate channel.
- Keep a separate backup of the entire `SovereignMeshVault/` directory on an encrypted disk or in an encrypted backup system. An encrypted bundle backs up records, not the active sigil verifier or its rotation history. A stale full-vault backup can restore old verifier/history state, so protect it and verify before restoring.
- Limits the ledger to 1,000 records and bundle files to 100 MiB before encryption (plus the small encryption header/tag).
- Allows older unencrypted `.bundle` files only after an explicit confirmation in the CLI or browser. These files remain readable to anyone who obtains them.
- Does not sync, publish, or push local data to GitHub.
- The separate source-sync script sends only the CLI source, README, and sync script to `vitalitychems-dot/GitMesh`; it never reads or uploads `SovereignMeshVault/`.
- Rotates the admin sigil after each successful sign-in; the replacement is displayed once and must be saved before access is granted.
- A restored older copy of the local vault can restore an older sigil verifier and rotation history. Protect backups and avoid restoring stale copies if you need to keep prior sigils permanently invalid.

The scrypt verifier is local access control, not device encryption or account authentication. The sigil is shown in the terminal once per rotation, so store it somewhere secure. A checksum can detect accidental changes but is not a digital signature. Encrypted bundles protect file contents from people who obtain the file, provided the passphrase is strong and kept separate; old unencrypted bundles are still readable. File deletion cannot guarantee forensic erasure on SSDs, filesystems with journals, backups, or snapshots. Keep secrets and sensitive personal data out of records unless you have separately assessed the storage and transfer risks.

## Sync source to GitHub

This is separate from vault data transfer and makes an outbound HTTPS request to GitHub. On Replit, store a fine-grained token as the `GITHUB_TOKEN` Secret, limited to the `vitalitychems-dot/GitMesh` repository with Contents write access. Replit Secrets are project-level and available to processes running in the project; they are not folder-scoped. The sync script reads the token from `process.env.GITHUB_TOKEN` only when run and never writes or prints it.

Run from this folder with `node ./sync-public-source.mjs`. It updates only the three fixed source paths listed in the script, on `main`, and uses a non-force ref update. It does not stage, read, or upload local vault data, bundles, or other workspace files. Do not put the token in a `.env` file, source file, Git remote URL, or command-line argument.

For an offline JavaScript syntax check that does not require a GitHub token or make network requests, run `node ./sync-public-source.mjs --check-syntax`.

JavaScript syntax validation times out after 10 seconds. Each GitHub API request times out after 20 seconds. These are fixed limits; there is no repository-specific or environment override.

## Security regression checks

From the Replit workspace root, run `node --test projects/local-vault/tests/sync-public-source.test.mjs`. The checks use temporary files and mocked GitHub requests; they do not access the active vault or make network requests. Node.js is required; Python is not used.
