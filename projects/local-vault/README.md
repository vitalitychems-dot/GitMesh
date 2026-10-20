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

By default, open `http://127.0.0.1:8782` in a browser on the same machine running Node. The server binds only to the loopback interface; do not change it to `0.0.0.0`, publish the port, or treat Replit's hosted preview as a private tunnel. Stop it with Ctrl+C when finished. The browser keypad displays English keys, creates a fresh randomized mapping for each page session, and lets you hold a key to view its temporary session code. It does not accept sigils from the physical keyboard. The generated sigil is displayed once after sign-in and must be saved before the vault unlocks; cancelling keeps the old sigil active.

To use a custom port, choose one between `1024` and `65535` (for example, `8783`) and set `GITMESH_LOCAL_PORT` when starting the keypad. On macOS or Linux:

```sh
GITMESH_LOCAL_PORT=8783 node projects/local-vault/keypad-server.mjs
```

On Windows PowerShell:

```powershell
$env:GITMESH_LOCAL_PORT = "8783"
node .\projects\local-vault\keypad-server.mjs
```

Keep that same port in every part of the iPhone tunnel setup: replace `8782` with your chosen port in the host's SSH `PermitOpen` and iPhone `authorized_keys` `permitopen` restrictions, set the iPhone's local forwarding port and host destination port to that value, and use it in Safari's `http://127.0.0.1:<port>` URL. For example, with `8783`, forward local port `8783` to `127.0.0.1:8783` on the host and open `http://127.0.0.1:8783` in Safari. The local port, host loopback port, and Safari URL port must match the keypad's listening port; otherwise origin validation rejects the request. The SSH examples below use the default port `8782`.

### iPhone access without exposing the HTTP service

Use an SSH local-port forward from an iPhone only when the vault is running on a trusted computer that you control. The keypad HTTP listener remains on the host's loopback interface:

1. Install Git and Node.js 20+, place the approved GitMesh source on the computer, and start the local keypad with the command above. On Windows, run `node .\projects\local-vault\keypad-server.mjs` from the repository root. The `SovereignMeshVault/` directory is excluded from Git, so a fresh clone creates a separate, empty vault; it does not bring over the Replit workspace's local records or sigil.


### macOS or Linux host

On a trusted Mac or Linux computer, enable SSH for a dedicated key-only account. Restrict that account to local TCP forwarding for `127.0.0.1:8782` only; an OpenSSH account rule should include:

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

Run from this folder with `node ./sync-public-source.mjs`. It checks only the three fixed source paths listed in the script against GitHub's current `main` tree; if their Git blob contents and file modes already match, it verifies `main` has not moved during the check and exits without creating a commit. Otherwise it syncs those paths with a non-force ref update. It does not stage, read, or upload local vault data, bundles, or other workspace files. Do not put the token in a `.env` file, source file, Git remote URL, or command-line argument.

Before syncing, run `node ./sync-public-source.mjs --preview` to validate the configured source files and print only their three GitHub target paths. This local preview requires no token and makes no GitHub requests.

For an offline JavaScript syntax check that does not require a GitHub token or make network requests, run `node ./sync-public-source.mjs --check-syntax`.

JavaScript syntax validation times out after 10 seconds. Each GitHub API request times out after 20 seconds. These are fixed limits; there is no repository-specific or environment override.

## Security regression checks

From the Replit workspace root, run `node --test projects/local-vault/tests/sync-public-source.test.mjs`. The checks use temporary files and mocked GitHub requests; they do not access the active vault or make network requests. Node.js is required; Python is not used.

### Windows host with OpenSSH

Windows users can run the same loopback-only keypad behind the Windows OpenSSH Server. These steps require an elevated PowerShell window for server setup and a separate, standard local account for the tunnel:

1. Install or enable the OpenSSH Server capability if it is not already installed, then start its service:

   ```powershell
   Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
   Start-Service sshd
   ```

   If Windows reports that the capability is already installed, continue with the service setup.
2. Create a dedicated local account named `gitmesh-tunnel` that is **not** a member of Administrators. For example, in elevated PowerShell:

   ```powershell
   $password = Read-Host "Set a unique tunnel-account password" -AsSecureString
   New-LocalUser -Name "gitmesh-tunnel" -Password $password
   Remove-Variable password
   ```

   Sign in locally once as this account to create its Windows profile. In that account's session, create `.ssh\authorized_keys` under its profile (typically `C:\Users\gitmesh-tunnel\.ssh\authorized_keys`) and paste the iPhone SSH client's **public** key there. Keep the `.ssh` directory and key file writable only by the tunnel account and trusted administrators. Never copy the iPhone's private key to Windows or into GitMesh.
3. Add this key restriction to the `authorized_keys` line before the `ssh-ed25519` key type and public-key text. Replace the example key and comment with the iPhone client's public key:

   ```text
   restrict,port-forwarding,permitopen="127.0.0.1:8782" ssh-ed25519 <iPhone-public-key> iPhone-gitmesh-tunnel
   ```

   `restrict` disables optional key capabilities; `port-forwarding` enables forwarding for this key, while the server rules below limit it to the one local destination.
4. Add this account-specific block to `%ProgramData%\ssh\sshd_config`:

   ```text
   Match User gitmesh-tunnel
     AuthenticationMethods publickey
     PasswordAuthentication no
     AllowTcpForwarding local
     PermitOpen 127.0.0.1:8782
     GatewayPorts no
     PermitTTY no
     ForceCommand powershell.exe -NoLogo -NoProfile -NonInteractive -Command exit
   ```

   This requires public-key authentication, permits only client-side local forwarding to the keypad, and forces any remote command or shell request to exit without opening an interactive shell. Keep the `Match` block after the global settings it should override. Validate the configuration before restarting SSH, and keep an existing administrator session open while checking access:

   ```powershell
   & "$env:WINDIR\System32\OpenSSH\sshd.exe" -t
   Restart-Service sshd
   ```

5. In Windows Defender Firewall, restrict the inbound OpenSSH rule to the **Private** profile and `LocalSubnet`; disable any broader rule that would also allow SSH from other networks. Use trusted Wi-Fi or an existing private VPN only. Do not add a router port forward or expose SSH to the public internet.
6. Verify the Windows SSH host-key fingerprint before accepting it on the iPhone. In elevated PowerShell, display the host's Ed25519 fingerprint with:

   ```powershell
   ssh-keygen.exe -lf "$env:ProgramData\ssh\ssh_host_ed25519_key.pub"
   ```

   Compare that fingerprint with the one shown by the iPhone SSH client through a separate trusted channel; do not blindly accept an unknown host key.

For Windows-specific OpenSSH behavior, see Microsoft's [OpenSSH Server configuration for Windows](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh-server-configuration) and the [Win32 OpenSSH `sshd_config` reference](https://github.com/PowerShell/Win32-OpenSSH/wiki/sshd_config).


### iPhone

1. Install an iOS SSH client that supports local TCP forwarding reachable by Safari and a tunnel-only/no-shell session. Configure the host address as its private-network or private-VPN address, and forward the iPhone's **local port `8782`** to **`127.0.0.1:8782` on the host** (the default-port example). Keep the tunnel active. Some clients require their documented device-wide SSH/VPN feature for Safari to use the tunnel; review its traffic-routing behavior before enabling it. For a custom port, use that port for both the iPhone's local port and the host loopback destination, and update the SSH restrictions above to allow that destination.
2. In Safari on the iPhone, open `http://127.0.0.1:8782` (the default-port example). For a custom port, use `http://127.0.0.1:<port>` with the same port configured for the keypad and SSH forward. The server checks the request origin against its listening port and rejects mismatches.

The HTTP server still listens only on the host's loopback address. The SSH tunnel carries browser traffic to that loopback socket; sigil verification and vault reads/writes remain on the host. This does not make a Replit workspace's loopback port reachable from an iPhone, and the current Replit preview is not a private tunnel. If the only copy of the vault is in Replit, do not expose the HTTP service to make it reachable; the steps above require running the source and vault on a computer you control. Moving vault state is a separate operation and must use an encrypted bundle or an encrypted backup, never GitHub.

Use an SSH key only for the tunnel account and keep the phone locked. The tunnel protects traffic in transit, not data at rest; enable full-disk encryption on the host (such as FileVault, BitLocker, or LUKS). Compromised devices, screen recording, malicious browser extensions, keyloggers, or a person with access to an unlocked device can capture sigils and displayed records. The rotating keypad is input obfuscation, not encryption or a secure hardware keyboard.

The keypad accepts only ASCII letters, digits, hyphen, and underscore. If an existing legacy sigil contains other characters, use the terminal CLI to sign in and rotate it to a generated sigil before using the browser keypad.

The changing key labels are input obfuscation only. They are not a real language, encryption, a secure keyboard extension, or protection against a compromised device or software that can inspect the screen or browser. Sigil characters are entered through the visible buttons; a hardware keyboard can still navigate and activate those buttons for accessibility. The local browser console can add and list records and manually export/import Git bundles. New exports are encrypted before download; the existing terminal menu remains available.
