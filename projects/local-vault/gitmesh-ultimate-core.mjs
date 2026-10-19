import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const VAULT = path.join(ROOT, "SovereignMeshVault");
const AUTH_FILE = path.join(VAULT, "active_sigil.hash");
const LEDGER = path.join(VAULT, "ledger_matrix");
const INBOUND = path.join(VAULT, "drops_inbound");
const OUTBOUND = path.join(VAULT, "bundles_outbound");
const INTERNAL_GITIGNORE = [
  "active_sigil.hash",
  "security_audit.log",
  "drops_inbound/",
  "bundles_outbound/",
  "ledger_matrix/*",
  "!ledger_matrix/",
  "!ledger_matrix/*.json",
  "",
].join("\n");
const MAX_RECORDS = 1000;
const MAX_RECORD_BYTES = 64 * 1024;
const MAX_BUNDLE_BYTES = 100 * 1024 * 1024;
const MAX_AUTH_BYTES = 70 * 1024 * 1024;
const MAX_SIGIL_HISTORY = 1_000_000;
const SCRYPT_OPTIONS = { N: 32_768, r: 8, p: 1, maxmem: 128 * 1024 * 1024 };

function ensureDirectory(directory) {
  try {
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  } catch {
    throw new Error(`Could not create required directory: ${path.basename(directory)}`);
  }
  const info = fs.lstatSync(directory);
  if (!info.isDirectory() || info.isSymbolicLink()) {
    throw new Error(`Refusing to use a non-directory or symbolic link: ${path.basename(directory)}`);
  }
}

export function ensureVault() {
  ensureDirectory(VAULT);
  ensureDirectory(LEDGER);
  ensureDirectory(INBOUND);
  ensureDirectory(OUTBOUND);

  const gitDirectory = path.join(VAULT, ".git");
  if (fs.existsSync(gitDirectory) && fs.lstatSync(gitDirectory).isSymbolicLink()) {
    throw new Error("Refusing to use a symbolic link as the vault's Git metadata.");
  }

  const ignorePath = path.join(VAULT, ".gitignore");
  if (fs.existsSync(ignorePath)) {
    if (fs.lstatSync(ignorePath).isSymbolicLink() ||
        fs.readFileSync(ignorePath, "utf8") !== INTERNAL_GITIGNORE) {
      throw new Error("The vault's .gitignore is not the expected fixed file; refusing to continue.");
    }
  } else {
    fs.writeFileSync(ignorePath, INTERNAL_GITIGNORE, { flag: "wx", mode: 0o600 });
  }
  initializeGit();
}

function runGit(args, options = {}) {
  try {
    return execFileSync("git", args, {
      cwd: VAULT,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
      timeout: 30_000,
      maxBuffer: 2 * 1024 * 1024,
      ...options,
    }).trim();
  } catch (error) {
    const stderr = typeof error?.stderr === "string" ? error.stderr.trim() : "";
    const safeDetails = stderr
      .replace(/[\u0000-\u001f\u007f\u2028\u2029]/g, " ")
      .slice(0, 500);
    throw new Error(safeDetails ? `Git operation failed: ${safeDetails}` : "Git operation failed.");
  }
}

function initializeGit() {
  const gitDirectory = path.join(VAULT, ".git");
  if (!fs.existsSync(gitDirectory)) {
    runGit(["init"]);
    runGit(["branch", "-M", "main"]);
  } else {
    const isRepo = runGit(["rev-parse", "--is-inside-work-tree"]);
    if (isRepo !== "true") throw new Error("The vault's Git repository is invalid.");
    const branch = runGit(["branch", "--show-current"]);
    if (branch !== "main") throw new Error("The vault's active branch must be named main.");
  }

  runGit(["config", "user.name", "GitMesh Local"]);
  runGit(["config", "user.email", "gitmesh-local@localhost"]);

  let existingIgnore = null;
  try {
    runGit(["rev-parse", "--verify", "main"]);
    existingIgnore = runGit(["show", "main:.gitignore"]);
  } catch {
    // A new repository has no commit yet; its fixed ignore file is the first commit.
  }

  if (existingIgnore !== INTERNAL_GITIGNORE.trimEnd()) {
    const staged = runGit(["status", "--porcelain", "--untracked-files=no"]);
    if (staged) throw new Error("The vault repository has unexpected tracked changes.");
    fs.writeFileSync(path.join(VAULT, ".gitignore"), INTERNAL_GITIGNORE, { mode: 0o600 });
    runGit(["add", "--", ".gitignore"]);
    runGit(["commit", "-m", existingIgnore === null ? "Initialize local vault" : "Restore local vault ignore rules"]);
  }
}

function promptLine(promptText) {
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    return Promise.reject(new Error("Run this program in an interactive terminal."));
  }
  return new Promise((resolve, reject) => {
    let value = "";
    const finish = (error) => {
      process.stdin.off("data", onData);
      process.stdin.setRawMode(false);
      process.stdin.pause();
      process.stdout.write("\n");
      if (error) reject(error);
      else resolve(value);
    };
    const onData = (chunk) => {
      for (const character of chunk.toString("utf8")) {
        if (character === "\u0003") return finish(new Error("Input cancelled."));
        if (character === "\u0004") return finish(new Error("Input cancelled."));
        if (character === "\r" || character === "\n") return finish();
        if (character === "\u007f" || character === "\b") {
          if (value.length > 0) {
            value = value.slice(0, -1);
            process.stdout.write("\b \b");
          }
          continue;
        }
        if (character >= " " && character !== "\u007f" && value.length < 256) {
          value += character;
          process.stdout.write("*");
        }
      }
    };

    try {
      process.stdin.setRawMode(true);
      process.stdin.setEncoding("utf8");
      process.stdin.resume();
      process.stdin.on("data", onData);
      process.stdout.write(promptText);
    } catch {
      try { process.stdin.setRawMode(false); } catch {}
      reject(new Error("This terminal does not support hidden sigil input."));
    }
  });
}

function promptText(promptTextValue) {
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    return Promise.reject(new Error("Run this program in an interactive terminal."));
  }
  return new Promise((resolve) => {
    process.stdout.write(promptTextValue);
    let value = "";
    const onData = (chunk) => {
      for (const character of chunk.toString("utf8")) {
        if (character === "\u0003") {
          process.stdin.off("data", onData);
          process.stdin.pause();
          process.stdout.write("\n");
          resolve("");
          return;
        }
        if (character === "\r" || character === "\n") {
          process.stdin.off("data", onData);
          process.stdin.pause();
          process.stdout.write("\n");
          resolve(value);
          return;
        }
        if (character === "\u007f" || character === "\b") value = value.slice(0, -1);
        else if (character >= " " && value.length < 512) value += character;
      }
    };
    process.stdin.setEncoding("utf8");
    process.stdin.resume();
    process.stdin.on("data", onData);
  });
}

function deriveSigilVerifier(sigil, salt) {
  return crypto.scryptSync(sigil, salt, 64, SCRYPT_OPTIONS).toString("hex");
}

function fingerprintSigil(sigil) {
  return crypto.createHash("sha256").update(sigil, "utf8").digest("hex");
}

function makeAuthRecord(sigil, generation, usedSigilHashes) {
  const auth = {
    version: 2,
    salt: crypto.randomBytes(16).toString("hex"),
    verifier: "",
    generation,
    usedSigilHashes,
  };
  auth.verifier = deriveSigilVerifier(sigil, auth.salt);
  return auth;
}

function readAuth(authFile = AUTH_FILE) {
  if (!fs.existsSync(authFile)) return null;
  const info = fs.lstatSync(authFile);
  if (!info.isFile() || info.isSymbolicLink() || info.size > MAX_AUTH_BYTES) {
    throw new Error("The local credential file is invalid.");
  }
  let auth;
  try {
    auth = JSON.parse(fs.readFileSync(authFile, "utf8"));
  } catch {
    throw new Error("The local credential file is invalid.");
  }
  if (!auth || typeof auth !== "object" ||
      (auth.version !== 1 && auth.version !== 2) ||
      !/^[a-f0-9]{32}$/.test(auth.salt ?? "") ||
      !/^[a-f0-9]{128}$/.test(auth.verifier ?? "")) {
    throw new Error("The local credential file is invalid.");
  }
  if (auth.version === 2 &&
      (!Number.isSafeInteger(auth.generation) ||
       auth.generation < 0 ||
       !Array.isArray(auth.usedSigilHashes) ||
       auth.usedSigilHashes.length > MAX_SIGIL_HISTORY ||
       auth.usedSigilHashes.some((hash) => !/^[a-f0-9]{64}$/.test(hash)) ||
       new Set(auth.usedSigilHashes).size !== auth.usedSigilHashes.length)) {
    throw new Error("The local credential file is invalid.");
  }
  return auth;
}

export function saveAuth(auth, authFile = AUTH_FILE, {
  renameSync = fs.renameSync,
  writeFileSync = fs.writeFileSync,
  linkSync = fs.linkSync,
  exclusive = false,
} = {}) {
  const temporaryPath = path.join(path.dirname(authFile), `.auth-${crypto.randomUUID()}.tmp`);
  try {
    writeFileSync(temporaryPath, `${JSON.stringify(auth)}\n`, { flag: "wx", mode: 0o600 });
    if (exclusive) {
      try {
        linkSync(temporaryPath, authFile);
      } catch (error) {
        if (error?.code === "EEXIST") {
          throw new Error("An admin sigil was set up by another process; no credential was changed.");
        }
        throw error;
      }
      try { fs.unlinkSync(temporaryPath); } catch {}
      return;
    }
    renameSync(temporaryPath, authFile);
  } catch (error) {
    try { fs.unlinkSync(temporaryPath); } catch {}
    throw error;
  }
}

function verifySigil(sigil, auth) {
  const actual = Buffer.from(deriveSigilVerifier(sigil, auth.salt), "hex");
  const expected = Buffer.from(auth.verifier, "hex");
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

function generateNextSigil(generation, currentSigil, usedHashes) {
  if (!Number.isSafeInteger(generation) || generation < 1) {
    throw new Error("The sigil generation counter is invalid.");
  }
  for (let attempt = 0; attempt < 32; attempt += 1) {
    const sigil = `gm-${generation}-${crypto.randomBytes(32).toString("base64url")}`;
    const fingerprint = fingerprintSigil(sigil);
    if (sigil !== currentSigil && !usedHashes.has(fingerprint)) return sigil;
  }
  throw new Error("Could not generate a unique admin sigil.");
}

export async function setupOrAuthenticate({
  authFile = AUTH_FILE,
  promptLineFn = promptLine,
  promptTextFn = promptText,
  saveAuthFn = saveAuth,
  log = console.log,
} = {}) {
  const auth = readAuth(authFile);
  if (!auth) {
    log("First run: choose an initial admin sigil of at least 12 characters.");
    const first = await promptLineFn("New admin sigil: ");
    const confirmation = await promptLineFn("Confirm admin sigil: ");
    if (first.length < 12) throw new Error("Admin sigil must contain at least 12 characters.");
    if (first !== confirmation) throw new Error("Admin sigils did not match.");
    const initialAuth = makeAuthRecord(first, 0, []);
    saveAuthFn(initialAuth, authFile, { exclusive: true });
    log("Admin sigil verifier saved locally. The sigil itself was not saved.");
    log("On each later successful sign-in, GitMesh will issue a replacement sigil.");
    return { auth: initialAuth, currentSigil: first };
  }

  const attempt = await promptLineFn("Current admin sigil (hidden): ");
  if (!verifySigil(attempt, auth)) throw new Error("Access denied.");

  const usedSigilHashes = auth.version === 2 ? auth.usedSigilHashes : [];
  const currentFingerprint = fingerprintSigil(attempt);
  const usedHashes = new Set(usedSigilHashes);
  if (usedHashes.has(currentFingerprint)) {
    throw new Error("The local credential history is inconsistent; access was not granted.");
  }
  if (usedSigilHashes.length >= MAX_SIGIL_HISTORY) {
    throw new Error("The sigil history limit has been reached; no sigil was consumed.");
  }

  const nextGeneration = (auth.version === 2 ? auth.generation : 0) + 1;
  if (!Number.isSafeInteger(nextGeneration)) {
    throw new Error("The sigil generation limit has been reached; no sigil was consumed.");
  }
  usedHashes.add(currentFingerprint);
  const nextSigil = generateNextSigil(nextGeneration, attempt, usedHashes);
  const nextAuth = makeAuthRecord(nextSigil, nextGeneration, [...usedHashes]);

  log("\nYour previous sigil will be invalidated when you confirm saving this replacement.");
  log("Copy and store this new admin sigil securely; it is shown only once:");
  log(`\n${nextSigil}\n`);
  const confirmation = await promptTextFn("Type SAVED to activate it and open the console: ");
  if (confirmation !== "SAVED") {
    throw new Error("Rotation cancelled. The previous sigil remains valid; access was not granted.");
  }

  saveAuthFn(nextAuth, authFile);
  log("Sigil rotated. The previous sigil is now invalid.");
  return { auth: nextAuth, currentSigil: nextSigil };
}

function cleanText(value, label, maxLength) {
  const normalized = value.normalize("NFC").replace(/[\u0000-\u001f\u007f\u2028\u2029]/g, " ").trim();
  if (!normalized) throw new Error(`${label} is required.`);
  if (normalized.length > maxLength) throw new Error(`${label} must be ${maxLength} characters or fewer.`);
  return normalized;
}

function unsignedRecord(record) {
  return {
    "@context": "https://gitmesh.local/schema/v1",
    "@type": "MeshRecord",
    id: record.id,
    createdAt: record.createdAt,
    targetNode: record.targetNode,
    objectiveScope: record.objectiveScope,
  };
}

function createRecord(targetNode, objectiveScope) {
  const base = {
    id: crypto.randomUUID(),
    createdAt: new Date().toISOString(),
    targetNode: cleanText(targetNode, "Node name", 120),
    objectiveScope: cleanText(objectiveScope, "Purpose", 1000),
  };
  const record = unsignedRecord(base);
  record.securityHash = crypto.createHash("sha256").update(JSON.stringify(record)).digest("hex");
  return record;
}

function validateRecord(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Invalid record format.");
  const allowed = new Set(["@context", "@type", "id", "createdAt", "targetNode", "objectiveScope", "securityHash"]);
  if (Object.keys(value).some((key) => !allowed.has(key)) || Object.keys(value).length !== allowed.size) {
    throw new Error("Record contains missing or unexpected fields.");
  }
  if (value["@context"] !== "https://gitmesh.local/schema/v1" || value["@type"] !== "MeshRecord") {
    throw new Error("Unsupported record type.");
  }
  if (!/^[0-9a-f-]{36}$/i.test(value.id) || !Number.isFinite(Date.parse(value.createdAt))) {
    throw new Error("Record ID or timestamp is invalid.");
  }
  if (cleanText(value.targetNode, "Node name", 120) !== value.targetNode ||
      cleanText(value.objectiveScope, "Purpose", 1000) !== value.objectiveScope) {
    throw new Error("Record text contains unsupported characters or formatting.");
  }
  if (!/^[a-f0-9]{64}$/.test(value.securityHash)) throw new Error("Record checksum is invalid.");
  const expected = crypto.createHash("sha256").update(JSON.stringify(unsignedRecord(value))).digest();
  const actual = Buffer.from(value.securityHash, "hex");
  if (!crypto.timingSafeEqual(expected, actual)) throw new Error(`Record checksum mismatch: ${value.id}`);
  return value;
}

function readRecordFile(filename) {
  if (!/^[0-9a-f-]{36}\.json$/i.test(filename)) throw new Error("Unexpected ledger filename.");
  const filePath = path.join(LEDGER, filename);
  const info = fs.lstatSync(filePath);
  if (!info.isFile() || info.isSymbolicLink() || info.size > MAX_RECORD_BYTES) {
    throw new Error(`Invalid ledger file: ${filename}`);
  }
  const data = JSON.parse(fs.readFileSync(filePath, "utf8"));
  const record = validateRecord(data);
  if (`${record.id}.json`.toLowerCase() !== filename.toLowerCase()) {
    throw new Error(`Ledger filename does not match record ID: ${filename}`);
  }
  return record;
}

function listRecordFiles() {
  return fs.readdirSync(LEDGER).filter((name) => name.toLowerCase().endsWith(".json"));
}

export function listLocalRecords() {
  const files = listRecordFiles();
  if (files.length > MAX_RECORDS) throw new Error(`Ledger exceeds the ${MAX_RECORDS}-record limit.`);
  return files.map(readRecordFile).sort((a, b) => a.createdAt.localeCompare(b.createdAt));
}

function verifyLedger() {
  const records = listLocalRecords();
  console.log(`Verified ${records.length} local record(s).`);
  for (const record of records) {
    console.log(`${record.createdAt}  ${record.targetNode}  ${record.objectiveScope}`);
  }
  return records;
}

function commitFiles(files, message) {
  if (!files.length) return;
  runGit(["add", "--", ...files]);
  runGit(["commit", "-m", message]);
}

export function addLocalRecord(targetNode, objectiveScope) {
  const record = createRecord(targetNode, objectiveScope);
  if (listRecordFiles().length >= MAX_RECORDS) throw new Error(`The ledger is limited to ${MAX_RECORDS} records.`);
  const filename = `${record.id}.json`;
  const filePath = path.join(LEDGER, filename);
  const serialized = `${JSON.stringify(record, null, 2)}\n`;
  if (Buffer.byteLength(serialized) > MAX_RECORD_BYTES) throw new Error("Record is too large.");
  fs.writeFileSync(filePath, serialized, { flag: "wx", mode: 0o600 });
  try {
    commitFiles([`ledger_matrix/${filename}`], `Add local record ${record.id}`);
  } catch (error) {
    try { runGit(["reset", "--", `ledger_matrix/${filename}`]); } catch {}
    try { fs.unlinkSync(filePath); } catch {}
    throw error;
  }
  return record;
}

async function addRecord() {
  const targetNode = await promptText("Node name: ");
  const objectiveScope = await promptText("Purpose: ");
  const record = addLocalRecord(targetNode, objectiveScope);
  console.log(`Saved and verified record ${record.id}.`);
}

export function exportBundle() {
  listLocalRecords();
  validateBundleTree("main");
  const filename = `mesh_snapshot_${new Date().toISOString().replace(/[:.]/g, "-")}_${crypto.randomUUID().slice(0, 8)}.bundle`;
  const bundlePath = path.join(OUTBOUND, filename);
  runGit(["bundle", "create", bundlePath, "main"]);
  console.log(`Exported bundle: ${path.relative(ROOT, bundlePath)}`);
  console.log("Bundles are not encrypted. Transfer them only through a channel you trust.");
  return filename;
}

function safeBundlePath(filename) {
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,120}\.bundle$/.test(filename)) {
    throw new Error("Invalid bundle filename.");
  }
  const bundlePath = path.join(INBOUND, filename);
  const info = fs.lstatSync(bundlePath);
  if (!info.isFile() || info.isSymbolicLink()) throw new Error("The selected bundle is not a regular file.");
  if (info.size <= 0 || info.size > MAX_BUNDLE_BYTES) throw new Error("Bundle must be between 1 byte and 100 MiB.");
  return bundlePath;
}

function validateBundleTree(ref) {
  const names = runGit(["ls-tree", "-r", "--name-only", ref]).split("\n").filter(Boolean);
  if (!names.includes(".gitignore") ||
      names.some((name) => name !== ".gitignore" && !/^ledger_matrix\/[0-9a-f-]{36}\.json$/i.test(name))) {
    throw new Error("Bundle contains paths outside the allowed ledger format.");
  }
  const bundleIgnore = runGit(["show", `${ref}:.gitignore`]);
  if (bundleIgnore !== INTERNAL_GITIGNORE.trimEnd()) throw new Error("Bundle has unexpected ignore rules.");

  const records = [];
  for (const name of names.filter((item) => item.startsWith("ledger_matrix/"))) {
    const contents = runGit(["show", `${ref}:${name}`]);
    if (Buffer.byteLength(contents) > MAX_RECORD_BYTES) throw new Error("Bundle contains an oversized record.");
    const record = validateRecord(JSON.parse(contents));
    if (`ledger_matrix/${record.id}.json`.toLowerCase() !== name.toLowerCase()) {
      throw new Error("Bundle record filename does not match its record ID.");
    }
    records.push({ record, contents: `${JSON.stringify(record, null, 2)}\n` });
  }
  if (records.length > MAX_RECORDS) throw new Error("Bundle contains too many records.");
  return records;
}

export function listInboundBundles() {
  return fs.readdirSync(INBOUND)
    .filter((name) => name.endsWith(".bundle"))
    .filter((name) => {
      try { safeBundlePath(name); return true; } catch { return false; }
    });
}

export function importBundle(filename) {
  const bundlePath = safeBundlePath(filename);
  runGit(["bundle", "verify", bundlePath]);
  const heads = runGit(["bundle", "list-heads", bundlePath]).split("\n").filter(Boolean);
  const mainHeads = heads.filter((line) => /\srefs\/heads\/main$/.test(line));
  if (mainHeads.length !== 1 || heads.length !== 1) {
    throw new Error("Bundle must contain exactly one branch named main.");
  }

  const importRef = `refs/mesh-import/${crypto.randomUUID()}`;
  runGit(["fetch", "--no-tags", bundlePath, `refs/heads/main:${importRef}`]);
  try {
    const imported = validateBundleTree(importRef);
    const existing = new Map();
    for (const name of listRecordFiles()) {
      const record = readRecordFile(name);
      existing.set(record.id.toLowerCase(), fs.readFileSync(path.join(LEDGER, name), "utf8"));
    }

    const toWrite = [];
    for (const entry of imported) {
      const id = entry.record.id.toLowerCase();
      const previous = existing.get(id);
      if (previous !== undefined && previous !== entry.contents) {
        throw new Error(`Bundle conflicts with local record ${entry.record.id}; no records were imported.`);
      }
      if (previous === undefined) toWrite.push(entry);
    }
    if (existing.size + toWrite.length > MAX_RECORDS) {
      throw new Error(`Import would exceed the ${MAX_RECORDS}-record limit.`);
    }

    const written = [];
    try {
      for (const { record, contents } of toWrite) {
        const filename = `${record.id}.json`;
        fs.writeFileSync(path.join(LEDGER, filename), contents, { flag: "wx", mode: 0o600 });
        written.push(`ledger_matrix/${filename}`);
      }
      commitFiles(written, `Import ${written.length} record(s) from bundle`);
    } catch (error) {
      for (const relativePath of written) {
        try { fs.unlinkSync(path.join(VAULT, relativePath)); } catch {}
      }
      throw error;
    }
    const result = {
      imported: toWrite.length,
      duplicates: imported.length - toWrite.length,
    };
    console.log(`Imported ${result.imported} new record(s); ${result.duplicates} duplicate(s) were skipped.`);
    return result;
  } finally {
    try { runGit(["update-ref", "-d", importRef]); } catch {}
  }
}

async function importFromMenu() {
  const bundles = fs.readdirSync(INBOUND)
    .filter((name) => name.endsWith(".bundle"))
    .filter((name) => {
      try { safeBundlePath(name); return true; } catch { return false; }
    });
  if (!bundles.length) {
    console.log(`No usable bundles found in ${path.relative(ROOT, INBOUND)}.`);
    return;
  }
  bundles.forEach((name, index) => console.log(`${index + 1}. ${name}`));
  const selection = await promptText("Choose a bundle number (or press Enter to cancel): ");
  if (!selection) return;
  if (!/^\d+$/.test(selection)) throw new Error("Enter a bundle number from the list.");
  const index = Number(selection) - 1;
  if (index < 0 || index >= bundles.length) throw new Error("Bundle number is out of range.");
  importBundle(bundles[index]);
}

export async function changeSigil(session, {
  authFile = AUTH_FILE,
  promptLineFn = promptLine,
  saveAuthFn = saveAuth,
  log = console.log,
} = {}) {
  const first = await promptLineFn("New admin sigil: ");
  const confirmation = await promptLineFn("Confirm new admin sigil: ");
  if (first.length < 12) throw new Error("Admin sigil must contain at least 12 characters.");
  if (first !== confirmation) throw new Error("Admin sigils did not match.");

  const usedSigilHashes = [...session.auth.usedSigilHashes];
  const currentFingerprint = fingerprintSigil(session.currentSigil);
  const newFingerprint = fingerprintSigil(first);
  if (usedSigilHashes.length >= MAX_SIGIL_HISTORY) {
    throw new Error("The sigil history limit has been reached; the current sigil was not changed.");
  }
  if (newFingerprint === currentFingerprint || usedSigilHashes.includes(newFingerprint)) {
    throw new Error("Choose a sigil that has never been used before.");
  }

  usedSigilHashes.push(currentFingerprint);
  const updatedAuth = makeAuthRecord(first, session.auth.generation, usedSigilHashes);
  saveAuthFn(updatedAuth, authFile);
  session.auth = updatedAuth;
  session.currentSigil = first;
  log("Admin sigil updated. The previous sigil is now invalid.");
}

async function runMenu(session) {
  while (true) {
    console.log("\nGitMesh local console");
    console.log("1. Add a local record");
    console.log("2. Verify and list records");
    console.log("3. Export a Git bundle");
    console.log("4. Import a bundle from drops_inbound");
    console.log("5. Change admin sigil");
    console.log("0. Exit");
    const choice = await promptText("Select: ");
    try {
      if (choice === "1") await addRecord();
      else if (choice === "2") verifyLedger();
      else if (choice === "3") exportBundle();
      else if (choice === "4") await importFromMenu();
      else if (choice === "5") await changeSigil(session);
      else if (choice === "0") return;
      else console.log("Choose one of the listed menu numbers.");
    } catch (error) {
      console.error(error instanceof Error ? error.message : "The operation failed.");
    }
  }
}

async function main() {
  if (process.argv.length !== 2) {
    console.error("This program does not accept command-line arguments.");
    process.exitCode = 2;
    return;
  }
  try {
    ensureVault();
    const session = await setupOrAuthenticate();
    await runMenu(session);
  } catch (error) {
    console.error(error instanceof Error ? error.message : "The program could not continue.");
    process.exitCode = 1;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main();
}
