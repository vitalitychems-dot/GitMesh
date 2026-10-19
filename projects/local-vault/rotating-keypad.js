"use strict";

const ui = {
  authPanel: document.querySelector("#auth-panel"),
  authMode: document.querySelector("#auth-mode"),
  authTitle: document.querySelector("#auth-title"),
  authHelp: document.querySelector("#auth-help"),
  setupStepper: document.querySelector("#setup-stepper"),
  entryDisplay: document.querySelector("#entry-display"),
  keyHint: document.querySelector("#key-hint"),
  keyboard: document.querySelector("#keyboard"),
  lettersTab: document.querySelector("#letters-tab"),
  symbolsTab: document.querySelector("#symbols-tab"),
  caseToggle: document.querySelector("#case-toggle"),
  setupActions: document.querySelector("#setup-actions"),
  setupNext: document.querySelector("#setup-next"),
  setupCreate: document.querySelector("#setup-create"),
  loginActions: document.querySelector("#login-actions"),
  signIn: document.querySelector("#sign-in"),
  rotationPanel: document.querySelector("#rotation-panel"),
  newSigil: document.querySelector("#new-sigil"),
  confirmSaved: document.querySelector("#confirm-saved"),
  cancelRotation: document.querySelector("#cancel-rotation"),
  copySigil: document.querySelector("#copy-sigil"),
  vaultPanel: document.querySelector("#vault-panel"),
  signOut: document.querySelector("#sign-out"),
  recordForm: document.querySelector("#record-form"),
  recordList: document.querySelector("#record-list"),
  exportBundle: document.querySelector("#export-bundle"),
  refreshBundles: document.querySelector("#refresh-bundles"),
  bundleList: document.querySelector("#bundle-list"),
  bundleDownload: document.querySelector("#bundle-download"),
  notice: document.querySelector("#notice"),
  backspace: document.querySelector("#backspace"),
  clearEntry: document.querySelector("#clear-entry"),
};

const state = {
  setup: false,
  setupStep: 0,
  challengeId: "",
  keys: [],
  entered: [],
  firstEntry: [],
  layout: "letters",
  uppercase: false,
  pendingAttempt: "",
  pendingSigil: "",
};

function showNotice(message, isError = false) {
  ui.notice.textContent = message;
  ui.notice.classList.toggle("error", isError);
}

async function api(url, { method = "GET", body } = {}) {
  const response = await fetch(url, {
    method,
    credentials: "same-origin",
    headers: body ? { "Content-Type": "application/json" } : {},
    body: body ? JSON.stringify(body) : undefined,
    cache: "no-store",
  });
  let result;
  try {
    result = await response.json();
  } catch {
    throw new Error("The local vault returned an unreadable response.");
  }
  if (!response.ok) throw new Error(result.error || "The request could not be completed.");
  return result;
}

function renderEntry() {
  const count = state.entered.length;
  ui.entryDisplay.classList.toggle("empty", count === 0);
  ui.entryDisplay.textContent = count ? "• ".repeat(count).trim() : "No characters entered";
  ui.entryDisplay.setAttribute("aria-label", count ? `${count} characters entered` : "No characters entered");
}

function resetEntry() {
  state.entered = [];
  renderEntry();
}

function setLayout(layout) {
  state.layout = layout;
  ui.lettersTab.classList.toggle("selected", layout === "letters");
  ui.symbolsTab.classList.toggle("selected", layout === "symbols");
  ui.lettersTab.setAttribute("aria-pressed", String(layout === "letters"));
  ui.symbolsTab.setAttribute("aria-pressed", String(layout === "symbols"));
  renderKeyboard();
}

function renderKeyboard() {
  ui.keyboard.replaceChildren();
  const available = state.layout === "letters"
    ? state.keys.filter((key) => /[a-z]/.test(key.label) && key.label.length === 1)
    : state.keys.filter((key) => /[0-9_-]/.test(key.label) && key.label.length === 1);

  for (const key of available) {
    const displayLabel = state.layout === "letters" && state.uppercase
      ? key.label.toUpperCase()
      : key.label;
    const mapped = state.keys.find((item) => item.label === displayLabel);
    if (!mapped) continue;

    const button = document.createElement("button");
    button.type = "button";
    button.className = "key";
    button.textContent = displayLabel;
    button.setAttribute("aria-label", `English key ${displayLabel}. Hold to reveal its randomized session code.`);
    let hintTimer;
    button.addEventListener("pointerdown", () => {
      hintTimer = window.setTimeout(() => {
        ui.keyHint.textContent = `Session code for ${displayLabel}: ${mapped.glyph}`;
      }, 430);
    });
    const clearHint = () => {
      window.clearTimeout(hintTimer);
      window.setTimeout(() => {
        ui.keyHint.textContent = "Hold a key to view its session code.";
      }, 2200);
    };
    button.addEventListener("pointerup", clearHint);
    button.addEventListener("pointercancel", clearHint);
    button.addEventListener("pointerleave", clearHint);
    button.addEventListener("click", () => {
      if (state.entered.length >= 256) {
        showNotice("The sigil is too long for this keypad.", true);
        return;
      }
      state.entered.push(mapped.token);
      renderEntry();
      showNotice("");
    });
    ui.keyboard.append(button);
  }
}

function initializeAuthPanel() {
  ui.authPanel.hidden = false;
  ui.rotationPanel.hidden = true;
  ui.vaultPanel.hidden = true;
  ui.authMode.textContent = state.setup ? "FIRST-TIME SETUP" : "ADMIN ACCESS";
  ui.authTitle.textContent = state.setup ? "Choose an initial sigil" : "Enter your sigil";
  ui.authHelp.textContent = state.setup
    ? "Create at least 12 characters using letters, numbers, hyphen, or underscore, then enter them again to confirm."
    : "Tap the English keys. Hold one to reveal its randomized code. For a legacy sigil with other characters, use the terminal to rotate it first.";
  ui.setupActions.hidden = !state.setup;
  ui.loginActions.hidden = state.setup;
  ui.setupStepper.hidden = !state.setup;
  ui.setupCreate.hidden = !state.setup || state.setupStep !== 1;
  ui.setupNext.hidden = !state.setup || state.setupStep !== 0;
  ui.setupStepper.textContent = state.setup
    ? `Step ${state.setupStep + 1} of 2 · ${state.setupStep === 0 ? "Choose sigil" : "Confirm sigil"}`
    : "";
  resetEntry();
  renderKeyboard();
}

async function refreshKeymap() {
  const result = await api("/api/keymap");
  state.challengeId = result.id;
  state.keys = result.keys;
  renderKeyboard();
}

async function unlockVault() {
  ui.authPanel.hidden = true;
  ui.rotationPanel.hidden = true;
  ui.vaultPanel.hidden = false;
  ui.bundleDownload.hidden = true;
  showNotice(state.setup ? "Local sigil created. Future successful sign-ins rotate it." : "Vault unlocked on this device.");
  state.setup = false;
  await loadRecords();
  await loadBundles();
}

async function loadRecords() {
  const result = await api("/api/records");
  ui.recordList.replaceChildren();
  if (!result.records.length) {
    const empty = document.createElement("li");
    empty.className = "record-card";
    empty.textContent = "No records yet.";
    ui.recordList.append(empty);
    return;
  }
  for (const record of result.records) {
    const item = document.createElement("li");
    item.className = "record-card";
    const time = document.createElement("time");
    const date = new Date(record.createdAt);
    time.dateTime = record.createdAt;
    time.textContent = Number.isNaN(date.valueOf()) ? "Saved locally" : date.toLocaleString();
    const name = document.createElement("strong");
    name.textContent = record.targetNode;
    const purpose = document.createElement("p");
    purpose.textContent = record.objectiveScope;
    item.append(time, name, purpose);
    ui.recordList.append(item);
  }
}

async function loadBundles() {
  const result = await api("/api/inbound");
  ui.bundleList.replaceChildren();
  if (!result.bundles.length) {
    const empty = document.createElement("li");
    empty.className = "bundle-card";
    empty.textContent = "No valid bundles in the inbound folder.";
    ui.bundleList.append(empty);
    return;
  }
  for (const filename of result.bundles) {
    const item = document.createElement("li");
    item.className = "bundle-card";
    const label = document.createElement("span");
    label.textContent = filename;
    const button = document.createElement("button");
    button.type = "button";
    button.className = "quiet-button";
    button.textContent = "Import";
    button.setAttribute("aria-label", `Import ${filename}`);
    button.addEventListener("click", async () => {
      if (!window.confirm(`Import records from ${filename}? Existing records are kept.`)) return;
      button.disabled = true;
      try {
        const imported = await api("/api/import", { method: "POST", body: { filename } });
        showNotice(`Import complete: ${imported.imported} added, ${imported.duplicates} already present.`);
        await loadRecords();
      } catch (error) {
        showNotice(error.message, true);
      } finally {
        button.disabled = false;
      }
    });
    item.append(label, button);
    ui.bundleList.append(item);
  }
}

function readAuthEntry() {
  return [...state.entered];
}

async function startSignIn(first, confirmation) {
  const body = { challengeId: state.challengeId, first };
  if (confirmation) body.confirmation = confirmation;
  ui.signIn.disabled = true;
  ui.setupCreate.disabled = true;
  try {
    const result = await api("/api/auth/start", { method: "POST", body });
    if (result.state === "save-new-sigil") {
      state.pendingAttempt = result.attemptId;
      state.pendingSigil = result.nextSigil;
      ui.authPanel.hidden = true;
      ui.rotationPanel.hidden = false;
      ui.newSigil.textContent = result.nextSigil;
      showNotice("");
      return;
    }
    if (result.state === "authenticated") {
      await unlockVault();
      return;
    }
    showNotice("Sign-in cancelled. Your current sigil remains valid.", true);
    await refreshKeymap();
    initializeAuthPanel();
  } catch (error) {
    showNotice(error.message, true);
    try {
      await refreshKeymap();
      initializeAuthPanel();
    } catch {
      showNotice("Could not refresh the keypad. Reload this page and try again.", true);
    }
  } finally {
    ui.signIn.disabled = false;
    ui.setupCreate.disabled = false;
  }
}

ui.lettersTab.addEventListener("click", () => setLayout("letters"));
ui.symbolsTab.addEventListener("click", () => setLayout("symbols"));
ui.caseToggle.addEventListener("click", () => {
  state.uppercase = !state.uppercase;
  ui.caseToggle.setAttribute("aria-pressed", String(state.uppercase));
  ui.caseToggle.textContent = state.uppercase ? "Lowercase" : "Uppercase";
  renderKeyboard();
});
ui.backspace.addEventListener("click", () => {
  state.entered.pop();
  renderEntry();
});
ui.clearEntry.addEventListener("click", resetEntry);

ui.setupNext.addEventListener("click", () => {
  if (state.entered.length < 12) {
    showNotice("Use at least 12 characters for the initial sigil.", true);
    return;
  }
  state.firstEntry = readAuthEntry();
  state.setupStep = 1;
  resetEntry();
  initializeAuthPanel();
});

ui.setupCreate.addEventListener("click", () => {
  if (state.entered.length < 12 || state.entered.length !== state.firstEntry.length ||
      !state.entered.every((token, index) => token === state.firstEntry[index])) {
    showNotice("The confirmation must exactly match the first entry and contain at least 12 characters.", true);
    return;
  }
  startSignIn(state.firstEntry, readAuthEntry());
});

ui.signIn.addEventListener("click", () => {
  if (state.entered.length < 1) {
    showNotice("Enter your sigil using the on-screen keys.", true);
    return;
  }
  startSignIn(readAuthEntry());
});

ui.copySigil.addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(state.pendingSigil);
    showNotice("Replacement sigil copied. Store it somewhere safe before unlocking.");
  } catch {
    showNotice("Copy was blocked. Select the displayed sigil and copy it manually.", true);
  }
});

ui.confirmSaved.addEventListener("click", async () => {
  ui.confirmSaved.disabled = true;
  try {
    const result = await api("/api/auth/confirm", {
      method: "POST",
      body: { attemptId: state.pendingAttempt, saved: true },
    });
    if (result.state !== "authenticated") throw new Error("The sigil was not saved and access was not granted.");
    state.pendingAttempt = "";
    state.pendingSigil = "";
    ui.newSigil.textContent = "";
    await unlockVault();
  } catch (error) {
    showNotice(error.message, true);
  } finally {
    ui.confirmSaved.disabled = false;
  }
});

ui.cancelRotation.addEventListener("click", async () => {
  try {
    await api("/api/auth/confirm", {
      method: "POST",
      body: { attemptId: state.pendingAttempt, saved: false },
    });
  } catch {
    // Expired attempts already leave the current sigil in place.
  }
  state.pendingAttempt = "";
  state.pendingSigil = "";
  ui.newSigil.textContent = "";
  ui.rotationPanel.hidden = true;
  await refreshKeymap();
  initializeAuthPanel();
  showNotice("Rotation cancelled. Your previous sigil remains valid.");
});

ui.signOut.addEventListener("click", async () => {
  try {
    await api("/api/auth/logout", { method: "POST", body: {} });
  } catch {
    // Local session expires automatically if the request fails.
  }
  ui.vaultPanel.hidden = true;
  state.setup = false;
  state.setupStep = 0;
  state.firstEntry = [];
  await refreshKeymap();
  initializeAuthPanel();
  showNotice("Vault locked.");
});

ui.recordForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(ui.recordForm);
  const targetNode = String(form.get("targetNode") ?? "").trim();
  const objectiveScope = String(form.get("objectiveScope") ?? "").trim();
  try {
    await api("/api/records", {
      method: "POST",
      body: { targetNode, objectiveScope },
    });
    ui.recordForm.reset();
    await loadRecords();
    showNotice("Record saved in the local vault.");
  } catch (error) {
    showNotice(error.message, true);
  }
});

ui.exportBundle.addEventListener("click", async () => {
  ui.exportBundle.disabled = true;
  try {
    const result = await api("/api/export", { method: "POST", body: {} });
    ui.bundleDownload.href = result.download;
    ui.bundleDownload.textContent = `Download ${result.filename}`;
    ui.bundleDownload.hidden = false;
    showNotice("Bundle exported. It is not encrypted; download it only for transfer through a trusted channel.");
  } catch (error) {
    showNotice(error.message, true);
  } finally {
    ui.exportBundle.disabled = false;
  }
});

ui.refreshBundles.addEventListener("click", async () => {
  try {
    await loadBundles();
    showNotice("Inbound folder checked.");
  } catch (error) {
    showNotice(error.message, true);
  }
});

async function boot() {
  try {
    const [vaultState, keymap] = await Promise.all([api("/api/state"), api("/api/keymap")]);
    state.setup = vaultState.setupRequired;
    state.challengeId = keymap.id;
    state.keys = keymap.keys;
    initializeAuthPanel();
  } catch {
    showNotice("Could not connect to the local GitMesh service. Start it on this device and reload.", true);
  }
}

boot();
