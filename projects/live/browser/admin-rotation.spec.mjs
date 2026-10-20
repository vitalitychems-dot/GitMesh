import assert from "node:assert/strict";
import { test as base, expect } from "@playwright/test";
import { disposableAuthFixture } from "./fixture.mjs";

const test = base.extend({
  vault: async ({}, use) => {
    const fixture = await disposableAuthFixture();
    try { await use(fixture); } finally { await fixture.close(); }
  },
});

const acknowledgement = (page) => page.getByRole("checkbox", { name: "I have saved the replacement key somewhere secure." });
const confirmation = (page) => page.getByRole("button", { name: "Confirm and continue", exact: true });

async function begin(page, vault) {
  await page.goto(`${vault.baseURL}/sign-in`);
  await page.getByLabel("Separate web admin key", { exact: true }).fill(vault.initial);
  await page.getByRole("button", { name: "Continue to admin" }).click();
  await expect(page.getByRole("heading", { name: "Save your replacement key" })).toBeVisible();
  const replacement = await page.getByLabel("Replacement admin key", { exact: true }).inputValue();
  // Boolean assertions prevent Playwright from printing credentials on failure.
  assert.ok(replacement.length > 20 && replacement !== vault.initial, "A fresh test replacement must be offered");
  await expect(acknowledgement(page)).toBeDisabled();
  await expect(confirmation(page)).toBeDisabled();
  assert.ok(await page.evaluate(() => localStorage.length === 0 && sessionStorage.length === 0), "Credentials must not enter browser storage");
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), "Phone layout must not overflow horizontally");
  return replacement;
}

async function downloadKey(page, replacement) {
  const event = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download key", exact: true }).click();
  const download = await event;
  try {
    assert.equal(download.suggestedFilename(), "gitmesh-admin-sigil.txt");
    const stream = await download.createReadStream();
    const chunks = [];
    for await (const chunk of stream) chunks.push(chunk);
    assert.ok(Buffer.concat(chunks).toString("utf8") === `${replacement}\n`, "Download must contain exactly the offered test key");
  } finally { await download.delete(); }
  await expect(acknowledgement(page)).toBeEnabled();
  await expect(confirmation(page)).toBeDisabled();
}

async function confirm(page) {
  await acknowledgement(page).check();
  await expect(confirmation(page)).toBeEnabled();
  await confirmation(page).click();
  await expect(page).toHaveURL(/\/admin$/);
  await expect(page.getByText("GitMesh administrator", { exact: true })).toBeVisible();
  await expect(page.getByLabel("Replacement admin key", { exact: true })).toHaveCount(0);
}

async function generation(vault) {
  return (await vault.pool.query("SELECT generation FROM gm_web_admin")).rows[0].generation;
}

test("user-triggered copy requires acknowledgement before confirmation and rejects the consumed key", async ({ page, context, browserName, vault }, info) => {
  if (browserName === "chromium") {
    await context.grantPermissions(["clipboard-read", "clipboard-write"], { origin: vault.baseURL });
  }
  const replacement = await begin(page, vault);
  await page.getByRole("button", { name: "Copy key", exact: true }).click();
  if (browserName === "chromium") {
    await expect(acknowledgement(page)).toBeEnabled();
    assert.ok(await page.evaluate(async (expected) => (await navigator.clipboard.readText()) === expected, replacement), "Clipboard must contain the offered test key");
    await page.evaluate(() => navigator.clipboard.writeText(""));
  } else {
    await expect.poll(async () => await acknowledgement(page).isEnabled() ||
      await page.getByText("Clipboard access was unavailable. Use Download key instead.").isVisible()).toBe(true);
    if (!await acknowledgement(page).isEnabled()) await downloadKey(page, replacement);
  }
  await expect(confirmation(page)).toBeDisabled();
  await confirm(page);
  assert.equal(await generation(vault), 2);
  // Safe screenshot: the replacement is cleared and no credentials are rendered.
  await page.screenshot({ path: info.outputPath("signed-in-phone.png"), fullPage: true });
  await page.getByRole("button", { name: "Sign out", exact: true }).click();
  await expect(page).toHaveURL(/\/sign-in$/);
  await page.getByLabel("Separate web admin key", { exact: true }).fill(vault.initial);
  await page.getByRole("button", { name: "Continue to admin" }).click();
  await expect(page.getByRole("alert")).toContainText("That key was not accepted");
  assert.equal(await generation(vault), 2);
});

test("a user-triggered download enables acknowledgement, and cancellation leaves the old key valid", async ({ page, vault }) => {
  const replacement = await begin(page, vault);
  await downloadKey(page, replacement);
  await page.getByRole("button", { name: "Cancel rotation", exact: true }).click();
  await expect(page.getByLabel("Separate web admin key", { exact: true })).toBeVisible();
  assert.equal(await generation(vault), 1);
  assert.equal((await vault.pool.query("SELECT count(*) FROM gm_web_pending")).rows[0].count, "0");
  await begin(page, vault);
  await page.getByRole("button", { name: "Cancel rotation", exact: true }).click();
});

test("clipboard failure does not permit a false save acknowledgement", async ({ page, vault }) => {
  await page.addInitScript(() => {
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText: async () => { throw new Error("Test clipboard permission denied"); } },
    });
  });
  await begin(page, vault);
  await page.getByRole("button", { name: "Copy key", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("Clipboard access was unavailable");
  await expect(acknowledgement(page)).toBeDisabled();
  await expect(confirmation(page)).toBeDisabled();
  assert.equal(await generation(vault), 1);
});

test("expired offers cannot rotate the key and can be cancelled safely", async ({ page, vault }) => {
  const replacement = await begin(page, vault);
  await downloadKey(page, replacement);
  await vault.pool.query("UPDATE gm_web_pending SET expires_at = now() - interval '1 second'");
  await acknowledgement(page).check();
  await confirmation(page).click();
  await expect(page.getByRole("alert")).toContainText("rotation is no longer current");
  assert.equal(await generation(vault), 1);
  assert.equal((await (await page.request.get(`${vault.baseURL}/api/session`)).json()).authenticated, false);
  await page.getByRole("button", { name: "Cancel rotation", exact: true }).click();
  await begin(page, vault);
});

test("competing tabs cannot confirm an offer belonging to another tab", async ({ page, context, vault }) => {
  const first = await begin(page, vault);
  await downloadKey(page, first);
  const other = await context.newPage();
  const second = await begin(other, vault);
  assert.ok(first !== second, "Competing tabs must receive distinct replacements");
  await acknowledgement(page).check();
  await confirmation(page).click();
  await expect(page.getByRole("alert")).toContainText("rotation is no longer current");
  assert.equal(await generation(vault), 1);
  await downloadKey(other, second);
  await confirm(other);
  assert.equal(await generation(vault), 2);
  await confirmation(page).click();
  await expect(page.getByRole("alert")).toContainText("rotation is no longer current");
  assert.equal((await (await other.request.get(`${vault.baseURL}/api/session`)).json()).authenticated, true);
  await other.close();
});

test("refresh discards an unsaved offer without consuming the active key", async ({ page, vault }) => {
  const first = await begin(page, vault);
  await page.reload();
  await expect(page.getByLabel("Separate web admin key", { exact: true })).toBeVisible();
  await expect(page.getByLabel("Replacement admin key", { exact: true })).toHaveCount(0);
  assert.equal(await generation(vault), 1);
  assert.ok(await page.evaluate(() => localStorage.length === 0 && sessionStorage.length === 0), "Refresh must not restore credentials from storage");
  const second = await begin(page, vault);
  assert.ok(first !== second, "A restarted sign-in must offer a fresh replacement");
  await downloadKey(page, second);
  await confirm(page);
  assert.equal((await vault.pool.query("SELECT count(*) FROM gm_web_pending")).rows[0].count, "0");
});

for (const failure of ["http-error", "unconfirmed-success", "network-error"]) {
test(`logout ${failure} is explicit and leaves a retry that really revokes the session`, async ({ page, vault }) => {
  const replacement = await begin(page, vault);
  await downloadKey(page, replacement);
  await confirm(page);
  await page.route("**/api/admin/logout", (route) => failure === "network-error"
    ? route.abort("failed")
    : route.fulfill({
      status: failure === "http-error" ? 503 : 200,
      contentType: "application/json",
      body: JSON.stringify(failure === "http-error"
        ? { error: "Test logout unavailable" } : { signedOut: false }),
    }));
  await page.getByRole("button", { name: "Sign out", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("Your session may still be active");
  assert.equal((await (await page.request.get(`${vault.baseURL}/api/session`)).json()).authenticated, true);
  await page.unroute("**/api/admin/logout");
  await page.getByRole("button", { name: "Sign out", exact: true }).click();
  await expect(page).toHaveURL(/\/sign-in$/);
  assert.equal((await (await page.request.get(`${vault.baseURL}/api/session`)).json()).authenticated, false);
  assert.equal((await vault.pool.query("SELECT count(*) FROM gm_web_sessions")).rows[0].count, "0");
});
}
