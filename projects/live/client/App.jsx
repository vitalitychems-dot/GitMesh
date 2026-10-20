import React, { useEffect, useRef, useState } from "react";
import { Link, Redirect, Route, Router, Switch, useLocation } from "wouter";

const basePath = import.meta.env.BASE_URL.replace(/\/$/, "");
const API_TIMEOUT = 10000;

function api(path, options = {}) {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), API_TIMEOUT);
  return fetch(path, {
    ...options,
    credentials: "include",
    signal: controller.signal,
  }).finally(() => window.clearTimeout(timeout));
}

function Brand({ inverse = false }) {
  return (
    <Link href="/" className={`brand${inverse ? " brand-inverse" : ""}`} aria-label="GitMesh private workspace">
      <img src={`${basePath}/logo.svg`} alt="" />
      <span>GitMesh</span>
      <span className="brand-private">PRIVATE MESH</span>
    </Link>
  );
}

function Mark({ children, tone = "quiet" }) {
  return <span className={`signal signal-${tone}`} aria-hidden="true">{children}</span>;
}

function AccessPage() {
  const [phase, setPhase] = useState("loading");
  const [configured, setConfigured] = useState(true);
  const [sigil, setSigil] = useState("");
  const [replacement, setReplacement] = useState("");
  const [offerId, setOfferId] = useState("");
  const [error, setError] = useState("");
  const [savedAction, setSavedAction] = useState(false);
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const inputRef = useRef(null);
  const [, setLocation] = useLocation();

  useEffect(() => {
    let active = true;
    api("/api/session")
      .then(async (response) => {
        if (response.status === 503) {
          if (active) { setPhase("error"); setError("The private admin service is temporarily unavailable. Please retry; do not reset your key."); }
          return;
        }
        if (!response.ok) throw new Error("Could not check the private session.");
        const session = await response.json();
        if (!active) return;
        setConfigured(session.configured !== false);
        if (session.authenticated && session.admin) setLocation("/admin", { replace: true });
        else setPhase("ready");
      })
      .catch((reason) => {
        if (active) {
          setPhase("error");
          setError(reason.name === "AbortError" ? "Session check timed out. Try again." : "The session service could not be reached.");
        }
      });
    return () => { active = false; };
  }, [setLocation]);

  async function submitSigil(event) {
    event.preventDefault();
    if (!sigil.trim() || busy) return;
    setBusy(true);
    setError("");
    try {
      const response = await api("/api/admin/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sigil }),
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) {
        if (response.status === 401) {
          throw new Error(
            "That key was not accepted. Use the latest saved web admin key, not your offline vault sigil or a key replaced by a confirmed rotation.",
          );
        }
        if (response.status === 409) throw new Error("Another key rotation is already in progress. Wait a moment and try again.");
        if (response.status === 429) throw new Error("Too many attempts. Pause briefly before trying again.");
        if (response.status === 503) throw new Error("Admin access is not configured or is temporarily unavailable.");
        throw new Error(payload.error || "The key could not be checked.");
      }
      if (payload.state !== "save-new-sigil" || typeof payload.nextSigil !== "string" || !payload.nextSigil || !/^[a-f0-9]{64}$/.test(payload.offerId || "")) {
        throw new Error("The server returned an incomplete key-rotation response. Your access has not changed.");
      }
      setSigil("");
      if (inputRef.current) inputRef.current.value = "";
      setReplacement(payload.nextSigil);
      setOfferId(payload.offerId);
      setSavedAction(false);
      setConfirmed(false);
      setPhase("rotation");
    } catch (reason) {
      setError(reason.name === "AbortError" ? "Request timed out. Check your connection and try again." : reason.message || "The request failed.");
    } finally {
      setBusy(false);
    }
  }

  async function saveReplacement() {
    try {
      const blob = new Blob([replacement, "\n"], { type: "text/plain;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = "gitmesh-admin-sigil.txt";
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      setSavedAction(true);
      setError("");
    } catch {
      setError("The browser could not start the download. Use Copy key instead.");
    }
  }

  async function copyReplacement() {
    try {
      await navigator.clipboard.writeText(replacement);
      setSavedAction(true);
      setError("");
    } catch {
      setError("Clipboard access was unavailable. Use Download key instead.");
    }
  }

  async function confirmRotation(event) {
    event.preventDefault();
    if (!confirmed || !savedAction || busy) return;
    setBusy(true);
    setError("");
    try {
      const response = await api("/api/admin/confirm", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ saved: true, offerId }),
      });
      const payload = await response.json().catch(() => ({}));
      if (response.status === 401) throw new Error("The pending rotation expired. Start again with the current admin key.");
      if (response.status === 409) throw new Error("This rotation is no longer current. Start again with the active admin key.");
      if (response.status === 429) throw new Error("Too many attempts. Wait briefly, then try again.");
      if (response.status === 503) throw new Error("The admin service is temporarily unavailable.");
      if (!response.ok || payload.authenticated !== true || payload.admin !== true) {
        throw new Error(payload.error || "The rotation could not be confirmed.");
      }
      setReplacement("");
      setSigil("");
      setLocation("/admin", { replace: true });
      setOfferId("");
    } catch (reason) {
      setError(reason.name === "AbortError" ? "Confirmation timed out. The pending key may have expired; check before retrying." : reason.message || "Confirmation failed.");
    } finally {
      setBusy(false);
    }
  }

  async function cancelRotation() {
    setBusy(true);
    setError("");
    try {
      const response = await api("/api/admin/cancel", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ offerId }),
      });
      if (!response.ok && response.status !== 401 && response.status !== 410) throw new Error("The pending rotation could not be cleared. Try again.");
      setOfferId("");
      setReplacement("");
      setConfirmed(false);
      setSavedAction(false);
      setPhase("ready");
    } catch (reason) {
      setError(reason.name === "AbortError" ? "Cancellation timed out. The pending key may have expired." : reason.message || "Could not cancel the rotation.");
    } finally {
      setBusy(false);
    }
  }

  if (phase === "loading") return <AccessFrame><LoadingLine /><LoadingLine /><LoadingLine /></AccessFrame>;

  return (
    <AccessFrame>
      <div className="access-content">
        <div className="eyebrow"><Mark tone="teal">01</Mark> PRIVATE ADMIN ACCESS</div>
        <h1>Only your<br /><em>workspace.</em></h1>
        <p className="lead">A private service console for the GitMesh admin. No public accounts, no external identity providers.</p>
        {!configured ? (
          <div className="notice notice-warn" role="status">
            <strong>Admin access is not configured.</strong>
            <p>Set <code>GITMESH_WEB_ADMIN_KEY</code> in this project’s Secrets, then reload. Do not share the value in chat.</p>
          </div>
        ) : phase === "rotation" ? (
          <section className="rotation-panel" aria-labelledby="rotate-title">
            <div className="rotation-heading">
              <Mark tone="coral">!</Mark>
              <div><div className="eyebrow">KEY ROTATION REQUIRED</div><h2 id="rotate-title">Save your replacement key</h2></div>
            </div>
            <p className="rotation-copy">This one-time key replaces the previous admin key only after you confirm it is safely saved. It will not be shown again.</p>
            <label className="field-label" htmlFor="replacement-key">Replacement admin key</label>
            <textarea id="replacement-key" className="replacement-key" value={replacement} readOnly rows={3} onFocus={(event) => event.currentTarget.select()} aria-describedby="key-help" />
            <p id="key-help" className="field-help">Keep this separately from your private vault key. The vault/keypad remains on your device.</p>
            <div className="key-actions">
              <button className="button" type="button" onClick={saveReplacement}>Download key</button>
              <button className="button button-light" type="button" onClick={copyReplacement}>Copy key</button>
            </div>
            <form onSubmit={confirmRotation}>
              <label className="confirm-check">
                <input type="checkbox" checked={confirmed} disabled={!savedAction || busy} onChange={(event) => setConfirmed(event.target.checked)} />
                <span>I have saved the replacement key somewhere secure.</span>
              </label>
              <div className="key-actions confirm-actions">
                <button className="button" type="submit" disabled={!savedAction || !confirmed || busy}>{busy ? "Confirming…" : "Confirm and continue"}</button>
                <button className="text-button" type="button" onClick={cancelRotation} disabled={busy}>Cancel rotation</button>
              </div>
            </form>
          </section>
        ) : (
          <form className="access-form" onSubmit={submitSigil}>
            <label className="field-label" htmlFor="admin-sigil">Separate web admin key</label>
            <div className="input-wrap">
              <input
                ref={inputRef}
                id="admin-sigil"
                type="password"
                autoComplete="current-password"
                spellCheck="false"
                required
                value={sigil}
                onChange={(event) => setSigil(event.target.value)}
                placeholder="Enter your current web admin key"
                aria-describedby="admin-key-help admin-key-security"
              />
              <span className="input-mark" aria-hidden="true">KEY</span>
            </div>
            <button className="button access-submit" type="submit" disabled={busy || !sigil.trim()}>
              {busy ? "Checking key…" : "Continue to admin"} <span aria-hidden="true">↗</span>
            </button>
            <p id="admin-key-help" className="field-help">
              This is not your offline vault sigil. After each confirmed sign-in, use the latest web key you saved; the replaced key stops working.
            </p>
            <p id="admin-key-security" className="field-help">
              The initial setup Secret does not reset an existing key. This page sends the key only to this GitMesh service and does not save it.
            </p>
          </form>
        )}
        {error && <div id="admin-key-error" className="notice notice-error" role="alert">{error}</div>}
        {phase === "error" && <button className="text-button retry-button" type="button" onClick={() => window.location.reload()}>Retry session check</button>}
        <div className="access-rule"><span /> PRIVATE ACCESS ONLY <span /> NO PUBLIC SIGNUP</div>
      </div>
    </AccessFrame>
  );
}

function AccessFrame({ children }) {
  return (
    <main className="access-page">
      <div className="access-top wrap"><Brand /><span className="top-note"><Mark>PRIVATE ACCESS</Mark> ADMIN WEB KEY IS SEPARATE</span></div>
      <div className="access-layout wrap">
        <section className="access-story">
          <div className="story-index"><span>GITMESH / SERVICE DESK</span><span>PRIVATE · 01</span></div>
          <div className="story-body">
            <div className="eyebrow">AGENT-TO-AGENT MESH WORKSPACE</div>
            <h2>A quieter kind<br />of connected.</h2>
            <div className="mesh-diagram" aria-label="Private workspace boundary illustration">
              <div className="diagram-ring ring-one" /><div className="diagram-ring ring-two" />
              <div className="diagram-core"><img src={`${basePath}/logo.svg`} alt="" /></div>
              <span className="node node-a">LOCAL</span><span className="node node-b">ADMIN</span><span className="node node-c">MESH</span>
              <span className="diagram-caption">SERVICE ACCESS / RESTRICTED</span>
            </div>
          </div>
          <p className="story-foot">Private workspace. Agent transport is not connected.</p>
        </section>
        <section className="access-panel" aria-label="Administrator sign in">
          <div className="panel-top"><span>CONTROL / ACCESS</span><span>01—01</span></div>
          {children}
          <div className="privacy-note">
            <span className="privacy-mark">i</span>
            <p>No external identity providers are used here. Hosting and network providers may still observe connection metadata; GitMesh does not promise anonymity.</p>
          </div>
        </section>
      </div>
      <footer className="access-footer wrap"><span>GITMESH <span className="footer-dot">/</span> PRIVATE WORKSPACE</span><span>THE WEB ADMIN DOES NOT ACCESS YOUR LOCAL VAULT</span></footer>
    </main>
  );
}

function LoadingLine() {
  return <div className="loading-line" aria-hidden="true" />;
}

function SignUpPage() {
  return (
    <AccessFrame>
      <div className="access-content signup-content">
        <div className="eyebrow"><Mark tone="coral">CLOSED</Mark> PRIVATE WORKSPACE</div>
        <h1>No public<br /><em>registration.</em></h1>
        <p className="lead">GitMesh access is provisioned privately. This workspace does not accept public account creation.</p>
        <Link className="button" href="/sign-in">Return to private access</Link>
      </div>
    </AccessFrame>
  );
}

function AdminHeader({ onLogout, busy }) {
  return (
    <header className="admin-head">
      <div className="wrap admin-head-inner">
        <Brand inverse />
        <div className="admin-head-actions"><span className="mono">ADMIN SERVICE VIEW</span><button type="button" className="quiet-button" onClick={onLogout} disabled={busy}>{busy ? "Signing out…" : "Sign out"}</button></div>
      </div>
    </header>
  );
}

function AdminPage() {
  const [state, setState] = useState({ phase: "loading", data: null, message: "" });
  const [attempt, setAttempt] = useState(0);
  const [loggingOut, setLoggingOut] = useState(false);
  const [, setLocation] = useLocation();

  useEffect(() => {
    let active = true;
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), API_TIMEOUT);
    setState({ phase: "loading", data: null, message: "" });
    async function load() {
      try {
        const sessionResponse = await fetch("/api/session", { credentials: "include", signal: controller.signal });
        if (sessionResponse.status === 503) {
          if (active) setState({ phase: "unavailable", data: null, message: "Admin session service is not configured or is temporarily unavailable." });
          return;
        }
        if (!sessionResponse.ok) throw new Error("Could not verify the admin session.");
        const session = await sessionResponse.json();
        if (!session.authenticated || !session.admin) {
          if (active) setState({ phase: "signed-out", data: null, message: "A valid administrator session is required." });
          return;
        }
        const response = await fetch("/api/admin/status", { credentials: "include", signal: controller.signal });
        if (response.status === 401) {
          if (active) setState({ phase: "signed-out", data: null, message: "Your administrator session has expired. Sign in again." });
          return;
        }
        if (response.status === 503) {
          if (active) setState({ phase: "unavailable", data: null, message: "The admin status service is temporarily unavailable." });
          return;
        }
        if (!response.ok) throw new Error("Could not load the admin service overview.");
        const data = await response.json();
        if (data?.identity?.role !== "admin" || data?.security?.vaultHosted !== false || data?.security?.socialLogin !== false || data?.mesh?.transport !== "not_connected") {
          if (active) setState({ phase: "invalid", data: null, message: "The service response did not match the expected private admin contract. Details are withheld." });
          return;
        }
        if (active) setState({ phase: "ready", data, message: "" });
      } catch (reason) {
        if (active) setState({ phase: "error", data: null, message: reason.name === "AbortError" ? "Status request timed out." : reason.message || "Could not load service status." });
      } finally {
        window.clearTimeout(timeout);
      }
    }
    load();
    return () => { active = false; controller.abort(); window.clearTimeout(timeout); };
  }, [attempt]);

  async function logout() {
    setLoggingOut(true);
    setState({ phase: "loading", data: null, message: "" });
    try {
      await api("/api/admin/logout", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({}) });
      setLocation("/sign-in", { replace: true });
    } catch {
      setState({ phase: "error", data: null, message: "Sign-out could not be confirmed. Your session may still be active. Retry sign out." });
    } finally {
      setLoggingOut(false);
    }
  }

  if (state.phase === "signed-out") return <Redirect to="/sign-in" />;
  return (
    <div className="admin-page">
      <AdminHeader onLogout={logout} busy={loggingOut} />
      <main className="wrap admin-main">
        {state.phase === "loading" ? <AdminSkeleton /> : state.phase !== "ready" ? (
          <section className="state-card" role="alert">
            <div className="eyebrow">SERVICE STATUS / {state.phase === "invalid" ? "CONTRACT MISMATCH" : "UNAVAILABLE"}</div>
            <h1>{state.phase === "invalid" ? "Overview withheld." : "Status could not load."}</h1>
            <p>{state.message}</p>
            <button className="button" type="button" onClick={() => setAttempt((value) => value + 1)}>Retry status check</button>
          </section>
        ) : (
          <AdminOverview data={state.data} onRefresh={() => setAttempt((value) => value + 1)} />
        )}
      </main>
    </div>
  );
}

function AdminSkeleton() {
  return <div className="admin-skeleton" role="status" aria-label="Loading service overview"><LoadingLine /><LoadingLine /><div className="skeleton-box" /><div className="skeleton-box" /></div>;
}

function AdminOverview({ data, onRefresh }) {
  const { identity, service, security, mesh } = data;
  return (
    <>
      <div className="admin-title-row">
        <div><div className="eyebrow"><Mark tone="teal">SESSION ACTIVE</Mark> PRIVATE SERVICE OVERVIEW</div><h1>Good to see<br /><em>your console.</em></h1><p>Admin service details only. No agent messages, peers, or transport controls are available here.</p></div>
        <button className="refresh-button" type="button" onClick={onRefresh}>Refresh status <span aria-hidden="true">↻</span></button>
      </div>
      <div className="admin-identity"><div><span className="eyebrow">AUTHENTICATED IDENTITY</span><strong>GitMesh administrator</strong></div><span className="role-chip">{identity.role.toUpperCase()}</span></div>
      <div className="admin-layout">
        <section className="admin-card service-card" aria-labelledby="runtime-heading">
          <div className="card-index"><span>01 / RUNTIME</span><Mark tone="teal">REPORTED</Mark></div>
          <h2 id="runtime-heading">Service details</h2>
          <dl className="detail-list"><Detail label="Service" value={service.name} /><Detail label="Uptime" value={formatUptime(service.uptimeSeconds)} /><Detail label="Node version" value={service.nodeVersion} /></dl>
        </section>
        <section className="admin-card mesh-card" aria-labelledby="mesh-heading">
          <div className="card-index"><span>02 / MESH</span><Mark tone="coral">NOT CONNECTED</Mark></div>
          <h2 id="mesh-heading">Transport status</h2>
          <div className="transport-status"><span className="transport-glyph" aria-hidden="true">—</span><div><strong>{mesh.transport.replaceAll("_", " ")}</strong><p>Agent-to-agent transport is not connected. No live peers or messages are shown.</p></div></div>
        </section>
        <section className="admin-card security-card" aria-labelledby="security-heading">
          <div className="card-index"><span>03 / BOUNDARIES</span><Mark>WEB ADMIN</Mark></div>
          <h2 id="security-heading">Security model</h2>
          <dl className="detail-list">
            <Detail label="Vault hosted" value={security.vaultHosted ? "Yes" : "No"} />
            <Detail label="Authentication" value={security.auth} />
            <Detail label="Social login" value={security.socialLogin ? "Enabled" : "Not used"} />
          </dl>
        </section>
        <aside className="admin-note">
          <div className="eyebrow">A CLEAR BOUNDARY</div><h2>Your private vault<br />stays on your device.</h2>
          <p>The private vault/keypad and the web admin key are separate. This console reports service metadata; it does not unlock or proxy local vault operations.</p>
          <p>No external identity providers are used. Hosting and network providers may observe connection metadata. This is not a promise of anonymity or untraceability.</p>
        </aside>
      </div>
      <div className="admin-tail"><span>GITMESH / ADMIN</span><span>NO PUBLIC SIGNUP · NO SOCIAL IDENTITY</span></div>
    </>
  );
}

function formatUptime(seconds) {
  const value = Number(seconds);
  if (!Number.isFinite(value) || value < 0) return "Unavailable";
  const days = Math.floor(value / 86400);
  const hours = Math.floor((value % 86400) / 3600);
  const minutes = Math.floor((value % 3600) / 60);
  const parts = [];
  if (days) parts.push(`${days}d`);
  if (hours || days) parts.push(`${hours}h`);
  parts.push(`${minutes}m`);
  return parts.join(" ");
}

function Detail({ label, value }) {
  const display = value === undefined || value === null || value === "" ? "Unavailable" : String(value);
  return <div className="detail-row"><dt>{label}</dt><dd>{display}</dd></div>;
}

function NotFound() {
  return <main className="not-found"><Brand /><div className="eyebrow">404 / NOT IN THIS WORKSPACE</div><h1>That route<br /><em>doesn’t exist.</em></h1><Link className="button" href="/sign-in">Return to private access</Link></main>;
}

function AppRoutes() {
  return (
    <Switch>
      <Route path="/" component={AccessPage} />
      <Route path="/sign-in" component={AccessPage} />
      <Route path="/sign-up" component={SignUpPage} />
      <Route path="/admin" component={AdminPage} />
      <Route component={NotFound} />
    </Switch>
  );
}

function App() {
  return <Router base={basePath}><AppRoutes /></Router>;
}

export default App;
