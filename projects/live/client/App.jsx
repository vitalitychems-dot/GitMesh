import React, { useEffect, useState } from "react";
import {
  ClerkProvider,
  SignIn,
  SignUp,
  useAuth,
  useClerk,
} from "@clerk/react";
import { publishableKeyFromHost } from "@clerk/react/internal";
import { shadcn } from "@clerk/themes";
import { Link, Redirect, Route, Router as WouterRouter, Switch, useLocation } from "wouter";

const clerkPubKey = publishableKeyFromHost(
  window.location.hostname,
  import.meta.env.VITE_CLERK_PUBLISHABLE_KEY,
);
const clerkProxyUrl = import.meta.env.VITE_CLERK_PROXY_URL;
const basePath = import.meta.env.BASE_URL.replace(/\/$/, "");
const SOURCE_URL = "https://github.com/vitalitychems-dot/GitMesh";
const OWNER = "vitalitychems-dot";

function stripBase(path) {
  return basePath && path.startsWith(basePath)
    ? path.slice(basePath.length) || "/"
    : path;
}

const clerkAppearance = {
  theme: shadcn,
  options: {
    logoPlacement: "inside",
    logoLinkUrl: basePath || "/",
    logoImageUrl: `${window.location.origin}${basePath}/logo.svg`,
  },
  variables: {
    colorPrimary: "#1b6864",
    colorForeground: "#183438",
    colorMutedForeground: "#627472",
    colorDanger: "#b74437",
    colorBackground: "#fbfbf5",
    colorInput: "#fffefa",
    colorInputForeground: "#183438",
    colorNeutral: "#bdc9bf",
    fontFamily: "'DM Sans', sans-serif",
    borderRadius: "4px",
  },
  elements: {
    rootBox: { width: "100%", minWidth: 0, maxWidth: "100%", display: "flex", justifyContent: "center" },
    cardBox: {
      width: "min(440px, 100%)",
      minWidth: 0,
      maxWidth: "100%",
      backgroundColor: "#fbfbf5",
      borderRadius: "6px",
      boxShadow: "0 18px 50px rgba(24,52,56,.08)",
      overflow: "hidden",
    },
    card: { backgroundColor: "transparent", boxShadow: "none", border: "0" },
    footer: { backgroundColor: "transparent", boxShadow: "none", border: "0" },
    headerTitle: { color: "#183438", fontFamily: "'Space Grotesk', sans-serif" },
    headerSubtitle: { color: "#627472" },
    socialButtonsBlockButtonText: { color: "#183438" },
    formFieldLabel: { color: "#274448" },
    footerActionLink: { color: "#1b6864" },
    footerActionText: { color: "#627472" },
    dividerText: { color: "#627472" },
    identityPreviewEditButton: { color: "#1b6864" },
    formFieldSuccessText: { color: "#1b6864" },
    alertText: { color: "#813e35" },
    logoBox: { marginBottom: "8px" },
    logoImage: { maxHeight: "42px", width: "auto" },
    socialButtonsBlockButton: {
      border: "1px solid #cbd6cd",
      backgroundColor: "#fbfbf5",
      borderRadius: "4px",
    },
    formButtonPrimary: {
      backgroundColor: "#1b6864",
      color: "#ffffff",
      borderRadius: "4px",
      boxShadow: "none",
    },
    formFieldInput: {
      backgroundColor: "#fffefa",
      color: "#183438",
      border: "1px solid #bac9be",
      borderRadius: "3px",
    },
    footerAction: { backgroundColor: "transparent" },
    dividerLine: { backgroundColor: "#d7ddd2" },
    alert: { backgroundColor: "#f2e1d8", borderColor: "#e2c6b9" },
    otpCodeFieldInput: { backgroundColor: "#fffefa", color: "#183438" },
    formFieldRow: { marginBottom: "16px" },
    main: { width: "100%" },
  },
};

function Brand({ admin = false }) {
  return (
    <Link href="/" className={`brand${admin ? " admin-brand" : ""}`} aria-label="GitMesh home">
      <img src={`${basePath}/logo.svg`} alt="" />
      <span>GitMesh</span>
    </Link>
  );
}

function PublicHeader() {
  return (
    <header className="topbar">
      <div className="wrap topbar-inner">
        <Brand />
        <nav className="nav" aria-label="Main navigation">
          <a href="#boundaries">Privacy boundary</a>
          <a href="#setup">Run it yourself</a>
          <Link href="/sign-in" className="nav-cta">Owner sign in</Link>
        </nav>
      </div>
    </header>
  );
}

function HomeRoute() {
  const { isLoaded, isSignedIn } = useAuth();
  if (isLoaded && isSignedIn) return <Redirect to="/admin" />;
  return <HomePage />;
}

function HomePage() {
  return (
    <div className="app-shell">
      <PublicHeader />
      <main>
        <section className="hero">
          <div className="wrap hero-grid">
            <div className="fade-up">
              <div className="eyebrow">Source-owned · portable by design</div>
              <h1>Your code.<br /><em>Your ground.</em></h1>
              <p className="hero-copy">
                GitMesh is a personal workspace whose source lives in a repository you can inspect,
                clone, and run yourself. The private vault is deliberately not part of this website.
              </p>
              <div className="hero-actions">
                <a className="button" href={SOURCE_URL} target="_blank" rel="noreferrer">
                  Read the source <span aria-hidden="true">↗</span>
                </a>
                <a className="button secondary" href="#setup">Offline setup notes</a>
              </div>
              <p className="hero-note">A web control room is for the repository owner only. It does not open or operate a local vault.</p>
            </div>
            <aside className="source-card fade-up" aria-label="Repository details">
              <div className="source-card-top">
                <span className="mono">THE PROJECT / SOURCE</span>
                <span className="mono">PUBLIC REPOSITORY</span>
              </div>
              <h2>Keep the source close.</h2>
              <p>GitMesh is available as a GitHub repository. Clone it to keep a working copy under your own control.</p>
              <a className="source-link" href={SOURCE_URL} target="_blank" rel="noreferrer">
                github.com/<br />vitalitychems-dot/GitMesh
              </a>
              <div className="card-foot"><span className="status-dot" /> SOURCE AVAILABLE TO INSPECT</div>
            </aside>
          </div>
        </section>

        <div className="principle-strip">
          <div className="wrap principle-inner">
            <p>Private means local. The web is not the vault.</p>
            <span className="mono">NO HOSTED VAULT · NO WEB KEY ENTRY</span>
          </div>
        </div>

        <section className="section" id="boundaries">
          <div className="wrap">
            <div className="section-heading">
              <div>
                <div className="eyebrow">A clear boundary</div>
                <h2>Two places.<br />Two purposes.</h2>
              </div>
              <p>GitMesh keeps its public-facing repository tools separate from private material. This site can explain the project and authenticate its owner; it cannot access a local vault.</p>
            </div>
            <div className="boundary-grid">
              <article className="boundary-cell web">
                <span className="eyebrow">This website</span>
                <h3>Repository control room</h3>
                <p>The authenticated admin view reports service and repository details supplied by the service. It has no vault, sigil, or keypad proxy.</p>
              </article>
              <article className="boundary-cell local">
                <span className="eyebrow">Your own device</span>
                <h3>Private vault stays offline</h3>
                <p>Keep private vault material and any local unlock method on your own device. Never type a sigil, password, token, or key into this page.</p>
              </article>
            </div>
          </div>
        </section>

        <section className="section setup-section" id="setup">
          <div className="wrap setup-layout">
            <div className="setup-intro">
              <div className="eyebrow">Source-first setup</div>
              <h2>Start with what you can inspect.</h2>
              <p>Use the repository as the source of truth. Review its current README and setup instructions before running anything.</p>
              <a className="button secondary" href={`${SOURCE_URL}#readme`} target="_blank" rel="noreferrer">
                Open repository README <span aria-hidden="true">↗</span>
              </a>
            </div>
            <div className="steps" aria-label="Repository setup overview">
              <article className="step">
                <span className="step-number">01 / SOURCE</span>
                <div><h3>Inspect the project</h3><p>Read the <a href={`${SOURCE_URL}#readme`} target="_blank" rel="noreferrer">GitHub README</a>, review the files and understand the current setup instructions before using the software.</p></div>
              </article>
              <article className="step">
                <span className="step-number">02 / COPY</span>
                <div><h3>Keep a local clone</h3><p>Clone <code>https://github.com/vitalitychems-dot/GitMesh.git</code> to a machine and location you control. Your clone remains yours to inspect and manage.</p></div>
              </article>
              <article className="step">
                <span className="step-number">03 / OFFLINE</span>
                <div><h3>Keep private material local</h3><p>Do not put private vault contents or unlock credentials in this website, repository issues, or other public-facing tools.</p></div>
              </article>
            </div>
          </div>
        </section>

        <WelcomeDemo />
        <section className="closing">
          <div className="wrap closing-inner">
            <div>
              <div className="eyebrow">For the source owner</div>
              <h2>Service details, not vault access.</h2>
              <p>The web admin is a small authenticated control room for service and repository status. GitHub sign-in is limited to the project owner.</p>
            </div>
            <Link href="/sign-in" className="button">Owner sign in</Link>
          </div>
        </section>
      </main>
      <footer className="footer">
        <div className="wrap footer-inner">
          <span>GitMesh · source-owned workspace</span>
          <span><a href={SOURCE_URL} target="_blank" rel="noreferrer">GitHub source</a> · <a href="#boundaries">Privacy boundary</a></span>
        </div>
      </footer>
    </div>
  );
}

function WelcomeDemo() {
  const [guests, setGuests] = useState([]);
  const [status, setStatus] = useState("");

  function submitGuest(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    const name = String(data.get("name") || "").trim();
    const purpose = String(data.get("purpose") || "").trim();
    if (!name || !purpose) {
      setStatus("Add a name and purpose to continue.");
      return;
    }
    setGuests((current) => [...current, { name, purpose, id: `${Date.now()}-${current.length}` }]);
    setStatus(`${name} was added to this temporary browser-only demo.`);
    form.reset();
  }

  function clearDemo() {
    setGuests([]);
    setStatus("Temporary entries cleared from this page.");
  }

  return (
    <section className="section demo-section" id="welcome-demo">
      <div className="wrap">
        <div className="section-heading">
          <div><div className="eyebrow">Optional · browser-only</div><h2>A small welcome demo.</h2></div>
          <p>This is a local interaction to preview a welcome list. It creates no account, sends nothing to a server, and does not grant access.</p>
        </div>
        <div className="demo-panel">
          <div className="demo-intro">
            <span className="eyebrow">Temporary by design</span>
            <h2>Try it in this tab.</h2>
            <p>Entries exist only in page memory. Reloading clears them. Please use harmless sample text only—never enter passwords, sigils, tokens, keys, or private information.</p>
          </div>
          <div className="demo-form-wrap">
            <form onSubmit={submitGuest} aria-describedby="demo-safety">
              <div className="field">
                <label htmlFor="demo-name">Name</label>
                <input id="demo-name" name="name" autoComplete="off" maxLength="40" required placeholder="A name for this preview" />
              </div>
              <div className="field">
                <label htmlFor="demo-purpose">Purpose</label>
                <input id="demo-purpose" name="purpose" autoComplete="off" maxLength="160" required placeholder="What brings them here?" />
                <p className="field-hint" id="demo-safety">Browser memory only. No account, network request, or persistence.</p>
              </div>
              <div className="demo-submit-row">
                <button className="button small" type="submit">Add to preview</button>
                {guests.length > 0 && <button className="demo-reset" type="button" onClick={clearDemo}>Clear temporary entries</button>}
              </div>
              <p className="demo-status" role="status" aria-live="polite">{status}</p>
            </form>
            <div className="guest-list" aria-label="Temporary welcome entries">
              {guests.length === 0
                ? <p className="guest-empty">No temporary entries yet.</p>
                : guests.map((guest) => (
                  <div className="guest-row" key={guest.id}>
                    <strong>{guest.name}</strong><span>{guest.purpose}</span>
                  </div>
                ))}
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

function AuthPage({ mode }) {
  const isSignIn = mode === "in";
  return (
    <div className="auth-page">
      <aside className="auth-context">
        <Brand />
        <div className="auth-message">
          <div className="eyebrow">GitMesh owner access</div>
          <h1>{isSignIn ? "The control room is owner-only." : "Create access with GitHub."}</h1>
          <p>Continue with GitHub as <strong>{OWNER}</strong>. Other authenticated accounts are not administrators and will be denied access.</p>
          <p>Sign-in here protects repository service details only. It does not unlock, read, or proxy a local offline vault.</p>
          <span className="owner-tag">GITHUB ACCOUNT · {OWNER}</span>
          <p>If “Continue with GitHub” is missing, enable GitHub in Replit’s Auth → Configure → SSO providers for this environment. Email or Google alone cannot grant admin access.</p>
        </div>
        <div className="auth-foot">GitMesh · Your private vault stays on your device.</div>
      </aside>
      <main className="auth-box">
        <div className="clerk-frame">
          <div className="auth-top-mobile"><Brand /></div>
          {isSignIn
            ? <SignIn routing="path" path={`${basePath}/sign-in`} signUpUrl={`${basePath}/sign-up`} />
            : <SignUp routing="path" path={`${basePath}/sign-up`} signInUrl={`${basePath}/sign-in`} />}
        </div>
      </main>
    </div>
  );
}

function AdminHeader() {
  const { signOut } = useClerk();
  return (
    <header className="admin-head">
      <div className="wrap admin-head-inner">
        <Brand admin />
        <div className="admin-head-actions">
          <span className="mono">OWNER CONTROL ROOM</span>
          <button className="quiet-button" type="button" onClick={() => signOut({ redirectUrl: basePath || "/" })}>Sign out</button>
        </div>
      </div>
    </header>
  );
}

function LoadingState() {
  return (
    <div className="wrap loading-block" role="status" aria-label="Loading admin service status">
      <div className="skeleton short" />
      <div className="skeleton" />
      <div className="skeleton large" />
      <div className="skeleton large" />
    </div>
  );
}

function formatUptime(seconds) {
  const value = Number(seconds);
  if (!Number.isFinite(value) || value < 0) return "Unavailable";
  const days = Math.floor(value / 86400);
  const hours = Math.floor((value % 86400) / 3600);
  const minutes = Math.floor((value % 3600) / 60);
  const secs = Math.floor(value % 60);
  return [days ? `${days}d` : null, `${hours}h`, `${minutes}m`, `${secs}s`].filter(Boolean).join(" ");
}

function AdminPage() {
  const { isLoaded, isSignedIn } = useAuth();
  const [result, setResult] = useState({ phase: "loading", data: null, message: "" });
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    if (!isLoaded || !isSignedIn) return undefined;
    let active = true;
    setResult({ phase: "loading", data: null, message: "" });
    async function loadControlRoom() {
      try {
        const sessionResponse = await fetch("/api/session", {
          method: "GET",
          credentials: "include",
          headers: { Accept: "application/json" },
        });
        if (sessionResponse.status === 401) {
          if (active) setResult({ phase: "signed-out", data: null, message: "Your web session is not authenticated by GitMesh. Sign in with the project owner's GitHub account." });
          return;
        }
        if (sessionResponse.status === 403) {
          if (active) setResult({ phase: "denied", data: null, message: "The service denied this account before loading admin status." });
          return;
        }
        if (sessionResponse.status === 503) {
          if (active) setResult({ phase: "error", data: null, message: "The session service is temporarily unavailable." });
          return;
        }
        if (!sessionResponse.ok) throw new Error(`Session check returned ${sessionResponse.status}.`);
        const session = await sessionResponse.json();
        if (!session?.authenticated || session?.admin !== true || session?.owner !== OWNER) {
          if (active) setResult({ phase: "denied", data: null, message: "This authenticated account is not the GitMesh owner. Admin access is denied." });
          return;
        }

        const response = await fetch("/api/admin/status", {
          method: "GET",
          credentials: "include",
          headers: { Accept: "application/json" },
        });
        if (response.status === 401) {
          if (active) setResult({ phase: "signed-out", data: null, message: "The service did not recognize an authenticated owner session." });
          return;
        }
        if (response.status === 403) {
          if (active) setResult({ phase: "denied", data: null, message: "The service denied owner access. No administrator data is shown." });
          return;
        }
        if (response.status === 503) {
          if (active) setResult({ phase: "error", data: null, message: "The admin status service is temporarily unavailable." });
          return;
        }
        if (!response.ok) throw new Error(`Admin status returned ${response.status}.`);
        const data = await response.json();
        if (
          data?.identity?.github !== OWNER ||
          data?.identity?.role !== "admin" ||
          data?.security?.vaultHosted !== false
        ) {
          if (active) setResult({ phase: "denied", data: null, message: "The service identity or security boundary did not match the expected owner contract. Data withheld." });
          return;
        }
        if (active) setResult({ phase: "ready", data, message: "" });
      } catch (error) {
        if (active) setResult({
          phase: "error",
          data: null,
          message: error instanceof Error ? error.message : "Could not load admin status.",
        });
      }
    }
    loadControlRoom();
    return () => { active = false; };
  }, [isLoaded, isSignedIn, attempt]);

  if (!isLoaded) return <LoadingState />;
  if (!isSignedIn) {
    return (
      <div className="admin-page">
        <AdminHeader />
        <main className="wrap"><StateCard eyebrow="Authentication required" title="Sign in to continue." message="The admin control room is available only to the authenticated repository owner." action={<Link href="/sign-in" className="button">Owner sign in</Link>} /></main>
      </div>
    );
  }

  if (result.phase === "loading") return <div className="admin-page"><AdminHeader /><LoadingState /></div>;
  if (result.phase !== "ready") {
    const denied = result.phase === "denied";
    return (
      <div className="admin-page">
        <AdminHeader />
        <main className="wrap">
          <StateCard
            eyebrow={denied ? "Access denied" : result.phase === "signed-out" ? "Session not authorized" : "Service unavailable"}
            title={denied ? "This account is not the owner." : result.phase === "signed-out" ? "Owner session required." : "Status is unavailable."}
            message={result.message}
            action={<>
              {!denied && <button className="button" type="button" onClick={() => setAttempt((value) => value + 1)}>Try again</button>}
              <Link href="/" className="button secondary">Back to GitMesh</Link>
            </>}
          />
        </main>
      </div>
    );
  }

  const { identity, service, security, repository } = result.data;
  return (
    <div className="admin-page">
      <AdminHeader />
      <main className="wrap admin-main">
        <div className="admin-title-row">
          <div>
            <div className="eyebrow">Authenticated owner view</div>
            <h1>Control room</h1>
            <p>Live service and repository details returned by GitMesh.</p>
          </div>
          <button className="refresh-button" type="button" onClick={() => setAttempt((value) => value + 1)}>Refresh status</button>
        </div>
        <div className="admin-identity">
          <strong>Signed in as {identity.github}</strong>
          <span className="mono">ROLE / {identity.role}</span>
        </div>
        <div className="admin-grid">
          <section className="admin-card" aria-labelledby="service-title">
            <div className="eyebrow">Runtime</div>
            <h2 id="service-title">Service status</h2>
            <dl className="detail-list">
              <Detail label="Service" value={service.name} />
              <Detail label="Uptime" value={formatUptime(service.uptimeSeconds)} />
              <Detail label="Node version" value={service.nodeVersion} />
            </dl>
          </section>
          <section className="admin-card" aria-labelledby="security-title">
            <div className="eyebrow">Boundary</div>
            <h2 id="security-title">Security model</h2>
            <dl className="detail-list">
              <Detail label="Vault hosted" value={security.vaultHosted ? "Yes" : "No"} />
              <Detail label="Authentication" value={security.auth} />
            </dl>
          </section>
          <section className="admin-card" aria-labelledby="repo-title">
            <div className="eyebrow">Source</div>
            <h2 id="repo-title">Repository</h2>
            <dl className="detail-list">
              <Detail label="Branch" value={repository.branch} />
              <Detail label="Source URL" value={repository.url} link />
            </dl>
          </section>
          <section className="admin-card" aria-labelledby="owner-title">
            <div className="eyebrow">Authorization</div>
            <h2 id="owner-title">Owner identity</h2>
            <dl className="detail-list">
              <Detail label="GitHub account" value={identity.github} />
              <Detail label="Role" value={identity.role} />
            </dl>
          </section>
        </div>
        <p className="security-note"><strong>Offline vault boundary.</strong> This control room reports service metadata only. It has no vault contents, sigil field, keypad, or proxy for local unlock operations. Keep private material on your own device.</p>
        <p className="admin-footer">Status is provided by the same-origin GitMesh API and shown only after the session and admin endpoint authorize this owner account.</p>
      </main>
    </div>
  );
}

function Detail({ label, value, link = false }) {
  const safeValue = value === undefined || value === null || value === "" ? "Unavailable" : String(value);
  return (
    <div className="detail-row">
      <dt>{label}</dt>
      <dd>{link && safeValue !== "Unavailable"
        ? <a href={safeValue} target="_blank" rel="noreferrer">{safeValue}</a>
        : safeValue}</dd>
    </div>
  );
}

function StateCard({ eyebrow, title, message, action }) {
  return (
    <section className="state-card">
      <div className="eyebrow">{eyebrow}</div>
      <h1>{title}</h1>
      <p>{message}</p>
      <div className="state-actions">{action}</div>
    </section>
  );
}

function NotFound() {
  return (
    <main className="wrap">
      <StateCard eyebrow="Not found" title="This route is not part of GitMesh." message="Return to the project page or inspect the source repository." action={<><Link href="/" className="button">GitMesh home</Link><a className="button secondary" href={SOURCE_URL}>Open source</a></>} />
    </main>
  );
}

function ClerkRoutes() {
  const [, setLocation] = useLocation();
  return (
    <ClerkProvider
      publishableKey={clerkPubKey}
      proxyUrl={clerkProxyUrl}
      appearance={clerkAppearance}
      signInUrl={`${basePath}/sign-in`}
      signUpUrl={`${basePath}/sign-up`}
      localization={{
        signIn: { start: { title: "Owner sign in", subtitle: "Continue with GitHub as vitalitychems-dot." } },
        signUp: { start: { title: "Owner access", subtitle: "Use GitHub account vitalitychems-dot for GitMesh administration." } },
      }}
      routerPush={(to) => setLocation(stripBase(to))}
      routerReplace={(to) => setLocation(stripBase(to), { replace: true })}
    >
      <Switch>
        <Route path="/" component={HomeRoute} />
        <Route path="/admin" component={AdminPage} />
        <Route path="/sign-in/*?" component={() => <AuthPage mode="in" />} />
        <Route path="/sign-up/*?" component={() => <AuthPage mode="up" />} />
        <Route component={NotFound} />
      </Switch>
    </ClerkProvider>
  );
}

function App() {
  if (!clerkPubKey) {
    return (
      <WouterRouter base={basePath}>
        <Switch>
          <Route path="/" component={HomePage} />
          <Route path="/sign-in/*?" component={() => <AuthSetupUnavailable mode="sign in" />} />
          <Route path="/sign-up/*?" component={() => <AuthSetupUnavailable mode="sign up" />} />
          <Route path="/admin" component={() => <AuthSetupUnavailable mode="owner control room" />} />
          <Route component={NotFound} />
        </Switch>
      </WouterRouter>
    );
  }
  return <WouterRouter base={basePath}><ClerkRoutes /></WouterRouter>;
}

function AuthSetupUnavailable({ mode }) {
  return (
    <main className="wrap">
      <StateCard
        eyebrow="Authentication setup"
        title={`${mode} is not configured.`}
        message="The GitMesh public page remains available. Clerk authentication needs a publishable key in this environment before owner access can be used."
        action={<><Link href="/" className="button">GitMesh home</Link><a className="button secondary" href={SOURCE_URL} target="_blank" rel="noreferrer">Read source</a></>}
      />
    </main>
  );
}

export default App;
