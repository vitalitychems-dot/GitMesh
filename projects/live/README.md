# GitMesh web

Private first-party admin-key access for the GitMesh mesh workspace.

- `npm run dev`: Express + Vite development preview on port 5000.
- `npm run build && npm start`: isolated frontend build and production server.
- `npm run test:web`: real PostgreSQL rotation/session/denial regression checks,
  using disposable development-only schemas (never production credentials).

See the root README for secure initial-key setup, rotation and publishing.
No social-login/identity provider or externally hosted fonts are used.
The web service never imports or serves the local-vault code or runtime storage.
