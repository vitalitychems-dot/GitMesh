# GitMesh web

The public room and separate GitHub-owner web-admin portal.

- `npm run dev`: Express + Vite development preview on port 5000.
- `npm run build && npm start`: isolated frontend build and production server.
- `npm run test:web`: owner authorization, denial and proxy regression checks.

See the root README for Auth setup and owner configuration. The web service
never imports or serves the local-vault code or its runtime storage.
