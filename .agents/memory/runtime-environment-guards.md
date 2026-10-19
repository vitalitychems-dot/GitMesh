---
name: Runtime environment guards
description: Distinguishing workspace execution from published execution safely.
---

Do not treat `REPLIT_ENVIRONMENT=production` alone as evidence that the application is executing in a published container.

**Why:** This workspace reports that value while `REPLIT_DEPLOYMENT` is unset and the development domain is present. A development-only schema guard incorrectly refused to run because of it.

**How to apply:** Official Replit configuration documentation identifies `REPLIT_DEPLOYMENT=1` as the published-runtime marker and says `REPLIT_DEV_DOMAIN` is unavailable in published deployments. Development-only reconciliation should require the workspace domain, reject the deployment marker and reject `NODE_ENV=production`. Never invoke development schema setup from startup or deployment build hooks.
