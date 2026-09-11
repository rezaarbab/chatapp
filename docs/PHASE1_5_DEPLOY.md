# Phase 1.5 — Cloudflare Environments & Deployment

## Environments

| Environment | Config | D1 | Deployed by | Token TTL |
|---|---|---|---|---|
| local | `wrangler.jsonc` (default) | local miniflare D1 | `npx wrangler dev` / vitest | 30 min |
| staging | `wrangler.staging.jsonc` — **generated in CI, never committed** | real `chatapp-staging` D1 | `deploy-staging.yml` on push to main | 20 s (smoke-test hook) |
| production | `wrangler.production.jsonc` — generated on manual dispatch | real `chatapp-production` D1 | `deploy-production.yml` (workflow_dispatch + typed confirmation) | 30 min (default) |

## Required GitHub configuration (user actions)

Settings → Secrets and variables → Actions → New repository secret:

1. `CLOUDFLARE_API_TOKEN` — Create at dash.cloudflare.com → My Profile → API Tokens.
   Minimal permissions: **Account → D1 → Edit** and **Account → Workers Scripts → Edit**.
2. `CLOUDFLARE_ACCOUNT_ID` — visible on any Cloudflare dashboard page (not a secret,
   but kept out of git per policy).

Until both exist, the staging deploy job skips itself (visible as a warning).

## Flow (deploy-staging.yml)

1. idempotent `wrangler d1 create chatapp-staging` (skips if it exists)
2. render `wrangler.staging.jsonc` from the template with the real database id
   (database id stays out of git)
3. `wrangler d1 migrations apply chatapp-staging --remote`
4. verify all 12 tables exist on the real D1
5. `wrangler deploy --config wrangler.staging.jsonc` → workers.dev URL
6. run `test/smoke-staging.mjs` against the real URL:
   register → token → use (D1 persistence) → duplicate-username 409 → re-auth →
   add_device (dev_no=2) → cross-account revoke 403 → revoke → immediate 401
   DEVICE_REVOKED → fail-closed challenge 404 → **real token expiry** (staging TTL)

## Secrets policy

- No secret, private key, or token is committed to git, printed to CI logs, or
  stored in fixtures. Smoke-test keys are generated at runtime and discarded.
- The Worker itself needs **no secrets today**: D1 binding + vars only. When a
  real secret becomes necessary, it must be added via
  `wrangler secret put` / Cloudflare dashboard (Cloudflare Secrets), never in git.
- Production is protected by a typed confirmation input and a required
  `PROD_D1_DATABASE_ID` repository variable; it is never deployed by pushes.
