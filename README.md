# auth.kicon.com — Identity Provider

OpenID Connect identity provider for the kicon platforms. NestJS + `oidc-provider`
(panva). Architecture and settled decisions live in [`CLAUDE.md`](CLAUDE.md);
the learning material is in [`docs/phase-0-study-notes.md`](docs/phase-0-study-notes.md).

**Current state: Phase 4 complete.** Everything from Phase 3 (Redis + Postgres),
plus the full security layer: persistent ES256 **signing keystore** with `kid`
rotation; append-only **audit log**; **TOTP MFA** tiered by tenant (trader
mandatory, civic once enrolled, food none); **cross-tenant SSO gating** (food
seamless; civic/trader forced re-auth + MFA, `acr` loa1/loa2 in the id_token); and
**login hardening** — per-IP rate limiting, account lockout, and a HIBP
k-anonymity breached-password check. Next: **Phase 5** (droplet deploy).

---

## Run it

Needs Postgres + Redis. Either use `docker compose up -d` (provisions both with
the `kicon:kicon` creds in `.env.example`) **or** point `DATABASE_URL` at a local
Postgres and run your own Redis. Then:

```bash
cp .env.example .env          # edit DATABASE_URL / REDIS_URL for your setup
npm install
createdb kicon_idp            # or: psql -c 'CREATE DATABASE kicon_idp'  (skip if using docker)
npm run migration:run         # create the Ring 1/2/3 schema
npm run start:dev             # boots + seeds the dev account (non-production only)
```

Schema changes go through migrations (`npm run migration:generate` / `:run` /
`:revert`) — never auto-sync. The dev seed (`DevSeeder`) is idempotent and skipped
when `NODE_ENV=production`.

Then verify the milestone:

```bash
# Discovery document (should be JSON with issuer, endpoints, scopes_supported…)
curl -s http://localhost:3000/.well-known/openid-configuration | npx json 2>/dev/null \
  || curl -s http://localhost:3000/.well-known/openid-configuration

# Public signing keys (JWKS) — should list one ES256 key with a kid
curl -s http://localhost:3000/jwks

# Health
curl -s http://localhost:3000/healthz
```

You should see `authorization_endpoint`, `token_endpoint`, `jwks_uri`,
`userinfo_endpoint`, `introspection_endpoint`, `revocation_endpoint`,
`end_session_endpoint`, plus `scopes_supported` including `food:orders`,
`civic:district`, etc., and `claims_supported` including `district`, `locale`,
`zoneinfo`.

`docker compose up -d` provisions Postgres + Redis for later phases; **the app
does not connect to them yet** at this milestone.

### See the login flow (Phase 2)

With the IdP running, start the test relying party (stands in for banmua.com):

```bash
cd sandbox/phase2-test-rp && npm install && npm run rp
# open http://localhost:8081  → click "Log in with kicon"
# dev creds are pre-filled: lan@example.com / demo-pass-123
```

You'll be redirected to the IdP's login page, sign in, and land back on the RP
showing the decoded ID token, `/userinfo`, and the raw token response. Open
DevTools → Network (preserve log) to watch `/auth → /interaction → /token`.

Or run the whole thing headless for all three clients (proves the per-tenant
projection + refresh rotation):

```bash
cd sandbox/phase2-test-rp && npm run verify
```

---

## ⚠️ Verify versions before trusting this (CLAUDE.md rule)

`CLAUDE.md` says: *do not trust training-data recollection of the `oidc-provider`
API — it changes across major versions.* This scaffold was written against
`oidc-provider` **v8** with pinned ranges I could not verify online at authoring
time. After `npm install`, check:

```bash
npm ls oidc-provider   # what actually installed
```

If it resolved to **v9+** (or v8 changed under you), re-check these against the
installed docs — they are the version-sensitive spots:

- **ESM/CJS**: `src/oidc/provider-loader.ts` uses a `Function('import()')` trick
  because v8 is ESM-only and we compile to CommonJS. If your version ships CJS,
  simplify it. If it broke, this is the first suspect.
- **Config keys**: `pkce.required`, `rotateRefreshToken`, `features.*`, `ttl.*`,
  `claims`, `scopes` in `src/oidc/oidc.config.ts`.
- **`findAccount` / `claims()` signature**: the closure in `src/oidc/oidc.service.ts`
  (projection logic in `src/identity/identity.service.ts`).
- **Adapter interface**: `src/oidc/redis/redis-adapter.ts`.
- **Mounting**: `provider.callback()` in `src/main.ts`.

---

## Layout

```
src/
  main.ts                 bootstrap; mounts provider.callback() at root, + /healthz
  app.module.ts           ConfigModule + OidcModule
  oidc/
    oidc.module.ts        DI wiring
    oidc.service.ts       builds & owns the single Provider (async, on init)
    provider-loader.ts    ESM dynamic-import shim + DEV ephemeral ES256 JWKS
    oidc.config.ts        Provider configuration (claims, scopes, pkce, ttl, …)
    clients.ts            the 3 clients from CLAUDE.md (dev redirects/secrets)
    redis/                ioredis client + oidc-provider Redis adapter (Phase 3)
  accounts/
    accounts.service.ts   Ring-1 core + Argon2id credentials (Postgres)
    dev-credentials.ts    dev seed password / login-page prefill
  identity/
    identity.service.ts   Ring 1/2/3 claim projection (Postgres-backed)
    tenants.ts            client → tenant map
  database/
    entities/             User, UserTenantPref, CivicResidency, TraderProfile
    migrations/           reviewed schema changes (TypeORM)
    data-source.ts        DataSource for the migration CLI
    dev-seeder.ts         idempotent dev seed (non-production only)
    persistence.module.ts wires repositories + services
```

## Wired vs TODO (against CLAUDE.md)

| Requirement | Status |
|---|---|
| OIDC discovery + standard endpoints | ✅ wired |
| 3 clients, exact redirect-URI matching | ✅ wired |
| Auth Code + PKCE (required), S256 only | ✅ enforced in config |
| Refresh rotation + reuse detection | ✅ `rotateRefreshToken` |
| ES256 signing + JWKS + kid | ✅ (DEV ephemeral key) |
| Per-tenant claim projection (`findAccount`) | ✅ Postgres-backed, verified via /userinfo |
| Custom login UI + interactions | ✅ Argon2id login, first-party auto-consent |
| Redis adapter (sessions/codes/tokens) | ✅ state survives restart (verified) |
| Postgres identity model (real rings) | ✅ TypeORM + migrations (users, prefs, civic, trader) |
| Real signing keys + `kid` rotation | ✅ persistent keystore, rotation keeps old tokens valid |
| Audit log (append-only, every auth event) | ✅ Postgres `audit_log`, oidc events + login hooks |
| MFA (TOTP), tenant-tiered | ✅ trader mandatory, civic if enrolled, food none |
| Cross-tenant SSO gating + `acr` | ✅ food seamless; civic/trader forced re-auth + MFA |
| Rate limit / lockout / breached-password | ✅ Redis throttle + lockout, HIBP k-anonymity |
| Two instances behind nginx, backups | ⬜ Phase 5 (droplet) |
| Real key management + rotation script | ⬜ Phase 4 |
| Two instances behind nginx, backups | ⬜ Phase 5 (droplet) |
