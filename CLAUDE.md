# CLAUDE.md — kicon.com Identity Provider

Project context for Claude Code. These are settled decisions, not options to
re-open. Fit all work to the existing repo conventions (NestJS / TypeORM /
Postgres) rather than introducing new patterns.

---

## Goal

Build an OpenID Connect (OIDC) identity provider that serves multiple
first-party platforms as separate OAuth clients.

**The IdP is hosted at `auth.kicon.com`** (issuer / discovery / all OIDC
endpoints live here), NOT at the bare `kicon.com` apex. This is deliberate: the
IdP session cookie is the crown jewel — whoever holds it is authenticated across
every client — so the auth origin is kept isolated with a tiny, tightly
controlled surface (login page + auth endpoints only).

**The `kicon.com` apex is reserved for future first-party applications.** Any app
served from `kicon.com` (or another subdomain) later becomes just another
registered OAuth client of `auth.kicon.com` and logs in via the standard redirect
flow — no special access to the auth cookies. Do NOT host application features on
the `auth.kicon.com` origin; keep it boring and security-critical.

## Stack

- **Runtime / framework:** Node.js, NestJS, TypeORM
- **OIDC engine:** `node-oidc-provider` (panva) — the OpenID-certified library.
  Do NOT hand-roll the protocol. We own the account model, storage adapters,
  and login/consent UI around it.
- **Datastore:** Postgres (identity + config), Redis (sessions, token/code
  cache, rate-limit counters)
- **Password hashing:** Argon2id
- **Token signing:** asymmetric — ES256 (preferred) or RS256 — with a JWKS
  endpoint and `kid`-based key rotation. Never sign with a symmetric secret.

> Before writing integration code, check the **installed** `node-oidc-provider`
> version's docs for the current adapter interface, configuration options, and
> claim/`findAccount` signatures. Do not trust training-data recollection of the
> API — it changes across major versions. Same for OAuth 2.1 BCP details.

## Flows

- **Authorization Code + PKCE** — all human login (web, SPA, mobile).
- **Client Credentials** — service-to-service only.
- **Refresh Token** — with rotation + reuse detection (a replayed refresh token
  must invalidate the family).
- **Disallowed:** Implicit, Resource Owner Password Credentials (ROPC).

## Endpoints (standard OIDC surface)

`/.well-known/openid-configuration`, `/authorize`, `/token`, `/userinfo`,
`/jwks.json`, `/introspect`, `/revoke`, plus RP-initiated and back-channel
logout. External clients auto-configure from the discovery document.

---

## Identity model — shared pool, hard partition

One shared user pool. A single human is one core identity across all clients.
The core record is deliberately **thin and low-sensitivity**; everything
sensitive or app-specific lives in tenant-scoped tables that other tenants
cannot see.

```
users                       -- shared core; keep small and low-sensitivity
  id, primary_email, name, default_locale, default_zoneinfo, created_at

user_tenant_prefs           -- sparse per-tenant overrides for TRUE-shared attrs
  user_id, tenant_id, locale?, zoneinfo?   -- row exists only when overridden

-- tenant-scoped tables (each owns its own schema; never cross-read):
food_delivery_addresses     -- user_id, label, line1, city, ...   [APP DATA — see note]
civic_residency             -- user_id, verified_address, district_id, verified_at   [SENSITIVE]
trader_profile              -- user_id, ...                                           [SENSITIVE / FINANCIAL]
```

> **Storage boundary (see `docs/data-ownership.md`).** Applications never share the
> IdP's database — they get `sub` + claims via tokens and key their own rows by
> `sub`. Of the tables above, `food_delivery_addresses` is **application data owned
> by the food app (banmua) and stored in banmua's own DB** — it is listed here to
> describe the identity model, not to place it in the IdP datastore. Only
> `civic_residency` and `trader_profile` (identity-grade, sensitive) live behind
> the IdP boundary. The IdP Postgres holds Ring 1 `users`, Ring 2
> `user_tenant_prefs`, credentials/MFA, the sensitive tenant tables, and the audit
> log — nothing app-specific.

### Attribute cascade (true-shared attributes only)

`locale` and `zoneinfo` are person-level facts. Resolve as:

```
value(user, tenant, attr) = tenant_override ?? global_default
```

- Writes land on the **tenant override** by default. One app must never
  silently change another app's behavior.
- The **global default** is only editable from a central `kicon.com` account
  page that explicitly states it applies everywhere unless an app overrides it.
- Prefer **detecting** locale/zoneinfo (`Accept-Language`, JS timezone probe)
  and persisting only on explicit user action.

### Address is NOT a shared attribute

Same name, different meaning per tenant — keep it fully partitioned:
- **Food tenant:** a collection of labeled, user-editable delivery addresses
  (none authoritative), tied to orders.
- **Viet Council:** a single (possibly verified) residential address that drives
  district assignment. Sensitive; never surfaces outside the civic tenant.

### Claim resolution

Emit `locale`/`zoneinfo` resolved through the requesting client's overrides.
Emit `address` only from the tenant that owns it, only to that client. Same core
user, different projection per client — resolved at token-mint / `/userinfo`
time in `findAccount`.

---

## Clients / tenants

`auth.kicon.com` is the IdP (issuer). The following are registered clients.
Confirm redirect URIs and finalize scopes before first client registration —
values below are defaults / TODOs. A future app on the `kicon.com` apex would be
added here as just another client.

| Client | Tenant / pool | SSO | Auth strength | Notes |
|---|---|---|---|---|
| `banmua.com` | **food** (shared customer pool) | Seamless within food | Standard | Food ordering front-end. |
| `vietcouncil.org` | **civic** (hard partition) | No silent SSO from other tenants | MFA encouraged; consider forced re-auth | 501(c)(3) data — keep legally/operationally separate. |
| `xbottrader.ai` | **trader** (hard partition) | **No silent SSO** from food/civic | **MFA mandatory + forced re-auth** (`prompt=login` / low `max_age`) | Financially sensitive — treat like a brokerage login. |

**PhoBonsa (placeholder):** came up earlier as a food property but is not in the
current client list. If added, it joins the **food** tenant and shares the
customer pool with `banmua.com`. Leave a registration slot for it.

### Per-client registration (fill in exact values)

- **banmua.com**
  - redirect_uris: `https://banmua.com/auth/callback` *(TODO confirm)*
  - grants: `authorization_code`, `refresh_token`
  - scopes: `openid profile email offline_access food:orders food:addresses`
  - client type: confidential (server-rendered) or public+PKCE (SPA) — TODO
- **vietcouncil.org**
  - redirect_uris: `https://vietcouncil.org/auth/callback` *(TODO confirm)*
  - grants: `authorization_code`, `refresh_token`
  - scopes: `openid profile email offline_access civic:member civic:district`
- **xbottrader.ai**
  - redirect_uris: `https://xbottrader.ai/auth/callback` *(TODO confirm)*
  - grants: `authorization_code`, `refresh_token`
  - scopes: `openid profile email offline_access` *(trading-specific scopes are
    defined/enforced by the xbottrader resource server, not the IdP — keep IdP
    scopes minimal)*

All are **first-party / trusted** clients: skip the third-party consent screen.
Only introduce consent if outside developers ever build on the IdP.

### SSO policy

SSO is seamless **within** the food tenant. Across tenants it is deliberately
gated: the civic and (especially) trader clients must not be silently
authenticated by a food session. Enforce with `prompt=login` and/or a low
`max_age` on those clients, and require MFA before issuing their tokens.

---

## Authorization model

- OAuth **scopes** for coarse API access (above).
- **RBAC** (roles → permissions) for in-app authorization; resolve roles per
  tenant and emit as claims or resolve at the resource server.
- Viet Council may need relationship-style authz (council / member / document
  hierarchies) later — leave room for a policy layer (OPA / Zanzibar-style) but
  don't build it up front.
- A user's roles in one tenant must never appear in another tenant's token.

## Security requirements (non-negotiable)

- HTTPS everywhere.
- **Exact** redirect-URI matching (no prefix/wildcard).
- `state` (CSRF) and `nonce` (replay) on every code flow; PKCE always.
- Short access-token TTL (minutes–1h); opaque refresh tokens, server-stored,
  rotated, with reuse detection.
- Cookies: `HttpOnly`, `Secure`, `SameSite`.
- Rate limiting + account lockout; breached-password checks.
- Signing-key rotation via `kid` in JWKS; keys stored as secrets outside the
  repo. Script rotation early.
- Audit-log every auth event (login, token issue, refresh, revoke, MFA, admin).

## Operational notes

- Deploy so the IdP is not a lone droplet — it's the login path for every
  platform. At minimum: automated backups, health checks, and two instances
  behind nginx so a reboot doesn't lock users out of everything.
- Redis required for sessions / rate limits / code cache.
- Cross-domain SSO works through the OIDC redirect flow, not shared cookies —
  the session cookie is scoped to `auth.kicon.com` only. Do NOT widen it to a
  `.kicon.com` parent-domain cookie; that would leak the auth session to any
  future app on the apex and defeat the origin isolation.

---

## Working agreement for Claude Code

1. Read the installed library versions and existing repo schema/conventions
   before generating code.
2. Implement incrementally; don't re-open settled decisions above.
3. Flag anything here that conflicts with what's actually in the repo rather
   than silently diverging.
