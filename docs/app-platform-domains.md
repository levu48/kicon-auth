# App platform — domains & embedding model

Settles: *"where do kicon's own apps live, and how are they embedded into partner
sites (e.g. a voting app inside vietcouncil.org)?"* Companion to
[`CLAUDE.md`](../CLAUDE.md) and [`data-ownership.md`](data-ownership.md).

---

## The one rule (again)

> **Origin is the security boundary.** The same principle that isolates the auth
> cookie to `auth.kicon.com` governs the app platform: each embeddable app gets
> its **own origin**, and the auth origin is never widened or embedded.

`kicon.com` is a platform that serves first-party apps (a voting app, and more
later). Some of those apps are **embedded into other organizations' sites** — the
voting app runs inside `vietcouncil.org`. That embedding is exactly why origins
must stay separate: a partner framing our app, and our app framing nothing of the
auth origin.

## Domain scheme

| Domain | Role | Type |
|---|---|---|
| `kicon.com` (apex) | First-party portal / app catalog home | OAuth client of the IdP |
| `apps.kicon.com` | App **platform shell** — dashboard, catalog, standalone app views | OAuth client |
| `vote.kicon.com` | The **voting app**, on its own origin | OAuth client (registered — see below) |
| `<app>.kicon.com` | Each future app its own origin (`poll`, `forms`, …) | OAuth client |
| `cdn.kicon.com` | **Cookieless** origin for the embed loader + JS/CSS bundles | static, no credentials |
| `api.kicon.com` | Resource-server API the apps call (or per-app `vote-api.kicon.com`) | resource server |
| `auth.kicon.com` | **IdP — unchanged, never embedded** | issuer |

### Why origin-per-app, not `apps.kicon.com/<app>` paths
- One app's XSS can't reach another app's DOM/storage/tokens — they're different origins.
- Embedding is scoped **per app, per partner**: `vote.kicon.com` sends
  `Content-Security-Policy: frame-ancestors https://vietcouncil.org` so only that
  partner can frame it. A shared origin would force one policy for everything.
- Path-based hosting gives none of this — it is all one origin.

## Embedding model

Two ways a "microfrontend" loads into a partner page — pick by trust level:

- **iframe embed** — the app runs in **its own origin** (`vote.kicon.com`) and
  talks to the parent via `postMessage`. Strong isolation. **Use this for
  anything embedded into a separate org** (vietcouncil is a legally separate
  501(c)(3) — see CLAUDE.md). The partner allows it with `frame-ancestors`; we
  allow the partner with our CSP. This is the default.
- **Module Federation / web-component `<script>`** — remote code executes **inside
  the partner's origin** with the partner's privileges (loader served from
  `cdn.kicon.com`). No origin isolation. Reserve for composing **our own**
  first-party apps together, not for cross-org embedding.

## Authenticating an embedded app (the real gotcha)

An embedded, authenticated app is a **third-party context**, so the browser blocks
its cookies (third-party-cookie phase-out, `SameSite`). `vote.kicon.com` in an
iframe on `vietcouncil.org` therefore **cannot silently reuse a kicon session**.
Two supported patterns:

1. **Top-level / popup OIDC** — the app breaks out of the frame (popup or full
   redirect) to run the standard Authorization-Code + PKCE flow, then returns to
   the iframe. No silent in-frame auth.
2. **Parent-passes-token** — the partner (already an OIDC client) obtains a token
   and hands it to the iframe over `postMessage`.

Either way the app is **just another OAuth client of `auth.kicon.com`** — no
special access to auth cookies, exactly like every other client.

## Invariants (do not break)

- **Never** widen the auth cookie to `.kicon.com`. `auth.kicon.com` keeps its own
  origin and its own TLS cert. A `*.kicon.com` wildcard for the *app fleet* is
  fine, but the auth origin stays separate and is never framed
  (`frame-ancestors 'none'` / `X-Frame-Options: DENY` stay as they are).
- Apps store their own data keyed by `sub` (see `data-ownership.md`); they never
  touch the IdP database or another tenant's tables.
- App-specific authorization (who may vote) lives at the app's resource server via
  scopes/RBAC — not baked into IdP authentication strength.

## Registered: `vote.kicon.com`

Registered as a first-party client in `src/oidc/clients.ts`, tenant `apps` in
`src/identity/tenants.ts`:

- **client_id:** `vote` · **type:** public SPA + PKCE (`token_endpoint_auth_method: none`)
- **grants:** `authorization_code`, `refresh_token` · **response:** `code`
- **redirect_uris:** `http://localhost:8084/auth/callback` (dev),
  `https://vote.kicon.com/auth/callback` (prod — *TODO confirm*)
- **scopes:** `openid profile email offline_access`
- **assurance:** standard (`acr` loa1); seamless SSO allowed. It is its **own
  tenant** (`apps`) so vote users never receive food/civic/trader claims and
  vice-versa — the hard partition holds.

> The voting app being embedded in a civic context does **not** make it the civic
> tenant. Membership gating for a VietCouncil vote is authorization handled at the
> vote resource server (or via VietCouncil's own API), not civic identity claims
> leaking across the partition.

## Client integration notes (what a relying party must send)

Clients auto-configure endpoints from `/.well-known/openid-configuration`, but a
few IdP behaviours are not discoverable and every integrator (SPA or server) hits
them:

- **PKCE is mandatory** for all clients, including confidential ones (S256; `plain`
  is disabled). No exceptions — a code flow without `code_challenge` is rejected.
- **Exact redirect-URI match.** No wildcards or path-prefixing; the full URI must be
  registered. Same for `post_logout_redirect_uri` (must be a registered
  `post_logout_redirect_uris` value or RP-initiated logout is refused).
- **`offline_access` requires `prompt=consent`.** This is the non-obvious one: to
  receive a **refresh token**, the authorization request must include both
  `scope=…offline_access` **and** `prompt=consent`. Without `prompt=consent`,
  oidc-provider silently strips `offline_access` and issues no refresh token — so a
  SPA's silent-renew has nothing to renew with. For **first-party** clients the
  consent is **auto-approved server-side (no consent screen)**, so sending
  `prompt=consent` stays seamless — it just unlocks the refresh token. (The vote
  SPA sets `prompt: 'consent'` for exactly this reason.)
- **CORS is client-scoped.** Browser clients may call `/token` and `/me`
  cross-origin, but only from an origin that matches one of *their own* registered
  `redirect_uris` (see `clientBasedCORS` in `src/oidc/oidc.config.ts`). Register the
  app's real origin as a redirect URI and its CORS is enabled automatically; there
  is no wildcard origin.
- **First-party clients skip the consent screen** entirely (auto-granted via
  `loadExistingGrant`). The only reason a first-party client sends `prompt=consent`
  is the `offline_access` rule above — not to render a screen.
- **Cross-tenant assurance/SSO** still applies: civic/trader force fresh auth + MFA
  regardless of an existing session; app-tier clients (e.g. `vote`) get seamless SSO.
