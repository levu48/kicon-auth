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
| `apps.kicon.com` | App **platform shell** — portal / catalog / standalone launcher only (*not* where per-app admin lives) | OAuth client |
| `vote.kicon.com` | The **voting app** consumer UI, on its own origin | OAuth client (registered — see below) |
| `admin.<app>.kicon.com` | Per-app **admin surface** — never framed, its own OAuth client (`admin.vote.kicon.com`, …) | OAuth client (MFA) |
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

## Consumer vs admin surface

Each app has **two surfaces**: an embeddable **consumer UI** (the microfrontend
users interact with, framed into partner sites) and a privileged **admin UI**
(managing the app — polls, config, moderation). **They are always different
origins.**

The consumer UI is the worst place to also host admin:

- It is **embeddable**, so it runs inside third-party contexts and ships a
  *permissive* `frame-ancestors` CSP — the largest, least-controllable
  XSS/clickjacking surface in the whole system.
- The admin UI is the **highest-privilege** surface and must be **never framed**
  (`frame-ancestors 'none'` / `X-Frame-Options: DENY`).
- Same origin ⇒ one cookie jar, one token store, one XSS blast radius. A compromise
  of the embeddable widget could reach the admin session. Separate origins make the
  admin session **unreachable from the widget's JS** — the browser enforces it.

And admin does **not** go on a shared `apps.kicon.com` (or `app.kicon.com`) either:
that would collapse *every* app's admin onto one origin — the same anti-pattern this
doc rejects for `apps.kicon.com/<app>` paths, now applied to the most sensitive
surface. `apps.kicon.com` stays a portal/launcher only. Admin lives on a **per-app**
`admin.<app>.kicon.com`.

| Surface | Origin | Framing CSP | OAuth client | Assurance |
|---|---|---|---|---|
| Consumer (embeddable) | `vote.kicon.com` | `frame-ancestors` partner allow-list | `vote` (public+PKCE) | loa1, seamless SSO |
| Admin | `admin.vote.kicon.com` | `frame-ancestors 'none'` | separate `vote-admin` client | MFA + low `default_max_age` |

The admin surface is **just another first-party OAuth client** — its own
`client_id`, its own `redirect_uris` (registering them auto-enables its CORS via the
`clientBasedCORS` hook in `src/oidc/oidc.config.ts`), and MFA + forced re-auth
enforced at the IdP, mirroring the `vietcouncil` / `xbottrader` pattern in
`src/oidc/clients.ts`. As always, *who* is an admin is app-tier authorization
resolved at the resource server (scopes/RBAC) — the IdP only enforces the
authentication *strength* (MFA) required to reach the admin origin.

### Repo layout vs origins

Separate **origins** is a deploy/runtime rule; it says nothing about the **repo**.
Colocating an app's consumer and admin code in one repo (monorepo) is fine and
often better — shared types, one API client, one design system, one PR per feature.
The boundary is enforced by *how the code is served*, not where it is authored.

The one requirement: the repo must emit **two separate build artifacts deployed to
the two origins** — never one bundle routed by path.

- ✅ Separate entry points → two bundles, two deploys (`apps/consumer` →
  `vote.kicon.com`, `apps/admin` → `admin.vote.kicon.com`), shared code in
  `packages/*`.
- ❌ One bundle serving both surfaces on one origin, split by `/admin/*` — that is
  the origin-collapse this doc rejects.
- ⚠️ Keep the shared-code dependency **one-way**: both surfaces depend on
  `packages/shared`; neither imports the other. Admin code (and its endpoints/
  secrets) must never end up in the embeddable consumer bundle.

## Repo strategy — polyrepo + `kicon-platform` foundation (decided)

> **Decision.** Apps are **polyrepo** — one repository per app. The shared
> foundation lives in a single **`kicon-platform`** repo that publishes versioned
> packages. This is settled; new apps follow it.

Each app repo colocates its own two surfaces (`consumer/` + `admin/`) and a
private `shared/` for app-local code; anything shared *across* apps is a published
package from `kicon-platform`, pulled in as a semver-pinned dependency.

```
kicon-platform            (repo)  → @kicon/ui, @kicon/oidc-client, @kicon/types, …
  packages/ui                       (design system)
  packages/oidc-client              (PKCE / silent-renew wrapper — see integration notes)
  packages/types                    (shared TS types)

vote-app                  (repo)
  consumer/   → vote.kicon.com          (client: vote)
  admin/      → admin.vote.kicon.com    (client: vote-admin)
  shared/     (vote-local, unpublished)
  package.json → deps: @kicon/ui, @kicon/oidc-client, @kicon/types

cart-app                  (repo)  → cart.kicon.com  / admin.cart.kicon.com
rideshare-app             (repo)  → rideshare.kicon.com / admin.rideshare.kicon.com
```

**Why this shape.** Polyrepo makes cross-app isolation *physical* rather than
policed — `vote-app` literally cannot import `cart-app`'s source, so the one-way /
no-cross-app-import rules hold by construction, matching the hard-partition
philosophy in [`CLAUDE.md`](../CLAUDE.md). The single `kicon-platform` repo keeps
the shared layer (design system, OIDC client, types) in one place to evolve, so we
avoid scattering foundational code across every app repo.

**The cost we accept.** Shared-code changes are not atomic: publish from
`kicon-platform`, then bump + deploy each consuming app. Manage the fan-out with
Changesets (publishing) and Renovate/Dependabot (the internal `@kicon/*` bumps),
and tolerate some version skew across apps (e.g. `vote` on `@kicon/ui@2.1` while
`cart` is still on `2.0`).

| | Monorepo (rejected) | **Polyrepo + `kicon-platform` (chosen)** |
|---|---|---|
| Cross-app import leakage | prevented by lint/boundary rules | **impossible by construction** |
| Ownership / permissions | CODEOWNERS per dir | **repo = boundary** |
| Deploy independence | CI path-filtering | **native per repo** |
| Shared-code change | one atomic PR | publish → bump each repo |
| Version skew | none | possible (accepted) |

**Unchanged by the repo choice** (repo-agnostic invariants): each surface is its
own origin + its own OAuth `client_id`; two build artifacts per app; the consumer
bundle never contains admin code; each app is its own IdP tenant with data keyed by
`sub` in the app's own DB.

### Working locally (repo workspace)

The repos are cloned as **siblings under a plain umbrella directory** — not a git
repo, not submodules (submodules re-introduce the coupling polyrepo avoids):

```
kicon/                     ← plain directory + a clone-all.sh / repos.json manifest
  kicon-platform/          shared @kicon/* packages
  kicon-auth/              this repo (auth.kicon.com IdP)
  kicon-vote/  kicon-cart/  kicon-www/  …
```

Operating the tooling (e.g. Claude Code) across this:

- **Default: one session per repo, launched from that repo's root.** Git context,
  diffs/commits, review, and the repo's own `CLAUDE.md` all scope correctly. Do not
  run from the bare umbrella as your working mode — the cwd isn't a repo, so
  git-aware features get muddy and per-repo scoping is lost.
- **Cross-repo work** (typically editing `kicon-platform` alongside a consumer):
  root the session in the **app** repo and add the platform repo to it
  (`--add-dir ../kicon-platform` / `/add-dir`), rather than launching from the
  umbrella.
- **`CLAUDE.md`:** each repo owns its own (canonical). An optional thin
  `kicon/CLAUDE.md` at the umbrella may hold only cross-repo conventions (the
  polyrepo rules, `@kicon/*` versioning) — a per-repo session picks up both the
  umbrella file and the repo file. It is not version-controlled with any product,
  so keep it minimal.

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
- An app's **admin surface lives on its own `admin.<app>.kicon.com` origin**, never
  framed, never sharing an origin with the embeddable consumer UI or with another
  app's admin.
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
