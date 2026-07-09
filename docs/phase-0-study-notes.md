# Phase 0 Study Notes — Learning the IdP

Personal study material for building `auth.kicon.com` (an OpenID Connect identity
provider). This captures the "learn before you build" phase. Companion to
[`CLAUDE.md`](../CLAUDE.md), which holds the settled architecture decisions.

**How to use this file:** read top to bottom once, then use the *self-tests* at
the end of each part to check yourself. The goal of Phase 0 is understanding, not
code — you build the whole thing on `localhost` later, once these ideas are solid.

---

## Table of contents

1. [The mental model — what an IdP is](#1-the-mental-model)
2. [Concepts to learn, in dependency order](#2-concepts-in-order)
3. [Deep dive: Authorization Code + PKCE, as a security story](#3-auth-code-pkce)
4. [Deep dive: the identity model (findAccount / claim projection)](#4-identity-model)
5. [Phased build roadmap](#5-roadmap)
6. [Droplet setup — for Phase 5 (deferred)](#6-droplet)
7. [Learning resources](#7-resources)
8. [Master self-test](#8-self-test)

---

<a name="1-the-mental-model"></a>
## 1. The mental model — what an IdP is

An OIDC identity provider is one thing: **a service that other apps trust to
answer "who is this person?"** so each app doesn't store passwords or run its own
login.

Four actors — get these names into your head and you're 80% there:

| Role | In your world | Job |
|---|---|---|
| **Resource Owner** | the human user | owns their identity, grants access |
| **Client / Relying Party (RP)** | `banmua.com`, `vietcouncil.org`, `xbottrader.ai` | wants to know who the user is |
| **Authorization Server (the IdP)** | `auth.kicon.com` — *what you're building* | authenticates the user, issues tokens |
| **Resource Server** | each app's backend API | accepts tokens, serves protected data |

**The crown-jewel distinction: the IdP session ≠ the tokens.**

- The **IdP session** is a cookie scoped to `auth.kicon.com` only. It means "this
  browser has proven who it is *to the IdP*." Whoever holds it is authenticated
  across every client — so the origin is kept boring and isolated. Never widen
  this cookie to a `.kicon.com` parent-domain cookie.
- The **tokens** are what each client receives *about* the user. Clients never
  see the session cookie.

SSO across apps works entirely through that IdP session: a client redirects a
user who *already* has a live `auth.kicon.com` session, and the IdP recognizes
them without a password prompt. That is also why the design deliberately *gates*
SSO for the trader/civic tenants (`prompt=login`, low `max_age`).

---

<a name="2-concepts-in-order"></a>
## 2. Concepts to learn, in dependency order

Don't learn these all at once — this is roughly the order they build on each other.

**Tier 1 — the protocol core (before any code)**
- **OAuth 2.0 vs OIDC.** OAuth = *authorization* ("can this app do X on your
  behalf?"). OIDC = a thin *authentication* layer on top ("who are you?"). The
  one thing OIDC adds is the **ID token** + a standard `/userinfo` endpoint.
- **The four token/credential types** and why each is separate (see Part 3).
- **Authorization Code + PKCE flow** — *the* flow; everything else is a variation.
- **PKCE** — how a public client (no secret) proves it's the same party that
  started the flow.

**Tier 2 — the trust machinery**
- **JWT structure & asymmetric signing (ES256)** — IdP holds the private key;
  clients verify with the public key. No shared secrets.
- **JWKS + `kid` rotation** — clients fetch public keys from `/jwks.json`; rotate
  signing keys without downtime.
- **Discovery** (`/.well-known/openid-configuration`) — one URL that lets a
  client auto-configure.
- **`state` (CSRF) and `nonce` (replay)** — learn *what attack each stops*.

**Tier 3 — the parts that make it *your* IdP**
- **Sessions vs tokens** + cookie security (`HttpOnly`, `Secure`, `SameSite`).
- **`findAccount` / claim projection** — the shared-pool / hard-partition model
  (Part 4). The most original engineering in the project.
- **Scopes vs RBAC** — scopes gate coarse API access; roles are in-app authz.
- **SSO gating, `prompt`, `max_age`** — forced re-auth for sensitive tenants.
- **MFA** and **logout** (RP-initiated + back-channel).

---

<a name="3-auth-code-pkce"></a>
## 3. Deep dive: Authorization Code + PKCE, as a security story

Nearly every security rule in `CLAUDE.md` is a defense living at one specific step
of this flow. Learn *which attack each parameter stops*.

Scenario: a user logging into `banmua.com` (a public SPA client, so PKCE matters).

```
User clicks "Log in" on banmua.com
        │
        ▼
1. banmua.com redirects browser to  auth.kicon.com/authorize
   ?client_id=banmua&redirect_uri=...&scope=openid...
   &state=<csrf>&nonce=<replay>&code_challenge=<hash>
        │
        ▼
2. auth.kicon.com: is there a live IdP session cookie?
     ├─ no  → show login page → verify password (Argon2id) → set session cookie
     └─ yes → (SSO) skip ahead   ← unless prompt=login / max_age forces re-auth
        │
        ▼
3. auth.kicon.com redirects browser back to
   banmua.com/auth/callback?code=<one-time>&state=<csrf>
        │
        ▼
4. banmua.com SERVER calls  auth.kicon.com/token
   (code + code_verifier)  ─── back channel, not the browser
        │
        ▼
5. auth.kicon.com verifies, returns:
   { id_token (who), access_token (api key), refresh_token }
        │
        ▼
6. banmua.com verifies id_token signature via /jwks.json → user is logged in
```

### Step 1 — the authorization request

```
GET https://auth.kicon.com/authorize
      ?response_type=code
      &client_id=banmua
      &redirect_uri=https://banmua.com/auth/callback
      &scope=openid profile email offline_access food:orders
      &state=xyz123
      &nonce=abc789
      &code_challenge=E9Melhoa2Ow...        (a hash)
      &code_challenge_method=S256
```

Every parameter as a **defense**:

- **`response_type=code`** — "send a *code*, not tokens directly." The old Implicit
  flow (`token`) put tokens straight in the browser URL, leaking into history,
  logs, and `Referer`. Implicit is banned for exactly this reason. The code is a
  one-time claim ticket, useless on its own.
- **`client_id=banmua`** — *identifies* but does **not** authenticate the client.
  Anyone can put this here; that's fine — the authorize request is unauthenticated,
  and client authentication happens later at the token endpoint.
- **`redirect_uri`** — where the code goes. **The juiciest attack surface in OAuth.**
  Sloppy matching lets an attacker use `https://banmua.com.evil.com/cb` or
  `https://banmua.com/cb?next=//evil.com` and the code lands on their server. →
  **Exact matching, no prefixes, no wildcards.** Character-for-character.
  - *Why is `/callback` vs `/callback/` security-relevant?* A prefix match would
    let `/callback/../../evil` through; exact match is the only safe rule.
- **`state=xyz123`** — random value the client stores and re-checks on callback.
  Defends against **CSRF / login-fixation**: without it, an attacker tricks your
  browser into completing *their* login flow, silently logging you into the
  attacker's account. `state` = "I only accept a callback for a flow *I* started."
- **`nonce=abc789`** — echoed *inside the ID token*; defends against **token
  replay** by binding the ID token to this one auth request. **`state` protects
  the redirect; `nonce` protects the ID token.** (Classic interview question.)
- **`code_challenge` + `code_challenge_method=S256`** — **PKCE**:
  1. Client generates a random secret, the **`code_verifier`**, kept in memory.
  2. It sends only the hash: `code_challenge = BASE64URL(SHA256(code_verifier))`.
  3. At token exchange it sends the original verifier; the IdP re-hashes and
     compares.
  - **Attack stopped:** *authorization code interception*. Even if the code leaks
    (malicious app grabbing a URL scheme, sniffing), it's worthless without the
    `code_verifier`, which never left the legit client. OAuth 2.1 makes PKCE
    mandatory for everyone.

### Step 2 — authentication at the IdP (where the session cookie lives)

The browser is at `auth.kicon.com`. Question: *is there a valid session cookie?*

- **No session** → login page → verify password (Argon2id) → `Set-Cookie`
  (`HttpOnly; Secure; SameSite`). User now has an IdP session.
- **Session exists** → **SSO**: proceed without a password.

**Cross-tenant gating lives here.** If the request came from `xbottrader.ai` with
`prompt=login` or a low `max_age`, the IdP must *not* use the existing session
silently — it forces re-auth (and MFA):
- `prompt=login` → "ignore any session, prove it again."
- `max_age=300` → "session acceptable only if they authenticated in the last 5 min."

This decision — *honor the session, or force re-auth?* — is the technical heart of
"seamless within food, gated for trader/civic."

### Step 3 — redirect back with the code

```
HTTP 302
Location: https://banmua.com/auth/callback?code=SplxlOBeZ...&state=xyz123
```

Client immediately: (1) **checks `state`** matches stored value; (2) treats the
**code as short-lived (~30–60s) and one-time-use** — a second redemption signals
interception and should revoke everything tied to it. The code leaking into logs
is tolerable *only because* it's one-time, short-lived, and (public clients)
PKCE-bound. Defense in depth.

### Step 4 — token exchange (the back channel)

```
POST https://auth.kicon.com/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=SplxlOBeZ...
&redirect_uri=https://banmua.com/auth/callback
&client_id=banmua
&code_verifier=dBjftJeZ...          ← the PKCE secret, revealed at last
```

IdP's gauntlet: code valid/unexpired/unused? `redirect_uri` **exactly** matches
step 1? `SHA256(code_verifier) == stored code_challenge`? **Client authentication**
— confidential clients present a secret / private-key JWT here; public clients have
no secret, so **PKCE is the only thing standing in**.

Returns:
```json
{
  "access_token":  "...",              // opaque or JWT; for calling APIs
  "id_token":      "eyJhbGc...",       // signed JWT; WHO logged in
  "refresh_token": "...",              // opaque, server-stored
  "expires_in":    900
}
```

**Three tokens, three audiences (the #1 beginner confusion):**
- **ID token → for the client.** "Who logged in." Not an API key.
- **Access token → for the resource server.** `Authorization: Bearer`. Short TTL
  (minutes–1h) so a leak has a short blast radius.
- **Refresh token → to get new access tokens** without re-login. Long-lived, so
  the dangerous one → **rotation + reuse detection**: every refresh issues a new
  refresh token and invalidates the old; presenting an already-rotated one nukes
  the whole token family (it means it was stolen). `offline_access` scope is what
  asks for a refresh token.

### Step 5 — client validates the ID token

JWT = three base64url parts (header.payload.signature). Validate *before trusting*:
- **Signature** — fetch public keys from `/jwks.json`, match the `kid` in the
  header, verify the ES256 signature. This is why you sign **asymmetrically** —
  clients verify with the public key; the private key never leaves the IdP.
- **`iss`** = `https://auth.kicon.com` · **`aud`** = `banmua` (this token is for me)
  · **`exp`** not passed · **`nonce`** matches step 1.

```json
{
  "iss": "https://auth.kicon.com",
  "sub": "u_8f3c...",         // stable, opaque user id — NEVER the email
  "aud": "banmua",
  "exp": 1720444800,
  "nonce": "abc789",
  "email": "user@example.com",
  "locale": "vi-VN"           // ← resolved through banmua's tenant override
}
```

The `sub` (stable, opaque, never reused, never the email) *is* the identity.

### Part 3 self-test

Map each to the step it defends and the attack it stops:
> exact redirect-URI matching · `state` · `nonce` · PKCE · asymmetric signing ·
> one-time codes · refresh rotation

---

<a name="4-identity-model"></a>
## 4. Deep dive: the identity model (findAccount / claim projection)

Most of this is *yours* — OIDC gives you a claims hook and gets out of the way.
Everything interesting happens in one function: **`findAccount`**.

> The exact `findAccount` signature and claims/config shape **change across
> `node-oidc-provider` major versions**. What follows is the correct mental model
> and current shape — verify names against the installed version before relying.

### The one seam

```
   AUTHENTICATION                        │        PROJECTION
   "which human is this?"                │  "what does THIS client see about them?"
   (login page, password, session)       │  (findAccount → claims())
                              ─────────── │ ───────────
   resolves to one stable sub  ──────────┼──────────►  same sub, N different views
```

Authentication lands on one stable `sub`, the same regardless of client — **that's
the shared pool.** Projection returns a different view per client — **that's the
hard partition.** Both meet here:

```ts
// shape is version-sensitive — verify against installed node-oidc-provider
async findAccount(ctx, sub /*, token */) {
  const client = ctx.oidc.client;              // e.g. 'banmua'
  const tenant = tenantOf(client.clientId);    // → 'food' | 'civic' | 'trader'
  const user   = await users.findById(sub);    // the thin shared core
  if (!user) return undefined;

  return {
    accountId: sub,
    // Called at token-mint AND at /userinfo. `use` distinguishes them.
    async claims(use, scope /*, claims, rejected */) {
      return projectClaims({ user, tenant, use, scope, ctx });
    },
  };
}
```

Two things to burn in:
1. **`findAccount` receives `ctx`** → it knows the `client_id` → it derives the
   **tenant**. Tenant is a property of *who's asking*, not stored on the user.
2. **`claims()` is a closure computed per request** (mint time + `/userinfo`), not
   a stored blob. Nothing pre-materialized, nothing to leak between tenants by
   accident.

### The three-layer identity, and why each layer exists

```
┌─ Ring 1: SHARED CORE ──────────────────────────────────┐
│  users(id, primary_email, name,                          │
│        default_locale, default_zoneinfo, created_at)     │
│  → one row per human. Thin. Low-sensitivity on purpose.  │
│  → identity every client may see.                        │
│                                                           │
│  ┌─ Ring 2: SHARED-WITH-OVERRIDE ────────────────────┐   │
│  │  user_tenant_prefs(user_id, tenant_id,             │   │
│  │                    locale?, zoneinfo?)             │   │
│  │  → sparse: a row exists ONLY when a tenant          │   │
│  │    overrode a true-shared attribute.                │   │
│  └────────────────────────────────────────────────────┘   │
│                                                           │
│  ┌─ Ring 3: HARD-PARTITIONED (never cross-read) ──────┐   │
│  │  food_delivery_addresses   (food only)             │   │
│  │  civic_residency           (civic only)  SENSITIVE │   │
│  │  trader_profile            (trader only) FINANCIAL │   │
│  └────────────────────────────────────────────────────┘   │
└───────────────────────────────────────────────────────────┘
```

- **Ring 1 is thin on purpose.** What every client sees, so keep it boring. Less
  here = smaller blast radius. Resist fattening it with `phone`/`dob`/`address` —
  that pull is the main way the design rots.
- **Ring 2 exists because a few attributes are person-level but may differ per
  app.** `locale`: I want `banmua` in Vietnamese, `xbottrader` in English. Same
  *kind* of fact everywhere (not fully partitioned), value can diverge (not a
  single core column). The sparse override row expresses exactly that.
- **Ring 3 exists because some data is the same *word*, different *meaning* — or
  is too sensitive to share.** `address` in food ≠ `address` in civic. Trader
  financial data is visible only to trader. These tables are never joined across
  tenants — a food request's query path can't even *name* `trader_profile`.

### The cascade — resolving a true-shared attribute (Ring 2 only)

```ts
// value(user, tenant, attr) = tenant_override ?? global_default
async function resolveShared(user, tenant, attr, ctx) {
  const override = await tenantPrefs.get(user.id, tenant, attr);        // 1. app-specific
  if (override != null) return override;
  if (user[`default_${attr}`] != null) return user[`default_${attr}`];  // 2. global
  return detectFromRequest(ctx, attr);   // 3. Accept-Language / tz probe (don't persist!)
}
```

Three rules encoded:
1. **Writes land on the tenant override by default** — so one app never silently
   changes another's behavior. The global default is edited *only* from the
   central `kicon.com` account page (which says "applies everywhere unless an app
   overrides"). Two write targets, two UIs — keep them separate.
2. **Detection is a fallback, not a write.** Detect from `Accept-Language` / a JS
   timezone probe; persist only on explicit user action.
3. `??` means an absent override is invisible — the sparse table stays sparse.

### The payoff: same user, three projections

```ts
async function projectClaims({ user, tenant, use, scope, ctx }) {
  const base = { sub: user.id };                        // always; opaque, stable
  if (scope.includes('email'))   base.email = user.primary_email;
  if (scope.includes('profile')) {
    base.name     = user.name;
    base.locale   = await resolveShared(user, tenant, 'locale', ctx);   // Ring 2 cascade
    base.zoneinfo = await resolveShared(user, tenant, 'zoneinfo', ctx);
  }

  // Ring 3 — ONLY the owning tenant, and even then only identity-grade facts:
  if (tenant === 'civic' && scope.includes('civic:district')) {
    const res = await civicResidency.get(user.id);      // civic table ONLY
    if (res?.verified_at) base.district = res.district_id;
    // emit the DISTRICT (a derived identity fact), not the raw address
  }
  // food & trader emit NO Ring-3 identity claims — their app data is fetched
  // from resource servers via the access token, not carried in the token.

  return base;
}
```

Same human `u_8f3c`, three clients:

| Claim | `banmua` (food) | `vietcouncil` (civic) | `xbottrader` (trader) |
|---|---|---|---|
| `sub` | `u_8f3c` | `u_8f3c` | `u_8f3c` |
| `email` | ✓ | ✓ | ✓ |
| `name` | ✓ | ✓ | ✓ |
| `locale` | `vi-VN` (override) | `vi-VN` (global default) | `en-US` (override) |
| `district` | — | `D3` (verified) | — |
| trader/food data | *not a claim* | *not a claim* | *not a claim* |

The `if (tenant === …)` guard is the only door to partitioned data, and it's keyed
off *who's asking*.

### The insight that separates a good IdP from a leaky one

**Food delivery addresses and trader profile data are NOT identity claims.**

- **Identity claims** (ID token / `/userinfo`) answer *"who is this person?"* —
  stable, small, describe the human: `sub`, `email`, `name`, `locale`, verified
  `district`.
- **Application data** (behind a resource server, fetched with the *access token*
  + a scope like `food:addresses`) answers *"what does this app store for them?"*
  — five labeled delivery addresses are a shopping feature, not an identity fact.

Rule of thumb: **a bounded fact that describes the human can be a claim; a
collection / app-specific / bulk data lives behind the resource server and travels
via the access token + scope, never as an identity claim.** Cramming app data into
ID tokens is the most common IdP design smell.

Civic's *single verified residential address* drives district assignment and *is*
identity-grade → emit the derived `district` claim, keep the raw address inside the
civic tenant.

### `id_token` vs `userinfo` — the `use` argument

`claims(use, ...)` runs for both; return different amounts:
- **`use === 'id_token'`** → lean. It gets logged/cached. `sub` + `nonce` +
  essentials.
- **`use === 'userinfo'`** → fetched on demand over TLS with the access token; the
  right place for the fuller set.

### RBAC follows the same partition

Resolve roles **per tenant**, key by `(user_id, tenant_id)` from day one, emit as
a claim or resolve at the resource server. A user's `civic` roles must never appear
in a `food` token. Don't build the OPA/Zanzibar policy layer now — just leave room.

### Design tensions worth chewing on

1. **Where does the tenant→client mapping live?** Must be authoritative, fast,
   auditable — wants to be as static as the client registrations.
2. **`prompt=login` gating meets projection.** Gating is the *authentication* half;
   projection is unchanged. Good check that the two halves are cleanly separated.
3. **Account linking / shared `sub`.** One human = one `sub` across tenants — but
   how do you *know* `a@x.com` at banmua and `b@y.com` at vietcouncil are the same
   person? The hardest unsolved problem in the model. Deserves its own session.
4. **Verified vs claimed.** `civic_residency.verified_at` gates emitting `district`.
   Never emit an unverified sensitive claim as if verified — downstream trusts it.

### Part 4 self-test

> - Why is `locale` in Ring 2 but `address` in Ring 3, given both "vary by app"?
> - Why does `findAccount` need `ctx`, not just `sub`?
> - Why are food delivery addresses *not* an OIDC claim, but civic `district` *is*?
> - What structurally prevents a `trader` claim from ever landing in a `food` token?

---

<a name="5-roadmap"></a>
## 5. Phased build roadmap

Key insight: **build and learn almost the entire IdP on your laptop first.** The
droplet is the *last* phase. Certs/DNS teach nothing about OIDC.

- **Phase 0 — Learn (now, no server).** This document. Draw the flow from memory;
  optionally *be a client* at an existing IdP once.
- **Phase 1 — Scaffold, local.** NestJS + `node-oidc-provider`, Postgres + Redis
  in Docker Compose, in-memory adapter first. Goal: a valid discovery document.
- **Phase 2 — One real flow, local.** A throwaway test client doing full
  Auth Code + PKCE against `localhost`; custom login page; verify one ID token.
  **This is where it clicks.**
- **Phase 3 — Your identity model.** Postgres adapters, the Ring 1/2/3 schema,
  Argon2id, `findAccount` with per-tenant projection. The bulk of *your* work.
- **Phase 4 — Hardening.** Refresh rotation + reuse detection, key rotation script,
  rate limiting, audit log, MFA, SSO gating.
- **Phase 5 — Droplet.** Only now. Deploy the thing you already understand.

---

<a name="6-droplet"></a>
## 6. Droplet setup — for Phase 5 (deferred)

The IdP is the login path for *every* platform — a lone droplet reboot locks users
out of everything. Target is modest but redundant.

```
                DNS: auth.kicon.com → droplet public IP
                          │
                    ┌─────▼─────┐
                    │   nginx    │  TLS (Let's Encrypt), reverse proxy, headers
                    └──┬─────┬───┘
                 ┌─────▼─┐ ┌─▼─────┐   two app instances so a restart/deploy
                 │ node  │ │ node  │   never brings the login path fully down
                 │ inst1 │ │ inst2 │
                 └───┬───┘ └───┬───┘
                     └────┬────┘
        ┌───────────┬─────┴─────┐
  ┌─────▼─────┐          ┌──────▼──────┐
  │ Postgres  │          │    Redis    │
  │ (managed) │          │  (managed)  │
  └───────────┘          └─────────────┘
```

Steps, in order:
1. **Provision.** DO droplet (2GB+). Strongly prefer DO **Managed Postgres** +
   **Managed Redis** over self-hosting — you get automated backups + failover free
   (backups are mandated). Highest-leverage decision.
2. **Base hardening.** Non-root sudo user, SSH keys only (disable password auth),
   `ufw` allowing only 22/80/443, `fail2ban`, unattended security upgrades.
3. **DNS.** `A` record `auth.kicon.com` → droplet IP. Nothing on the apex yet.
4. **TLS.** nginx + Certbot (Let's Encrypt) with auto-renewal. HTTPS is
   non-negotiable — the protocol assumes it.
5. **Two app instances.** Under `systemd`/PM2; nginx load-balances. Meets the
   "reboot doesn't lock everyone out" rule cheaply on one box. Later: a second
   droplet + DO Load Balancer for real hardware redundancy.
6. **Secrets off-repo.** Signing keys + DB creds as env vars / secrets store —
   never in the image or git.
7. **Session/token store.** Point the Redis adapter at Managed Redis.
8. **Health checks + backups.** nginx health endpoint, DO monitoring alerts,
   test a Postgres restore once.
9. **Deploy pipeline.** Even staggered `git pull` + `systemctl restart` (one stays
   up) beats manual scp. Containerize when it stops being fun.

---

<a name="7-resources"></a>
## 7. Learning resources

- **OpenID Connect Core 1.0** spec — intro + Authorization Code flow section.
  Authoritative; you'll return to it.
- **`node-oidc-provider` docs & recipes** (panva, GitHub) — treat as primary;
  always read the *installed* version.
- **OAuth 2.0 Simplified** (Aaron Parecki) — friendliest correct explanation.
- **jwt.io** — paste a token, watch it decode. Great for the JWT/JWKS tier.
- **oauth.com** and the **OAuth 2.1 draft (BCP)** — the "why" behind banned flows
  (Implicit, ROPC).

---

<a name="8-self-test"></a>
## 8. Master self-test

If you can answer all of these, Phase 0 is solid:

**Protocol**
- Draw the Auth Code + PKCE flow from memory, all 6 steps.
- What attack does each stop: exact redirect-URI matching · `state` · `nonce` ·
  PKCE · asymmetric signing · one-time codes · refresh rotation?
- Difference between `state` and `nonce` (which protects what)?
- Why is the authorize request unauthenticated but the token request authenticated?
- Three tokens, three audiences — name each audience.
- Why sign asymmetrically (ES256) instead of a shared secret?

**Identity model**
- Why is `locale` Ring 2 but `address` Ring 3?
- Why does `findAccount` need `ctx`, not just `sub`?
- Why are food delivery addresses *not* a claim, but civic `district` *is*?
- What structurally prevents a `trader` claim from landing in a `food` token?
- Where should the tenant→client mapping live, and why?

**Sessions / SSO**
- IdP session cookie vs the tokens — what's the difference and why keep the cookie
  scoped to `auth.kicon.com`?
- How does `prompt=login` / `max_age` gate cross-tenant SSO, and which half of the
  flow (auth vs projection) does it touch?
