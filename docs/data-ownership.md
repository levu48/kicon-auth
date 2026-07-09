# Data ownership & the storage boundary

Settles: *"can an application (e.g. banmua) share the IdP's database?"* — **No.**
This document is the authoritative boundary for who stores what. Read it before
designing the Phase 3 schema. Companion to [`CLAUDE.md`](../CLAUDE.md).

---

## The one rule

> **Applications learn identity through tokens, never through shared storage.**
> An application's database and the IdP's database are separate, and no
> application role can reach the IdP's tables.

`auth.kicon.com` is the crown jewel: it holds password hashes, MFA secrets,
refresh-token/grant state, the audit log, and the sensitive tenant identity
tables. Every platform's login depends on it. So its datastore is reachable only
by the IdP itself. A relying party (banmua, vietcouncil, xbottrader) receives a
**`sub`** and projected **claims** in its tokens and stores `sub` as the foreign
key linking its own rows to the user. That is the entire substitute for a shared
user table.

This is the data-layer twin of the settled cookie rule: cross-domain identity
flows through the OIDC redirect flow, **not** through shared cookies — and **not**
through shared storage.

---

## Why (what sharing would break)

- **Crown-jewel blast radius.** Share the DB and a SQL-injection or leaked
  credential *in an app* can read Argon2id password hashes, MFA secrets, and
  refresh tokens for **every** platform. Today, compromising banmua costs you
  banmua; sharing storage makes it cost you every login everywhere.
- **The hard partition becomes fiction.** The `if (tenant === 'civic')` guard in
  `findAccount` only gates the *token projection*. If an app has raw table
  access, a food bug can read `civic_residency` / `trader_profile`. The partition
  is only real if those tables are **unreachable** by other tenants' code.
- **The OIDC contract.** Apps are "just another client with no special access."
  Direct DB reads bypass scopes, claim projection, and tenant isolation — the
  whole boundary the IdP exists to enforce.
- **Operational coupling.** An app's migrations, query load, or downtime must
  never be able to affect the login path.

---

## Who owns what

| Data | Owner | Store | How others reach it |
|---|---|---|---|
| `users` (Ring 1: id, primary_email, name, defaults) | IdP | IdP Postgres | via ID-token/`userinfo` claims only |
| `user_tenant_prefs` (Ring 2: locale/zoneinfo overrides) | IdP | IdP Postgres | resolved into `locale`/`zoneinfo` claims |
| password hashes, MFA secrets | IdP | IdP Postgres | never leaves the IdP |
| audit log | IdP | IdP Postgres | never leaves the IdP |
| sessions, auth codes, tokens, grants | IdP | Redis | never leaves the IdP |
| `civic_residency` (verified address → district) **[sensitive]** | IdP (civic) | IdP Postgres | only as the `district` claim, only to civic |
| `trader_profile` **[sensitive/financial]** | IdP (trader) | IdP Postgres / dedicated store | never as an identity claim; trader RS only |
| `food_delivery_addresses` | **banmua (food app)** | **banmua's own DB** | banmua's resource server, `food:addresses` scope |
| food orders, menus, carts | banmua | banmua's own DB | banmua's resource server |

**Rule of thumb:** *identity-grade, bounded, describes the human* → IdP. *A
collection / app feature / high-churn app data* → the application's own DB, keyed
by `sub`.

---

## The `sub`-as-foreign-key pattern

```
-- banmua's OWN database (NOT the IdP's). No password, no email-as-key,
-- no knowledge of civic/trader. Just: "user u_8f3c did X."
food_orders(id, user_sub, items, total, created_at)
food_delivery_addresses(id, user_sub, label, line1, city, ...)
```

`user_sub` is the opaque OIDC `sub`. banmua never joins to an IdP table; if it
needs a fresher profile attribute it calls `/userinfo` with the access token.

---

## Resolved ambiguity: `food_delivery_addresses`

`CLAUDE.md`'s identity-model section lists `food_delivery_addresses` alongside the
tenant-scoped identity tables, which reads as "IdP-owned." Elsewhere the same doc
treats food addresses as application data behind the food resource server. Those
conflict. **Resolution (this document wins for storage placement):**
`food_delivery_addresses` is **application data, owned by banmua, stored in
banmua's DB** — it is user-editable, non-authoritative, tied to orders, and never
an identity claim. It stays out of the crown-jewel IdP database to keep that
surface small and boring.

`civic_residency` and `trader_profile` remain behind the IdP boundary precisely
because they are identity-grade and sensitive (`civic_residency.verified_at`
literally drives the `district` claim the IdP mints).

---

## Same server vs same database

- **Same tables / same database as the IdP** → never, for any app.
- **Same Postgres *server*, separate database + separate role** (app role cannot
  see the IdP database) → tolerable only as an early cost optimization, but it
  still couples uptime/backups/load and one bad `GRANT` collapses the isolation.
  For the crown-jewel service, prefer its own managed instance from the start
  (consistent with the Phase 5 deployment note in `CLAUDE.md`).

---

## Deployment: where the IdP database runs (staging vs production)

Storage *ownership* (above) is settled. *Hosting* is staged by environment — the
isolation bar rises as the IdP becomes the live login path.

| Environment | IdP Postgres hosting | Rationale |
|---|---|---|
| **Local dev** | Postgres container co-located with the app (`docker-compose.yml`) | Zero-friction; nothing real at stake. |
| **Staging** (budget) | Postgres container on the staging droplet, **for staging only** | Acceptable cost compromise *with an explicit plan to move before go-live*. |
| **Production** | **Managed Postgres**, own instance, private network | Crown-jewel login path — needs backups/PITR, failover, and host isolation. |

**Do not run the IdP's Postgres on the IdP app droplet in production.** Reasons:

- The IdP must not be a lone droplet (`CLAUDE.md`): one reboot/failure would take
  down the app **and** the DB → total login outage for every platform. Two app
  instances behind nginx are pointless if they both depend on a Postgres living
  on one of those same boxes.
- Managed Postgres provides the automated backups + point-in-time recovery that
  `CLAUDE.md` mandates, plus standby failover — not a cron job and hope.
- Password hashes / MFA secrets should not sit on the host that terminates public
  HTTP; keep the datastore on a private network reachable only by IdP instances.
- Postgres (page cache, IO) and Node (CPU) contend on a small droplet.

**The rule:** a co-located IdP Postgres is fine for dev/staging, but before
banmua/civic/trader log in against it for real, the IdP moves to its own managed
instance on a private network. This is a Phase 5 (droplet deploy) task; nothing
to change while development is local.

## Enforcement checklist (when we build Phase 3)

- IdP Postgres: dedicated instance/database; a role used **only** by the IdP.
- No application credential is ever granted on IdP tables.
- Network: IdP datastore reachable only from IdP app instances (private network /
  firewall), not from application hosts.
- Applications store `sub` as the user key; they never receive IdP DB credentials.
- Sensitive tenant tables (`civic_residency`, `trader_profile`) are readable only
  by the IdP's claim-resolution path, never by an app or another tenant.
