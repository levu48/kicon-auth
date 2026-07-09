# banmua integration & cutover — zero impact until production

**Standing constraint:** the existing, live banmua app must be **unaffected** by
IdP development until an intentional, reversible cutover, performed only after the
IdP is production-ready. This document is the guardrail.

Companion to [`docs/data-ownership.md`](data-ownership.md) and [`CLAUDE.md`](../CLAUDE.md).

---

## Why there is no impact during development

- **Separate origins.** The IdP is `auth.kicon.com`; banmua is its own app on its
  own origin. Nothing the IdP does reaches banmua.
- **Client registration is inert.** Listing banmua's redirect URIs in the IdP's
  `clients.ts` only *allows* a future request; the IdP never calls banmua. banmua
  is affected only when **banmua's own code** is changed to use the IdP.
- **No shared database** (see data-ownership.md). Building the IdP's Postgres
  cannot touch banmua's data.
- **The `banmua` in this repo is a test stub** in `sandbox/phase2-test-rp/`, not
  the real app.

The guarantee holds as long as the guardrails below are followed.

---

## Guardrails (development & staging)

**Do**
- Keep all IdP work local/staging; drive flows only with the `sandbox/` test RP.
- Treat banmua's redirect URIs / secrets in `clients.ts` as placeholders until
  confirmed with the real banmua team/deploy.
- Keep the IdP and banmua databases fully separate.

**Do NOT**
- Modify banmua's codebase or deployment.
- Point **production** banmua at a non-production IdP.
- Put production banmua's redirect URI on an IdP that isn't the real, TLS-served
  `auth.kicon.com` — a misconfigured redirect could send real users somewhere broken.
- Import or migrate real banmua user data anywhere until the cutover plan runs.

---

## Readiness gate — what "fully in production" means

Do not begin cutover until the IdP meets ALL of:

- [ ] Served at real `https://auth.kicon.com` with valid TLS and a stable issuer.
- [ ] Postgres = managed instance, private network, automated backups + PITR verified.
- [ ] Redis provisioned; sessions/tokens persist across restarts.
- [ ] Two app instances behind nginx (no lone-droplet single point of failure).
- [ ] Real signing keys from a secret store, with `kid` rotation scripted (not the
      dev-ephemeral keys).
- [ ] Refresh rotation + reuse detection, rate limiting, account lockout, audit log.
- [ ] Health checks + monitoring + alerting in place.
- [ ] banmua's exact redirect URI confirmed and registered (exact match, no wildcard).

(Phases 3–5 close these out; today we are at Phase 2, local.)

---

## Cutover plan (reversible, staged)

1. **Parallel run.** Deploy the production IdP alongside banmua's *existing* auth.
   Do not remove banmua's current login yet.
2. **Account linking / migration** — the load-bearing step, because banmua has
   existing users:
   - Decide the mapping from a banmua account to an IdP identity (`sub`).
   - Preferred: **link on first IdP login by verified email** — the user logs in
     via the IdP, and banmua matches the returned email to its existing record and
     stores the `sub`. No bulk password migration; Argon2id rehash-on-login if
     importing hashes later.
   - No existing user should have to re-register or lose data.
   - This is the account-linking problem flagged in Phase 0 (study notes, tension
     #3); resolve it before cutover, not during.
3. **Canary behind a feature flag in banmua.** Route a small % of logins (or
   internal/test accounts) through the IdP, with an **instant flip back** to the
   old auth path. banmua owns this flag.
4. **Watch.** Monitor login success rate, error rates, latency, support tickets.
   Roll back on regression — the old path is still live, so rollback is a flag flip.
5. **Ramp** gradually to 100%.
6. **Decommission banmua's old auth** only after a soak period at 100% with no
   regressions and a tested rollback still available.

**Rollback at every step** = flip the banmua feature flag back to its existing
auth. Because the two run in parallel and share no database, rollback never risks
data loss.

---

## One-line rule

> Nothing we build changes banmua until banmua's team flips a feature flag to a
> production-ready `auth.kicon.com`, with existing users linked by `sub` and the
> old login still one flag away. Until then, banmua is untouched.
