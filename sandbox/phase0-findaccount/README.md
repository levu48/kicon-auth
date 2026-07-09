# Phase 0 sandbox — `findAccount` claim projection

A **throwaway learning demo**, not the real IdP. No NestJS, no
`node-oidc-provider`, no Postgres, no Redis, no HTTP server. Everything is
in-memory. It isolates the single most important idea in the identity model:

> ONE stable user (`sub`) → THREE clients → THREE different ID tokens,
> because claims are **projected per-tenant at mint time** in `findAccount()`.

## Run

```bash
npm install
npm run demo
```

## What it demonstrates

- **`findAccount` as the seam** — `ctx` gives the `client_id` → the tenant →
  which projection to apply.
- **The Ring 1/2/3 model** from `CLAUDE.md`: thin shared core, sparse per-tenant
  overrides, hard-partitioned tenant tables.
- **The Ring-2 cascade** `value = tenant_override ?? global_default ?? detected`
  — the trace lines show *which* source each value came from.
- **The Ring-3 hard partition** — only the owning tenant emits its claim; it's
  literally one `if (tenant === 'civic')` guard.
- **Real trust machinery** — mints ES256-signed JWTs and verifies them against a
  JWKS (stand-in for `GET /jwks.json`), including `iss`/`aud` checks.

## Things to try (learning)

- Delete the `food` override row in `userTenantPrefs` → watch banmua fall through
  to the global default.
- Add a `civic:district` claim attempt from a non-civic tenant → confirm the
  guard refuses it.
- Change `use` handling so the `id_token` stays lean and `userinfo` returns more.
- Tamper with one character of a printed token and feed it back to `jwtVerify` →
  watch the signature check fail.

## Related

- `../../docs/phase-0-study-notes.md` — Part 4 (identity model) explains every
  line of this.
- `../../CLAUDE.md` — the settled architecture this is modeled on.
