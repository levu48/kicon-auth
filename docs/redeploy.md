# Redeploy note — pushing a change live

Deploys are **manual** — there is no CI/CD. Pushing to GitHub updates the repo,
**not** the running server. To make a merged change live on `auth.kicon.com`,
someone runs this on the droplet. Companion to the one-time standup in
[`deployment.md`](deployment.md).

## Which path?

- **Code / static config only** (e.g. a new OAuth client in `src/oidc/clients.ts`,
  a route, a policy tweak) → **no migration**. Rebuild + roll the instances.
- **Schema change** (new/updated TypeORM entity or migration) → run `migrate`
  **before** rolling the instances.

Not sure? If `git diff` touches `src/database/migrations/` (or entities), it's a
schema change.

## Rolling redeploy (on the droplet)

```bash
cd /opt/kicon-idp && git pull

docker compose -f docker-compose.prod.yml build

# Schema change only — otherwise SKIP this line:
docker compose -f docker-compose.prod.yml run --rm migrate

# Roll the two app instances one at a time so nginx always has a live upstream:
docker compose -f docker-compose.prod.yml up -d --no-deps --force-recreate app1
docker compose -f docker-compose.prod.yml up -d --no-deps --force-recreate app2
```

## Verify

```bash
curl -s https://auth.kicon.com/healthz          # {"status":"ok"}
docker compose -f docker-compose.prod.yml ps     # app1, app2, nginx healthy
```

For a client-registration change specifically, confirm the new `client_id` is
recognized (an unknown client returns `invalid_client`; a known one gets past
client validation — e.g. to a redirect/scope check):

```bash
curl -s "https://auth.kicon.com/auth?client_id=<id>&response_type=code\
&scope=openid&redirect_uri=<registered-uri>&code_challenge=x&code_challenge_method=S256" \
  | grep -oiE 'invalid_client|invalid_redirect|login'
# invalid_client  -> NOT deployed yet
# anything else   -> client is recognized (deployed)
```

> **Pending:** `vote-admin` (committed in the client list) is not on the live
> server until this runbook is run — the live IdP still returns `invalid_client`
> for it.
