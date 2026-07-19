# Phase 5 — Droplet deployment runbook

How to stand up `auth.kicon.com` in production. Execute these steps **on the
droplet** when you are ready — nothing here runs from a dev machine automatically.

**Before you start**, meet the readiness gate in
[`banmua-integration.md`](banmua-integration.md): this deploy must be fully green
*before* the live banmua app is ever pointed at it. Artifacts referenced:
[`Dockerfile`](../Dockerfile), [`docker-compose.prod.yml`](../docker-compose.prod.yml),
[`deploy/nginx/nginx.conf`](../deploy/nginx/nginx.conf),
[`.env.prod.example`](../.env.prod.example).

Topology: **nginx (TLS) → two app instances**, with **managed Postgres + managed
Redis** (external, not on the droplet). Rationale in
[`data-ownership.md`](data-ownership.md).

---

## 1. Provision

- **Droplet:** Ubuntu LTS, 2 GB+ RAM. This runs nginx + two Node containers only.
- **Managed Postgres** (DigitalOcean Managed Databases): create a DB `kicon_idp`,
  a dedicated user, and note the **private-network** host. Automated backups + PITR
  come with it — this is why we don't self-host the crown-jewel DB.
- **Managed Redis:** create it; note the private host (`rediss://`, TLS).
- Put the droplet and both managed services on the **same VPC / private network**;
  restrict the databases to the droplet only (no public access).

## 2. Base hardening

```bash
adduser deploy && usermod -aG sudo deploy          # non-root sudo user
# SSH: key-only. In /etc/ssh/sshd_config: PasswordAuthentication no; PermitRootLogin no
systemctl restart ssh
ufw default deny incoming && ufw allow OpenSSH && ufw allow 80 && ufw allow 443 && ufw enable
apt-get update && apt-get install -y fail2ban unattended-upgrades
```

## 3. DNS

- `A` record `auth.kicon.com` → droplet public IP.
- Leave the `kicon.com` apex alone (reserved; a future app becomes just another client).

## 4. Install Docker

```bash
curl -fsSL https://get.docker.com | sh
usermod -aG docker deploy   # re-login afterwards
```

## 5. Get the code + create secrets

```bash
git clone <repo> /opt/kicon-idp && cd /opt/kicon-idp   # or rsync the tree

cp .env.prod.example .env.prod && chmod 600 .env.prod
# Fill in .env.prod: ISSUER=https://auth.kicon.com, DATABASE_URL, REDIS_URL,
# and COOKIE_KEYS (two random secrets):
#   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"

# Signing keystore — generate ONCE and keep it safe (back it up in your secret store).
mkdir -p secrets && chmod 700 secrets
docker compose -f docker-compose.prod.yml run --rm --entrypoint \
  "node dist/oidc/keys/cli.js init" app1   # or run `npm run keys:init` in a checkout
chmod 600 secrets/jwks.json
```
> The keystore is the crown-jewel signing key. It is gitignored and mounted
> read-only into the containers; never bake it into the image. Store a backup in
> your secret manager.

## 6. TLS certificate (Let's Encrypt)

```bash
apt-get install -y certbot
# First issuance: stop anything on :80, use standalone (or the nginx webroot).
certbot certonly --standalone -d auth.kicon.com
# Certs land in /etc/letsencrypt/live/auth.kicon.com/ (mounted into nginx).
# Auto-renew is installed by the certbot package; reload nginx post-renew:
echo "renew_hook = docker compose -f /opt/kicon-idp/docker-compose.prod.yml exec nginx nginx -s reload" \
  >> /etc/letsencrypt/renewal/auth.kicon.com.conf
```

## 7. Build, migrate, launch

```bash
cd /opt/kicon-idp
docker compose -f docker-compose.prod.yml build
# Run DB migrations once (creates the identity schema in managed Postgres):
docker compose -f docker-compose.prod.yml run --rm migrate
# Start nginx + the two app instances:
docker compose -f docker-compose.prod.yml up -d
```

## 8. Verify

```bash
curl -s https://auth.kicon.com/.well-known/openid-configuration | head
curl -s https://auth.kicon.com/jwks
curl -s https://auth.kicon.com/healthz          # {"status":"ok"} = Postgres+Redis reachable
docker compose -f docker-compose.prod.yml ps     # app1, app2, nginx all healthy
```
There is **no dev seed in production** (`NODE_ENV=production` skips it). Create real
accounts through your registration/admin path.

## 9. Operate

- **Backups:** managed Postgres does automated backups + PITR — **test a restore once**.
  Also back up `secrets/jwks.json` and `COOKIE_KEYS` in your secret store.
- **Key rotation:** `keys:rotate` in a checkout (or the CLI in a container) writes a
  new active key; then roll the app instances one at a time:
  `docker compose -f docker-compose.prod.yml up -d --no-deps --force-recreate app1`
  (then `app2`). Old tokens stay valid until their key is pruned.
- **Zero-downtime deploy:** `build` the new image, `run --rm migrate`, then recreate
  `app1` and `app2` one at a time so nginx always has a live upstream. For the
  recurring "I pushed a change, get it live" flow (and when to skip `migrate`), see
  [`redeploy.md`](redeploy.md).
- **Health/monitoring:** point DO monitoring / an uptime check at `/healthz`; alert on 503.
- **Logs:** `docker compose -f docker-compose.prod.yml logs -f app1`.

## 10. Only now — banmua cutover

With the deploy green and the readiness gate met, follow the **reversible cutover**
in [`banmua-integration.md`](banmua-integration.md): parallel-run, link existing
users to `sub` by verified email, canary behind a banmua feature flag, roll forward,
keep the old login one flag away until a clean soak.

---

## Hardening still open (tracked for later)

- DB-level INSERT-only role for the audit log; encrypt `user_mfa.secret` at rest.
- Move the JWKS/cookie secrets into a real secret manager (Vault / DO secrets) rather
  than a droplet file.
- Second droplet + DO Load Balancer for hardware redundancy (single droplet is the
  current SPOF even with two app instances).
