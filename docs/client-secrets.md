# Confidential client secrets

The IdP has four **confidential** clients — ones that authenticate with a shared
secret rather than PKCE:

| client_id | Used by | Env var |
|---|---|---|
| `vietcouncil` | Viet Council civic app | `CLIENT_SECRET_VIETCOUNCIL` |
| `xbottrader` | XBotTrader | `CLIENT_SECRET_XBOTTRADER` |
| `vote-bridge` | vote eligibility bridge (machine-to-machine) | `CLIENT_SECRET_VOTE_BRIDGE` |
| `survey-bridge` | survey partner vouch bridge (machine-to-machine) | `CLIENT_SECRET_SURVEY_BRIDGE` |

Secrets are resolved by [`src/oidc/client-secrets.ts`](../src/oidc/client-secrets.ts),
which reads `CLIENT_SECRET_<CLIENT_ID>` (upper snake case) from the environment.

## The rule

- **production** — the env var must be set to a real, non-placeholder value. If it
  is missing, blank, or still contains `CHANGE-ME`, **the IdP refuses to boot**.
- **anything else** — falls back to the documented dev placeholder, so `npm run
  start:dev`, CI, and the seeded MFA/bridge flows work with no provisioning.

The hard failure is deliberate. A misconfigured IdP that boots anyway serves
tokens normally while accepting a secret that is public in this repo — it looks
completely healthy from the outside. Failing at boot turns a silent compromise
into an obvious outage.

> **History:** these secrets were hardcoded as `dev-*-CHANGE-ME` in `clients.ts`
> with no override mechanism, so any production deploy ran with repo-published
> credentials. That is what this module fixes.

## Before your next production deploy

`.env.prod` on the droplet must gain all four variables **before** the next IdP
deploy, or the container will fail to start.

```bash
# on the droplet, in the IdP's deploy dir
openssl rand -base64 48    # once per client
vi .env.prod               # add the four CLIENT_SECRET_* lines
```

If you are not ready to rotate a given client, set its variable to that client's
**current** value — the mechanism is then in place with no behavior change, and
you can rotate later on your own schedule.

## Rotating a secret

A confidential client secret is shared between the IdP and the consumer that
presents it. Rotating one side alone breaks that client's authentication, so do
both in the same window:

1. Generate: `openssl rand -base64 48`.
2. Set the new value in the IdP's `.env.prod`.
3. Set the same value in the consumer (e.g. the survey api's
   `SURVEY_BRIDGE_CLIENT_SECRET`, the vote bridge's equivalent).
4. Redeploy the IdP, then the consumer.
5. Verify with a `client_credentials` token request — see the probes in
   `test/token-contract.mjs`.

`oidc-provider` holds one secret per client, so there is no overlap window: step
2 invalidates the old secret immediately. For a zero-downtime rotation you would
need to register a second client and migrate consumers across — worth doing for
a high-traffic bridge, unnecessary for the current low-volume ones.

## Adding a new confidential client

1. Add the client to `clients.ts` with `client_secret: secretFor('<id>')`.
2. Add a dev fallback to `DEV_SECRETS` in `client-secrets.ts` (this also adds it
   to `CONFIDENTIAL_CLIENT_IDS`).
3. Add `CLIENT_SECRET_<ID>` to `.env.prod.example` and to the droplet's
   `.env.prod`.
4. Add a row to the table above.
