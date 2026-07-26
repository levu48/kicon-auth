/**
 * Client secrets for the confidential clients, loaded from the environment.
 *
 * WHY THIS EXISTS: `clients.ts` used to hardcode `dev-*-CHANGE-ME` secrets for
 * every confidential client, with no way to supply a real one — so a production
 * deploy authenticated those clients with a secret published in this git repo.
 * There was no vault hook to reach for; this module is it.
 *
 * THE RULE, and the whole point of the module:
 *   - production  → the env var MUST be set to a non-placeholder value, or boot
 *                   FAILS LOUDLY. Silently falling back to a dev secret is the
 *                   exact failure this replaces.
 *   - non-prod    → fall back to the documented dev placeholder, so local dev,
 *                   CI, and the seeded MFA/bridge flows keep working untouched.
 *
 * Env var name is derived from the client_id: `CLIENT_SECRET_<UPPER_SNAKE>`, e.g.
 *   survey-bridge → CLIENT_SECRET_SURVEY_BRIDGE
 *   vietcouncil   → CLIENT_SECRET_VIETCOUNCIL
 *
 * Generate a value with:  openssl rand -base64 48
 *
 * A rotated secret must be updated in the CLIENT too (the machine-to-machine
 * consumer that presents it), in the same window — see docs/client-secrets.md.
 */

/** Marks a value as a dev placeholder, never acceptable in production. */
const DEV_PLACEHOLDER = /CHANGE-ME/i;

/**
 * Dev-only fallbacks. These are intentionally weak and PUBLIC — they exist so a
 * developer can clone and run without provisioning secrets. They are refused in
 * production by `secretFor`.
 */
const DEV_SECRETS: Record<string, string> = {
  vietcouncil: 'dev-vietcouncil-secret-CHANGE-ME',
  xbottrader: 'dev-xbottrader-secret-CHANGE-ME',
  'vote-bridge': 'dev-vote-bridge-secret-CHANGE-ME',
  'survey-bridge': 'dev-survey-bridge-secret-CHANGE-ME',
};

/** `survey-bridge` → `CLIENT_SECRET_SURVEY_BRIDGE` */
export function envVarFor(clientId: string): string {
  return `CLIENT_SECRET_${clientId.toUpperCase().replace(/-/g, '_')}`;
}

/**
 * Resolve a confidential client's secret. Throws in production when the env var
 * is missing/blank or still carries a dev placeholder — a misconfigured prod
 * must not start, because a booting IdP with a known secret looks perfectly
 * healthy while being wide open.
 */
export function secretFor(clientId: string): string {
  const varName = envVarFor(clientId);
  const fromEnv = process.env[varName]?.trim();
  const isProd = process.env.NODE_ENV === 'production';

  if (fromEnv) {
    if (isProd && DEV_PLACEHOLDER.test(fromEnv)) {
      throw new Error(
        `${varName} is set to a dev placeholder. Generate a real secret ` +
          `(openssl rand -base64 48) and set it in .env.prod — see docs/client-secrets.md.`,
      );
    }
    return fromEnv;
  }

  if (isProd) {
    throw new Error(
      `${varName} is not set. Every confidential client needs a real secret in ` +
        `production; refusing to boot with the dev fallback for '${clientId}'. ` +
        `See docs/client-secrets.md.`,
    );
  }

  const dev = DEV_SECRETS[clientId];
  if (!dev) {
    throw new Error(
      `No dev fallback secret registered for client '${clientId}'. Add one to ` +
        `DEV_SECRETS in client-secrets.ts, or set ${varName}.`,
    );
  }
  return dev;
}

/** The confidential clients, so tooling/tests can enumerate what must be provisioned. */
export const CONFIDENTIAL_CLIENT_IDS = Object.keys(DEV_SECRETS);
