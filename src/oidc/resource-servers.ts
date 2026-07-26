import { errors } from 'oidc-provider';

/**
 * Resource servers (RFC 8707 resource indicators) and the scopes each client may
 * obtain for them. Kept beside clients.ts because it is registration data, but
 * split out because it carries a security invariant clients.ts does not.
 *
 * ── WHY THIS MAP IS THE AUTHORIZATION BOUNDARY ──────────────────────────────
 * oidc-provider validates a requested scope against the client's registered
 * `scope` metadata ONLY when that scope also appears in the provider-level
 * `scopes` array (lib/actions/authorization/check_scope.js). Resource-server
 * scopes deliberately do NOT appear there — they are the resource server's
 * vocabulary, not the IdP's (CLAUDE.md: "keep IdP scopes minimal"). That means
 * `vote` can ask for `vote:admin` at /authorize and nothing rejects the request.
 *
 * The ONLY thing that stops it is the `scope` string returned below, which
 * oidc-provider intersects with the grant when minting the access token. So:
 *
 *   Returning one fixed scope string for every client would let the embeddable
 *   consumer widget mint an admin token. This map MUST stay client-aware.
 *
 * There is a CI assertion covering exactly this (see .github/workflows/ci.yml).
 * Do not "simplify" it away.
 */

/** api.kicon.com — the shared resource server (vote/cart/trade modules). */
export const API_RESOURCE = 'https://api.kicon.com';

/**
 * api.survey.kicon.com — the survey platform's DEDICATED resource server (a
 * separate app, not a module in api.kicon.com — kicon-survey ADR-0006). Its own
 * audience with its own scope vocabulary; a token minted for one resource never
 * verifies at the other.
 */
export const SURVEY_RESOURCE = 'https://api.survey.kicon.com';

/** Every resource server the IdP knows how to mint access tokens for. */
export const RESOURCES = [API_RESOURCE, SURVEY_RESOURCE] as const;

/**
 * resource → (client_id → the scopes that client may obtain for THAT resource).
 *
 * Naming is `<app>:<action>`. A client absent from a resource's map gets no
 * scopes there at all (the `?? ''` fallback below) — deny by default, so
 * registering a new client never silently grants access to any resource.
 */
const RS_SCOPES: Record<string, Record<string, string>> = {
  [API_RESOURCE]: {
    // Consumer surface (vote.kicon.com, embeddable). Read polls, cast a ballot.
    // Deliberately NOT vote:admin — this surface is framed into partner sites.
    vote: 'vote:read vote:write',

    // Admin surface (admin.vote.kicon.com, never framed, MFA + forced re-auth).
    // vote:admin is necessary but NOT sufficient at the resource server:
    // api.kicon.com additionally requires an app_role_assignments row and acr=loa2.
    'vote-admin': 'vote:read vote:write vote:admin',

    // Partner bridge (client_credentials, no human). Assert org membership so the
    // resource server can gate a poll WITHOUT civic claims crossing the partition.
    'vote-bridge': 'vote:eligibility:write',
  },

  [SURVEY_RESOURCE]: {
    // Respondent surface (survey.kicon.com, embeddable). A LOGGED-IN respondent
    // answers surveys; ANONYMOUS respondents use a capability token instead
    // (kicon-survey ADR-0005), not an OIDC scope.
    survey: 'survey:respond',

    // Authoring studio (studio.survey.kicon.com, never framed, MFA + forced
    // re-auth). Composes, previews, publishes, and analyses. As with vote-admin,
    // the scope authorizes the SURFACE; the survey api additionally gates on RBAC.
    'survey-studio': 'survey:author survey:publish survey:analyze survey:admin',

    // Partner survey-bridge (client_credentials, no human). Vouch for a respondent
    // so the survey api can mint a capability token, WITHOUT the partner's identity
    // model crossing into kicon. Narrow write only.
    'survey-bridge': 'survey:vouch',
  },
};

/** The scopes `clientId` may obtain for `resource`, as a space-delimited string. */
export function resourceScopesFor(resource: string, clientId: string): string {
  return RS_SCOPES[resource]?.[clientId] ?? '';
}

/** Back-compat helper: scopes for the api.kicon.com resource (used by the CI assertion). */
export function apiScopesFor(clientId: string): string {
  return resourceScopesFor(API_RESOURCE, clientId);
}

/**
 * features.resourceIndicators.getResourceServerInfo.
 *
 * accessTokenFormat:'jwt' is what makes the access token a verifiable JWT instead
 * of an opaque handle — the resource server verifies it locally against /jwks
 * with no introspection round-trip. jwt.sign.alg is pinned to ES256 because the
 * keystore holds ES256 keys only (src/oidc/keys/keystore.ts).
 */
export function getResourceServerInfo(_ctx: any, resourceIndicator: string, client: any) {
  if (!(RESOURCES as readonly string[]).includes(resourceIndicator)) {
    // Unknown resource. InvalidTarget is the RFC 8707 error for this.
    throw new errors.InvalidTarget();
  }
  return {
    scope: resourceScopesFor(resourceIndicator, client?.clientId ?? ''),
    audience: resourceIndicator,
    accessTokenFormat: 'jwt' as const,
    accessTokenTTL: 15 * 60,
    jwt: { sign: { alg: 'ES256' } },
  };
}
