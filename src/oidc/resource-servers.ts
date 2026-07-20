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

/** The one resource server today. Must match api.kicon.com's API_AUDIENCE exactly. */
export const API_RESOURCE = 'https://api.kicon.com';

/**
 * client_id → the scopes that client may obtain FOR api.kicon.com.
 *
 * Naming is `<app>:<action>`. A client absent from this map gets no API scopes
 * at all (see the `?? ''` fallback below) — deny by default, so registering a
 * new client never silently grants API access.
 */
const RS_SCOPES: Record<string, string> = {
  // Consumer surface (vote.kicon.com, embeddable). Read polls, cast a ballot.
  // Deliberately NOT vote:admin — this surface is framed into partner sites.
  vote: 'vote:read vote:write',

  // Admin surface (admin.vote.kicon.com, never framed, MFA + forced re-auth).
  // Note vote:admin is necessary but NOT sufficient at the resource server:
  // api.kicon.com additionally requires an app_role_assignments row and acr=loa2.
  // Everyone who logs into the admin origin gets this scope; only actual admins
  // get past the resource server.
  'vote-admin': 'vote:read vote:write vote:admin',

  // Partner bridge (client_credentials, no human). Used by VietCouncil to assert
  // "this sub is a member of this org" so the resource server can gate a poll
  // WITHOUT civic identity claims crossing the tenant partition
  // (docs/app-platform-domains.md). Write-only, and only that one narrow thing.
  'vote-bridge': 'vote:eligibility:write',
};

/** The scopes `clientId` may obtain for the API, as a space-delimited string. */
export function apiScopesFor(clientId: string): string {
  return RS_SCOPES[clientId] ?? '';
}

/**
 * features.resourceIndicators.getResourceServerInfo.
 *
 * Returning accessTokenFormat:'jwt' here is what makes the access token a
 * verifiable JWT instead of an opaque handle — api.kicon.com verifies it locally
 * against /jwks with no introspection round-trip.
 *
 * jwt.sign.alg is pinned to ES256 because the keystore holds ES256 keys only
 * (src/oidc/keys/keystore.ts). Requesting RS256 would fail at issuance.
 */
export function getResourceServerInfo(_ctx: any, resourceIndicator: string, client: any) {
  if (resourceIndicator !== API_RESOURCE) {
    // Unknown resource. InvalidTarget is the RFC 8707 error for this.
    throw new errors.InvalidTarget();
  }
  return {
    scope: apiScopesFor(client?.clientId ?? ''),
    audience: API_RESOURCE,
    accessTokenFormat: 'jwt' as const,
    accessTokenTTL: 15 * 60,
    jwt: { sign: { alg: 'ES256' } },
  };
}
