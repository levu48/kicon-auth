import type { Configuration } from 'oidc-provider';
import { clients } from './clients';
import { API_RESOURCE, apiScopesFor, getResourceServerInfo } from './resource-servers';
import { ACR_PWD, ACR_MFA } from '../mfa/acr';

/**
 * oidc-provider configuration. Field names/shape are version-sensitive — verify
 * against your INSTALLED version's docs (CLAUDE.md standing rule). The cast at the
 * end keeps custom scope/claim keys from fighting the @types.
 *
 * `adapter` and `findAccount` are injected by OidcService: the adapter is the
 * Redis-backed store (Phase 3); findAccount is a closure over the Postgres-backed
 * accounts + identity services.
 */
/**
 * Scopes the IdP itself understands — resource scopes it owns (`food:*`,
 * `civic:member`) plus the claim-bearing ones. Resource-SERVER scopes
 * (`vote:*`) are deliberately absent: they belong to api.kicon.com's
 * vocabulary, not the IdP's (CLAUDE.md: "keep IdP scopes minimal").
 *
 * Exported so loadExistingGrant can tell the two kinds apart. Do not filter by
 * looking for a ':' in the scope name — `food:orders` is an IdP scope and
 * `vote:read` is not, and that distinction is not visible in the syntax.
 */
const IDP_SCOPES = [
  'openid',
  'offline_access',
  'food:orders',
  'food:addresses',
  'civic:member',
] as const;

/** Claim-bearing scopes (keys of the `claims` map below). Also IdP-side. */
const IDP_CLAIM_SCOPES = ['openid', 'profile', 'email', 'civic:district'] as const;

const IDP_SCOPE_SET = new Set<string>([...IDP_SCOPES, ...IDP_CLAIM_SCOPES]);

export function buildConfiguration(opts: {
  jwks: any;
  cookieKeys: string[];
  adapter: any;
  findAccount: any;
  interactionsPolicy?: any;
}): Configuration {
  const config = {
    clients,
    adapter: opts.adapter,
    jwks: opts.jwks,
    findAccount: opts.findAccount,

    cookies: {
      keys: opts.cookieKeys,
      // long/short cookie flags default to HttpOnly + SameSite=lax; `secure` is
      // auto-true once the issuer is https (i.e. in prod behind nginx).
    },

    // Browser (SPA) clients call the token/userinfo endpoints cross-origin from
    // their own site (e.g. vote.kicon.com -> auth.kicon.com/token). Allow CORS
    // ONLY from an origin that matches one of the requesting client's registered
    // redirect_uris — never a wildcard. Confidential/server clients don't hit CORS.
    clientBasedCORS(_ctx: any, origin: string, client: any) {
      if (!client || !origin) return false;
      return (client.redirectUris ?? []).some((u: string) => {
        try {
          return new URL(u).origin === origin;
        } catch {
          return false;
        }
      });
    },

    // scope -> claims mapping. Claim-bearing scopes go here; resource-only scopes
    // (no claims) are declared in `scopes` below.
    claims: {
      openid: ['sub'],
      profile: ['name', 'locale', 'zoneinfo'],
      email: ['email'],
      'civic:district': ['district'], // custom claim, civic tenant only
    },

    // Authentication-strength levels the IdP supports (loa1 = pwd, loa2 = MFA).
    // Clients reference these via default_acr_values; the actual level reached is
    // emitted as the id_token `acr` claim.
    acrValues: [ACR_PWD, ACR_MFA],

    // Supported scopes. `offline_access` MUST be listed to enable the
    // refresh_token grant (without it, oidc-provider drops refresh_token from
    // grant_types_supported and rejects clients that declare it). `openid` is
    // listed for completeness; the rest are resource scopes with no own claims.
    scopes: [...IDP_SCOPES],

    // Code flow ONLY. oidc-provider advertises implicit/hybrid by default;
    // CLAUDE.md disallows Implicit (and we don't want hybrid either). Restricting
    // responseTypes here drops them from discovery and disables them provider-wide.
    responseTypes: ['code'],

    // Where to send the user-agent when an interaction (login) is required.
    // Our Express router handles this path; see src/interactions/interactions.router.ts.
    interactions: {
      url(_ctx: any, interaction: any) {
        return `/interaction/${interaction.uid}`;
      },
      ...(opts.interactionsPolicy ? { policy: opts.interactionsPolicy } : {}),
    },

    // First-party / trusted clients skip the consent screen (CLAUDE.md). Instead of
    // rendering consent, we auto-create a Grant covering exactly what was requested.
    // This is the correct oidc-provider mechanism for "no consent for trusted RPs".
    // (If we ever onboard third-party developers, replace this with a real consent UI.)
    async loadExistingGrant(ctx: any) {
      const provider = ctx.oidc.provider;
      const clientId = ctx.oidc.client.clientId;

      // Reuse a grant already tied to this session/client, if one exists.
      const priorGrantId =
        ctx.oidc.result?.consent?.grantId ?? ctx.oidc.session.grantIdFor(clientId);
      if (priorGrantId) return provider.Grant.find(priorGrantId);

      // Otherwise mint one granting everything this trusted client asked for.
      const grant = new provider.Grant({ accountId: ctx.oidc.session.accountId, clientId });

      // Split the request into IdP scopes and resource-server scopes. These go
      // into DIFFERENT buckets on the Grant and are NOT interchangeable:
      //   addOIDCScope   -> what /me and the id_token may carry
      //   addResourceScope -> what an access token FOR THAT RESOURCE may carry
      // Token issuance reads grant.getResourceScopeFiltered(resource, ...), which
      // consults only the resource bucket. Granting OIDC scopes alone (as this
      // did before) mints access tokens with an EMPTY `scope` — every check at
      // api.kicon.com then fails. See docs/app-platform-domains.md.
      const requested: string[] = (ctx.oidc.params.scope ?? '').split(' ').filter(Boolean);
      const allowedApi = new Set(apiScopesFor(clientId).split(' ').filter(Boolean));

      // Intersect with the per-client allow-list — never grant what this client
      // may not have, even if it asked. resource-servers.ts explains why this is
      // the real boundary rather than defence in depth.
      const apiScopes = requested.filter((s) => allowedApi.has(s));
      const oidcScopes = requested.filter((s) => IDP_SCOPE_SET.has(s));

      grant.addOIDCScope(oidcScopes.join(' '));
      if (apiScopes.length) grant.addResourceScope(API_RESOURCE, apiScopes.join(' '));

      await grant.save();
      return grant;
    },

    // PKCE always (CLAUDE.md). S256 only; `plain` stays disabled.
    pkce: { required: () => true },

    // Refresh-token rotation; reuse of a rotated token revokes the family
    // (reuse detection) — a CLAUDE.md non-negotiable, built into oidc-provider.
    rotateRefreshToken: true,

    features: {
      // Disabled: we now serve our OWN login page + interaction handlers
      // (Phase 2). The built-in dev stub must be off or it hijacks /interaction.
      devInteractions: { enabled: false },
      revocation: { enabled: true },
      introspection: { enabled: true },
      rpInitiatedLogout: { enabled: true },

      // Service-to-service only (CLAUDE.md permits Client Credentials for
      // exactly that). Required for the `vote-bridge` partner client; without
      // it oidc-provider rejects the registration outright with
      // "grant_types can only contain 'authorization_code' or 'refresh_token'".
      // No human, no session — the resulting token's `sub` is the client_id.
      clientCredentials: { enabled: true },

      // RFC 8707 resource indicators — how api.kicon.com gets a JWT access token
      // with a real `aud` instead of an opaque handle.
      //
      // NOTE: this feature is ON BY DEFAULT in oidc-provider 8.x, and its default
      // getResourceServerInfo throws InvalidTarget. So before this block existed,
      // any client sending `resource=` already failed — we are supplying the
      // missing helper, not turning something on. (The old "TODO Phase 4:
      // resourceIndicators" comment here was wrong about that.)
      resourceIndicators: {
        enabled: true,
        getResourceServerInfo,

        // Let a refresh_token exchange keep the resource it was granted without
        // re-sending `resource=`. Without this, a silent renew in the SPA returns
        // a userinfo-audience OPAQUE token and the app breaks ~15 minutes after
        // login — a genuinely nasty failure to debug, since the initial login works.
        useGrantedResource: () => true,
      },

      // TODO Phase 4: backchannelLogout, dPoP.
    },

    /**
     * Extra claims on JWT access tokens.
     *
     * oidc-provider builds an access-token JWT from a fixed claim set (jti, sub,
     * iat, exp, scope, client_id, iss, aud, cnf) plus whatever this returns.
     * `acr` and `auth_time` are NOT in that set — they live on the
     * AuthorizationCode/RefreshToken, not the AccessToken. api.kicon.com needs
     * them to enforce step-up on admin routes (acr=loa2), so we copy them across.
     *
     * `gty` lets the resource server distinguish a human's token from a
     * client_credentials one without inferring it from sub === client_id.
     */
    async extraTokenClaims(ctx: any, token: any) {
      if (token?.kind !== 'AccessToken') return undefined;
      const src = ctx?.oidc?.entities?.AuthorizationCode ?? ctx?.oidc?.entities?.RefreshToken;
      return {
        acr: src?.acr ?? undefined,
        auth_time: src?.authTime ?? undefined,
        gty: token?.gty ?? undefined,
      };
    },

    // Short-lived access/id tokens; long refresh; very short auth codes.
    ttl: {
      AccessToken: 15 * 60,
      AuthorizationCode: 60,
      IdToken: 15 * 60,
      RefreshToken: 14 * 24 * 60 * 60,
      Session: 14 * 24 * 60 * 60,
      Grant: 14 * 24 * 60 * 60,
      Interaction: 60 * 60,
    },
  };

  return config as unknown as Configuration;
}
