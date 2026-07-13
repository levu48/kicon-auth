import type { Configuration } from 'oidc-provider';
import { clients } from './clients';
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
    scopes: ['openid', 'offline_access', 'food:orders', 'food:addresses', 'civic:member'],

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
      grant.addOIDCScope(ctx.oidc.params.scope);
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
      // TODO Phase 4: backchannelLogout, resourceIndicators, dPoP.
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
