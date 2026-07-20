import type { ClientMetadata } from 'oidc-provider';
import { ACR_PWD, ACR_MFA } from '../mfa/acr';

/**
 * Registered clients, from CLAUDE.md. DEV values below (localhost redirects,
 * placeholder secrets). Prod is still TODO in CLAUDE.md: confirm redirect URIs,
 * finalise confidential-vs-public per client, and load secrets from a vault.
 *
 * oidc-provider enforces EXACT redirect-URI matching (no wildcards) — a core
 * CLAUDE.md security requirement, satisfied for free by listing full URIs here.
 *
 * NOTE (Phase 4, not the discovery milestone): the civic and trader clients must
 * additionally require MFA and forced re-auth, and must NOT be silently SSO'd by
 * a food session. That is enforced in the interaction/policy layer we build
 * later, not in this static registration.
 */
export const clients: ClientMetadata[] = [
  {
    client_id: 'banmua',
    client_name: 'Banmua — food (public SPA + PKCE)',
    token_endpoint_auth_method: 'none', // public client; PKCE is its only proof
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    redirect_uris: [
      'http://localhost:8081/auth/callback',
      'https://banmua.com/auth/callback', // TODO confirm
    ],
    scope: 'openid profile email offline_access food:orders food:addresses',
    id_token_signed_response_alg: 'ES256',
    // Requesting acr makes oidc-provider emit the actual assurance level (loa1
    // here) in the id_token so resource servers can see how the user authed.
    default_acr_values: [ACR_PWD],
  },
  {
    client_id: 'vietcouncil',
    client_name: 'Viet Council — civic (confidential)',
    client_secret: 'dev-vietcouncil-secret-CHANGE-ME',
    token_endpoint_auth_method: 'client_secret_basic',
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    redirect_uris: [
      'http://localhost:8082/auth/callback',
      'https://vietcouncil.org/auth/callback', // TODO confirm
    ],
    scope: 'openid profile email offline_access civic:member civic:district',
    id_token_signed_response_alg: 'ES256',
    // No silent SSO from other tenants: force fresh authentication every time
    // (which triggers MFA for enrolled users via the login interaction).
    default_max_age: 0,
    default_acr_values: [ACR_MFA],
  },
  {
    client_id: 'xbottrader',
    client_name: 'XBotTrader — trader (confidential, high assurance)',
    client_secret: 'dev-xbottrader-secret-CHANGE-ME',
    token_endpoint_auth_method: 'client_secret_basic',
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    redirect_uris: [
      'http://localhost:8083/auth/callback',
      'https://xbottrader.ai/auth/callback', // TODO confirm
    ],
    // Trading-specific scopes live at the xbottrader resource server, not the IdP.
    scope: 'openid profile email offline_access',
    id_token_signed_response_alg: 'ES256',
    // Brokerage-grade: forced re-auth on every authorization (no silent SSO from
    // a food/civic session), and MFA is mandatory (enforced in the login step).
    default_max_age: 0,
    default_acr_values: [ACR_MFA],
  },
  {
    // First app of the kicon app platform (see docs/app-platform-domains.md).
    // A microfrontend served from its OWN origin (vote.kicon.com) and embedded
    // into partner sites (e.g. vietcouncil.org) via an iframe. Because an embedded
    // cross-site app cannot silently reuse the auth cookie (third-party cookies),
    // it authenticates via a top-level/popup redirect — a normal public+PKCE
    // client. Standard assurance; app-specific authz (who may vote) lives at the
    // vote resource server (api.kicon.com), not in IdP scopes.
    client_id: 'vote',
    client_name: 'Kicon Vote — app platform (public SPA + PKCE, embeddable)',
    token_endpoint_auth_method: 'none', // public client; PKCE is its only proof
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    redirect_uris: [
      'http://localhost:8084/auth/callback',
      'https://vote.kicon.com/auth/callback', // TODO confirm
      'http://localhost:8084/auth/popup-callback',
      'https://vote.kicon.com/auth/popup-callback',
    ],
    // RP-initiated logout returns the user to the app's origin.
    // The embedded consumer widget cannot navigate its own iframe to the IdP
    // end-session page (auth denies framing), so it signs out via a top-level
    // popup that lands back on the popup-logout-callback path — the logout
    // counterpart to the /auth/popup-callback entries in redirect_uris above.
    post_logout_redirect_uris: [
      'http://localhost:8084/',
      'https://vote.kicon.com/',
      'http://localhost:8084/auth/popup-logout-callback',
      'https://vote.kicon.com/auth/popup-logout-callback',
    ],
    // NOTE: the vote:* resource-server scopes for api.kicon.com deliberately do
    // NOT appear here, and CANNOT. oidc-provider validates this string against
    // the provider-level `scopes` array at client load and rejects anything else
    // ("scope must only contain Authorization Server supported scope values").
    // Resource scopes are not provider scopes, by design.
    //
    // So which vote:* scopes this client may obtain is decided ENTIRELY by the
    // per-client map in resource-servers.ts. That file is the whole boundary —
    // there is no second line of defence here. Read it before changing anything.
    scope: 'openid profile email offline_access',
    id_token_signed_response_alg: 'ES256',
    default_acr_values: [ACR_PWD],
  },
  {
    // Admin surface of the vote app (see docs/app-platform-domains.md). Its OWN
    // origin (admin.vote.kicon.com), a SEPARATE client from the embeddable `vote`
    // consumer — the highest-privilege surface, never framed. Deliberately
    // stricter than `vote`: forced re-auth + MFA (like civic/trader, no silent
    // SSO from any session), and NO refresh token on the admin origin (no
    // offline_access / no popup) — a short privileged session, cheap re-auth.
    // Registering these redirect_uris also auto-enables the surface's CORS via
    // the clientBasedCORS hook in oidc.config.ts. WHO is an admin is app-tier
    // authz at the vote resource server; the IdP only enforces auth strength.
    client_id: 'vote-admin',
    client_name: 'Kicon Vote Admin — app platform (public SPA + PKCE, never framed)',
    token_endpoint_auth_method: 'none', // public client; PKCE is its only proof
    grant_types: ['authorization_code'], // no refresh_token on the admin origin
    response_types: ['code'],
    redirect_uris: [
      'http://localhost:8085/auth/callback',
      'https://admin.vote.kicon.com/auth/callback', // TODO confirm
    ],
    post_logout_redirect_uris: ['http://localhost:8085/', 'https://admin.vote.kicon.com/'],
    // As on the `vote` client: vote:admin cannot be listed here (oidc-provider
    // rejects non-provider scopes in client metadata). resource-servers.ts is
    // what grants it. And vote:admin alone never makes someone an admin —
    // api.kicon.com also requires an app_role_assignments row and acr=loa2.
    //
    // Consequence of having no offline_access: this client cannot refresh, so
    // the 15-minute access token IS the admin session. An admin re-authenticates
    // (with MFA, since default_max_age is 0) every 15 minutes. Deliberate.
    scope: 'openid profile email',
    id_token_signed_response_alg: 'ES256',
    // Brokerage-grade, like xbottrader: forced re-auth on every authorization (no
    // silent SSO from a consumer/food/civic session), MFA mandatory (enforced in
    // the login step). The admin SPA also sends prompt=login.
    default_max_age: 0,
    default_acr_values: [ACR_MFA],
  },
  {
    // Partner eligibility bridge — the ONLY client_credentials client, and the
    // only non-human one. No user, no redirect, no login.
    //
    // Why it exists: a VietCouncil poll must be restricted to VietCouncil
    // members, but civic membership must NOT leak into the apps tenant as a
    // claim (docs/app-platform-domains.md: gating is "authorization handled at
    // the vote resource server ... not civic identity claims leaking across the
    // partition"). So VietCouncil's own backend calls api.kicon.com and asserts
    // "this sub is a member of this org". The resource server stores that grant
    // keyed by sub and never learns WHY — it never sees civic_residency.
    //
    // Scope is deliberately a single narrow write. This client can add an
    // eligibility grant and do nothing else: it cannot read polls, cast a
    // ballot, or administer anything.
    client_id: 'vote-bridge',
    client_name: 'Kicon Vote — partner eligibility bridge (machine-to-machine)',
    client_secret: 'dev-vote-bridge-secret-CHANGE-ME',
    token_endpoint_auth_method: 'client_secret_basic',
    grant_types: ['client_credentials'],
    // No response_types / redirect_uris: client_credentials never runs a browser
    // flow. Listing them would be meaningless and would widen clientBasedCORS.
    response_types: [],
    redirect_uris: [],
    // `scope` is OMITTED, not empty. vote:eligibility:write is a resource-server
    // scope, and oidc-provider rejects those in client metadata ("scope must
    // only contain Authorization Server supported scope values") — but it also
    // rejects an empty string ("scope must be a non-empty string if provided").
    // Omitting the field is the only valid way to say "no IdP-level scopes".
    // resource-servers.ts grants the actual scope for the api.kicon.com resource.
    //
    // Required even though client_credentials never yields an id_token:
    // oidc-provider validates this metadata for every client, and the keystore
    // holds ES256 keys only, so the RS256 default is rejected.
    id_token_signed_response_alg: 'ES256',
  },
];
