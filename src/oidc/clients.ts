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
];
