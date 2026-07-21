/**
 * The api.kicon.com token contract.
 *
 * Run against a booted IdP:  BASE=http://localhost:3000 node test/token-contract.mjs
 *
 * WHY THIS EXISTS — the assertion in [2] is the important one. Resource-server
 * scopes (vote:*) are not provider-level scopes, so oidc-provider does NOT
 * validate them against client metadata at /authorize (check_scope.js only does
 * that for scopes in the provider `scopes` array). In fact they CANNOT be listed
 * in client metadata — oidc-provider rejects the registration outright with
 * "scope must only contain Authorization Server supported scope values".
 *
 * That means the per-client map in src/oidc/resource-servers.ts is the ONLY
 * thing preventing the embeddable consumer widget (`vote`, framed into partner
 * sites) from minting an admin-scoped token. There is no second line of defence.
 * If someone "simplifies" getResourceServerInfo to return a fixed scope string,
 * this test is what catches it.
 */
import {
  login,
  refresh,
  clientCredentials,
  decodeJwt,
  check,
  done,
  API_RESOURCE,
  ENROLLED_USER,
} from './flow.mjs';

console.log('\n[1] vote — JWT access token shape');
const r1 = await login({
  clientId: 'vote',
  scope: 'openid profile email offline_access vote:read vote:write',
  resource: API_RESOURCE,
  extra: { prompt: 'consent' }, // required for offline_access
});
if (r1.outcome !== 'code') throw new Error(`flow failed: ${r1.outcome} ${r1.detail ?? ''}`);
console.log(JSON.stringify(r1.at, null, 2));

check('access token is a JWT, not opaque', !r1.at.opaque, `${r1.at.segments} segments`);
check('typ is at+jwt (RFC 9068)', r1.at.header?.typ === 'at+jwt', `got ${r1.at.header?.typ}`);
check('signed ES256', r1.at.header?.alg === 'ES256', `got ${r1.at.header?.alg}`);
check('kid present for rotation', !!r1.at.header?.kid);
check('aud is the API resource', r1.at.payload?.aud === API_RESOURCE, `got ${JSON.stringify(r1.at.payload?.aud)}`);
check(
  'scope is NON-EMPTY (loadExistingGrant must addResourceScope)',
  !!r1.at.payload?.scope,
  `got ${JSON.stringify(r1.at.payload?.scope)}`,
);
check(
  'scope carries vote:read and vote:write',
  /\bvote:read\b/.test(r1.at.payload?.scope ?? '') && /\bvote:write\b/.test(r1.at.payload?.scope ?? ''),
  `got ${r1.at.payload?.scope}`,
);
check('acr present (extraTokenClaims)', !!r1.at.payload?.acr, `got ${r1.at.payload?.acr}`);
check('auth_time present', !!r1.at.payload?.auth_time);
check('gty present', !!r1.at.payload?.gty);
check('sub is the opaque user id', !!r1.at.payload?.sub && r1.at.payload.sub !== ENROLLED_USER.email);
check('client_id is vote', r1.at.payload?.client_id === 'vote');

console.log('\n[2] PRIVILEGE ESCALATION — vote must NOT obtain vote:admin');
const r2 = await login({
  clientId: 'vote',
  scope: 'openid profile email vote:read vote:write vote:admin',
  resource: API_RESOURCE,
});
if (r2.outcome !== 'code') throw new Error(`flow failed: ${r2.outcome} ${r2.detail ?? ''}`);
console.log(`  issued scope: ${JSON.stringify(r2.at.payload?.scope)}`);
check(
  'vote:admin NOT granted to the consumer client',
  !/\bvote:admin\b/.test(r2.at.payload?.scope ?? ''),
  `LEAKED — issued: ${r2.at.payload?.scope}`,
);

console.log('\n[3] vote-admin — must obtain vote:admin at loa2');
const r3 = await login({
  clientId: 'vote-admin',
  scope: 'openid profile email vote:read vote:write vote:admin',
  resource: API_RESOURCE,
});
if (r3.outcome !== 'code') throw new Error(`flow failed: ${r3.outcome} ${r3.detail ?? ''}`);
console.log(`  issued scope: ${JSON.stringify(r3.at.payload?.scope)}  acr: ${r3.at.payload?.acr}`);
check('vote:admin granted to the admin client', /\bvote:admin\b/.test(r3.at.payload?.scope ?? ''));
check('admin token is loa2 (MFA enforced)', r3.at.payload?.acr === 'urn:kicon:loa2', `got ${r3.at.payload?.acr}`);
check('admin login actually prompted for a second factor', r3.mfaPrompted === true);

console.log('\n[4] unknown resource must be rejected');
const r4 = await login({
  clientId: 'vote',
  scope: 'openid profile email vote:read',
  resource: 'https://evil.example.com',
});
check(
  'invalid_target for an unregistered resource',
  r4.outcome === 'error' && /invalid_target/.test(r4.detail ?? ''),
  `got ${r4.outcome} ${r4.detail ?? ''}`,
);

console.log('\n[5] silent renew must NOT downgrade to an opaque token');
// The browser's automaticSilentRenew sends NO `resource` (oidc-client-ts's
// signinSilent only forwards a resource passed as an argument, and the renew
// timer calls it with none). If the IdP does not resolve the granted resource
// for such a request, login works and then ~15 minutes later every API call
// starts failing with an opaque token — a genuinely horrible bug to trace.
// This asserts resourceIndicators.useGrantedResource covers it.
const refreshed = await refresh({
  clientId: 'vote',
  refreshToken: r1.tokens.refresh_token,
  // deliberately no `resource` — mirroring the real renewal request
});
const rat = decodeJwt(refreshed.access_token);
console.log(`  renewed aud: ${JSON.stringify(rat.payload?.aud)}  scope: ${JSON.stringify(rat.payload?.scope)}`);
check('refresh returned a refresh_token (rotation)', !!refreshed.refresh_token);
check('renewed access token is still a JWT', !rat.opaque, `${rat.segments} segments — DOWNGRADED to opaque`);
check('renewed token keeps aud=api.kicon.com', rat.payload?.aud === API_RESOURCE, `got ${JSON.stringify(rat.payload?.aud)}`);
check(
  'renewed token keeps its resource scopes',
  /\bvote:read\b/.test(rat.payload?.scope ?? '') && /\bvote:write\b/.test(rat.payload?.scope ?? ''),
  `got ${JSON.stringify(rat.payload?.scope)}`,
);
check('renewed token still has no vote:admin', !/\bvote:admin\b/.test(rat.payload?.scope ?? ''));

console.log('\n[6] vote-bridge — client_credentials for the partner eligibility bridge');
// This client registration failed FOUR different ways before it worked, none of
// which surface until something actually requests a token:
//   scope:'' rejected ("must be a non-empty string if provided") -> omit it
//   grant_types rejected -> features.clientCredentials must be enabled
//   id_token_signed_response_alg defaulted to RS256 -> rejected, keystore is ES256
//   (and resource scopes cannot go in client metadata at all)
// Registration errors are silent until exercised, hence this probe.
const cc = await clientCredentials({
  clientId: 'vote-bridge',
  scope: 'vote:eligibility:write',
  resource: API_RESOURCE,
});
check('client_credentials succeeded', !!cc.access_token, `got ${cc.error}: ${cc.error_description}`);

const ccat = decodeJwt(cc.access_token);
console.log(`  sub: ${ccat.payload?.sub}  scope: ${JSON.stringify(ccat.payload?.scope)}`);
check('machine token is a JWT', !ccat.opaque);
check('aud is the API resource', ccat.payload?.aud === API_RESOURCE, `got ${JSON.stringify(ccat.payload?.aud)}`);
check(
  'scope is exactly vote:eligibility:write',
  ccat.payload?.scope === 'vote:eligibility:write',
  `got ${JSON.stringify(ccat.payload?.scope)}`,
);
// No account exists, so oidc-provider sets sub = client_id. This is how the
// resource server tells a machine token from a human one — `gty` is NOT emitted
// on client_credentials tokens, so it cannot be relied on for that.
check('sub equals client_id (machine token marker)', ccat.payload?.sub === 'vote-bridge', `got ${ccat.payload?.sub}`);
check('bridge cannot read or write votes', !/\bvote:(read|write|admin)\b/.test(ccat.payload?.scope ?? ''));

done('token-contract');
