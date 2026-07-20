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
import { login, check, done, API_RESOURCE, ENROLLED_USER } from './flow.mjs';

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

done('token-contract');
