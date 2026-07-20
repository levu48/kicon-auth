/**
 * MFA policy matrix — every client × (enrolled, un-enrolled).
 *
 * Run against a booted IdP:  BASE=http://localhost:3000 node test/mfa-matrix.mjs
 * Requires the un-enrolled account to exist:
 *   USER_PASSWORD=demo-pass-123 npm run user:create -- \
 *     --email nomfa@example.com --name 'No MFA User'
 *
 * The load-bearing row is `vietcouncil` + un-enrolled: it must still LOG IN at
 * loa1, not be refused. `vietcouncil` declares default_acr_values:[ACR_MFA] just
 * like `vote-admin` does, so any implementation that treats that declaration as
 * "mandatory" passes every other row here and silently locks every un-enrolled
 * civic user out of their account. See the MFA policy table in CLAUDE.md.
 */
import { authorize, exchange, decodeJwt, check, done, ENROLLED_USER, UNENROLLED_USER } from './flow.mjs';

const SCOPE = 'openid profile email';

// client, user, expectation, and what breaks if it regresses
const CASES = [
  ['banmua', 'enrolled', { mfa: false, acr: 'urn:kicon:loa1' }, 'food: no MFA policy'],
  ['vote', 'enrolled', { mfa: false, acr: 'urn:kicon:loa1' }, 'consumer widget: standard assurance'],
  ['vote-admin', 'enrolled', { mfa: true, acr: 'urn:kicon:loa2' }, 'admin origin: mandatory MFA'],
  ['vote-admin', 'unenrolled', { refused: true }, 'admin origin: refuse, never downgrade to loa1'],
  ['vietcouncil', 'enrolled', { mfa: true, acr: 'urn:kicon:loa2' }, 'civic: required once enrolled'],
  ['vietcouncil', 'unenrolled', { mfa: false, acr: 'urn:kicon:loa1' }, 'civic: ENCOURAGED — must still log in'],
  ['xbottrader', 'enrolled', { mfa: true, acr: 'urn:kicon:loa2' }, 'trader: mandatory'],
  ['xbottrader', 'unenrolled', { refused: true }, 'trader: refuse'],
];

console.log('\nMFA policy matrix\n');
console.log('client        user          prompted  acr                   expected');
console.log('─'.repeat(78));

for (const [clientId, who, expect, why] of CASES) {
  const user = who === 'enrolled' ? ENROLLED_USER : UNENROLLED_USER;
  const r = await authorize({ clientId, scope: SCOPE, user });

  let acr = null;
  if (r.outcome === 'code') {
    const tokens = await exchange({ clientId, code: r.code, verifier: r.verifier });
    acr = decodeJwt(tokens.id_token).payload?.acr ?? null;
  }

  const want = expect.refused ? 'refused' : `${expect.acr} ${expect.mfa ? '(mfa)' : ''}`;
  console.log(
    `${clientId.padEnd(13)} ${who.padEnd(13)} ${String(r.mfaPrompted).padEnd(9)} ${String(acr).padEnd(21)} ${want}`,
  );

  if (expect.refused) {
    check(`${clientId}/${who} refused — ${why}`, r.outcome === 'refused', `got outcome=${r.outcome} ${r.detail ?? ''}`);
  } else {
    check(
      `${clientId}/${who} → ${expect.acr}${expect.mfa ? ' with MFA' : ' without MFA'} — ${why}`,
      r.outcome === 'code' && r.mfaPrompted === expect.mfa && acr === expect.acr,
      `got outcome=${r.outcome} prompted=${r.mfaPrompted} acr=${acr}`,
    );
  }
}

done('mfa-matrix');
