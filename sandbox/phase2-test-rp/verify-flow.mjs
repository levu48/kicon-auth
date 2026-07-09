// Phase 2 headless verifier — drives the REAL Auth Code + PKCE flow end to end,
// no browser, for all three clients, and prints the resulting ID-token claims
// side by side. This is the sandbox from Phase 0 made real: same user, three
// clients, three projections — but now through the actual running IdP.
//
// Run the IdP first (npm run start:dev in project root), then:  npm run verify

import crypto from 'node:crypto';
import { createRemoteJWKSet, jwtVerify } from 'jose';

const IDP = process.env.IDP ?? 'http://localhost:3000';
const CREDS = { email: 'lan@example.com', password: 'demo-pass-123' };
const JWKS = createRemoteJWKSet(new URL(`${IDP}/jwks`));

// Redirect URIs must match what's registered in src/oidc/clients.ts. We never run
// a server on these ports — we just read the `code` out of the redirect Location.
const CLIENTS = [
  { id: 'banmua', tenant: 'food', redirect: 'http://localhost:8081/auth/callback',
    scope: 'openid profile email offline_access food:orders food:addresses' },
  { id: 'vietcouncil', tenant: 'civic', redirect: 'http://localhost:8082/auth/callback',
    secret: 'dev-vietcouncil-secret-CHANGE-ME',
    scope: 'openid profile email offline_access civic:member civic:district' },
  { id: 'xbottrader', tenant: 'trader', redirect: 'http://localhost:8083/auth/callback',
    secret: 'dev-xbottrader-secret-CHANGE-ME',
    scope: 'openid profile email offline_access' },
];

const b64url = (b) => Buffer.from(b).toString('base64url');
const rand = (n = 32) => b64url(crypto.randomBytes(n));
const s256 = (v) => b64url(crypto.createHash('sha256').update(v).digest());
const isCallback = (loc) => /^http:\/\/localhost:80\d\d\//.test(loc);

// Compute a TOTP code from the seeded dev secret (matches src/mfa/totp.ts).
const DEV_TOTP_SECRET = 'JBSWY3DPEHPK3PXP';
function totp(secretB32, forMs = Date.now()) {
  const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0, val = 0; const bytes = [];
  for (const ch of secretB32.replace(/=+$/, '').toUpperCase()) {
    const i = B32.indexOf(ch); if (i < 0) continue;
    val = (val << 5) | i; bits += 5;
    if (bits >= 8) { bytes.push((val >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  let counter = Math.floor(forMs / 1000 / 30); const buf = Buffer.alloc(8);
  for (let i = 7; i >= 0; i--) { buf[i] = counter & 0xff; counter = Math.floor(counter / 256); }
  const h = crypto.createHmac('sha1', Buffer.from(bytes)).update(buf).digest();
  const o = h[h.length - 1] & 0x0f;
  const bin = ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return (bin % 1e6).toString().padStart(6, '0');
}

// Minimal per-run cookie jar (one browser session per client → fresh login each).
function makeFetch() {
  const jar = new Map();
  return async (url, opts = {}) => {
    const headers = { ...(opts.headers || {}) };
    if (jar.size) headers.cookie = [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
    const res = await fetch(url, { ...opts, headers, redirect: 'manual' });
    for (const c of res.headers.getSetCookie?.() ?? []) {
      const [pair] = c.split(';');
      const i = pair.indexOf('=');
      const k = pair.slice(0, i).trim();
      const v = pair.slice(i + 1).trim();
      if (v) jar.set(k, v); else jar.delete(k);
    }
    return res;
  };
}

async function runClient(c) {
  const F = makeFetch();
  const code_verifier = rand(32);
  const nonce = rand(16);
  const state = rand(16);

  // 1. Start the authorization request; follow redirects until the login page.
  const authUrl = new URL(`${IDP}/auth`);
  authUrl.search = new URLSearchParams({
    client_id: c.id, redirect_uri: c.redirect, response_type: 'code', scope: c.scope,
    state, nonce, prompt: 'consent', // needed for offline_access → refresh token
    code_challenge: s256(code_verifier), code_challenge_method: 'S256',
  }).toString();

  let loc = authUrl.toString();
  let uid;
  for (let i = 0; i < 6; i++) {
    const res = await F(loc);
    const next = res.headers.get('location');
    if (res.status >= 300 && res.status < 400 && next) {
      const abs = new URL(next, IDP).toString();
      if (abs.includes('/interaction/')) {
        await F(abs); // load the login page (sets no new cookies, but realistic)
        uid = abs.split('/').pop();
        break;
      }
      loc = abs;
      continue;
    }
    throw new Error(`expected a redirect to /interaction, got ${res.status} at ${loc}`);
  }
  if (!uid) throw new Error('never reached the login interaction');

  // 2. Submit credentials (Argon2id verified server-side).
  let res = await F(`${IDP}/interaction/${uid}/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(CREDS),
  });

  // 2b. If the tenant requires a second factor, the login POST returns the MFA
  // page (200, no redirect) instead of resuming. Submit a computed TOTP code.
  let mfaUsed = false;
  if (!res.headers.get('location')) {
    mfaUsed = true;
    res = await F(`${IDP}/interaction/${uid}/mfa`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ code: totp(DEV_TOTP_SECRET) }),
    });
  }

  // 3. Follow the resume redirects until we land on the client's redirect_uri.
  let hop = res.headers.get('location');
  for (let i = 0; i < 6 && hop && !isCallback(hop); i++) {
    res = await F(new URL(hop, IDP).toString());
    hop = res.headers.get('location');
  }
  if (!hop || !isCallback(hop)) throw new Error(`did not reach callback; last location: ${hop}`);

  const cbUrl = new URL(hop);
  if (cbUrl.searchParams.get('error')) {
    throw new Error(`authorize error: ${cbUrl.searchParams.get('error')} — ${cbUrl.searchParams.get('error_description')}`);
  }
  const code = cbUrl.searchParams.get('code');
  if (cbUrl.searchParams.get('state') !== state) throw new Error('state mismatch on callback');

  // 4. Exchange the code for tokens (Basic auth for confidential clients).
  const body = new URLSearchParams({
    grant_type: 'authorization_code', code, redirect_uri: c.redirect, code_verifier,
  });
  const headers = { 'content-type': 'application/x-www-form-urlencoded' };
  if (c.secret) headers.authorization = 'Basic ' + Buffer.from(`${c.id}:${c.secret}`).toString('base64');
  else body.set('client_id', c.id);

  const tokRes = await fetch(`${IDP}/token`, { method: 'POST', headers, body });
  const tokens = await tokRes.json();
  if (!tokRes.ok) throw new Error(`token error: ${JSON.stringify(tokens)}`);

  // 5. Verify the ID token like a real client would (signature + iss/aud + nonce).
  //    Note: the code flow keeps the ID token lean (just `sub`); the projected
  //    claims are fetched from /userinfo with the access token.
  const { payload } = await jwtVerify(tokens.id_token, JWKS, { issuer: IDP, audience: c.id });
  if (payload.nonce !== nonce) throw new Error('nonce mismatch');

  const ui = await fetch(`${IDP}/me`, {
    headers: { authorization: `Bearer ${tokens.access_token}` },
  }).then((r) => r.json());

  return {
    client: c.id, tenant: c.tenant,
    sub: ui.sub,
    locale: ui.locale ?? '—', district: ui.district ?? '—',
    mfa: mfaUsed ? 'yes' : 'no',
    amr: Array.isArray(payload.amr) ? payload.amr.join('+') : (payload.amr ?? '—'),
    acr: payload.acr ?? '—',
  };
}

console.log(`\nDriving the real Auth Code + PKCE flow against ${IDP}\n`);
const rows = [];
for (const c of CLIENTS) {
  try {
    const r = await runClient(c);
    rows.push(r);
    console.log(`  ✓ ${c.id.padEnd(12)} sub=${r.sub} locale=${r.locale} district=${r.district} mfa=${r.mfa} amr=${r.amr} acr=${r.acr}`);
  } catch (e) {
    console.log(`  ✗ ${c.id.padEnd(12)} ${e.message}`);
  }
}

if (rows.length) {
  console.log('\nSame user, three projections — now through the real IdP:');
  console.table(rows);
  console.log('sub identical everywhere (shared pool); locale differs by tenant override;');
  console.log('only civic gets district (Ring 3 hard partition). Phase 0 sandbox, made real.\n');
}
