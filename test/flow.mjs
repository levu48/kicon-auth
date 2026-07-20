/**
 * Shared helpers for the integration probes in this directory.
 *
 * These are deliberately dependency-free plain Node (no test framework, no
 * fixtures) — matching this repo's gate, which is "does a real instance boot and
 * answer correctly" rather than a unit-test suite. They drive the ACTUAL browser
 * flow: /auth -> login form -> optional MFA form -> callback -> /token.
 *
 * Anything that can only be caught by running the real thing belongs here.
 */
import { createHash, createHmac, randomBytes } from 'node:crypto';

export const BASE = process.env.BASE ?? 'http://localhost:3000';
export const API_RESOURCE = 'https://api.kicon.com';

/** The dev seed account (src/database/dev-seeder.ts) — MFA-enrolled. */
export const ENROLLED_USER = { email: 'lan@example.com', password: 'demo-pass-123' };
/** Created by CI via `user:create`; never MFA-enrolled. */
export const UNENROLLED_USER = { email: 'nomfa@example.com', password: 'demo-pass-123' };
const DEV_TOTP_SECRET = 'JBSWY3DPEHPK3PXP';

export const CLIENTS = {
  banmua: { redirectUri: 'http://localhost:8081/auth/callback' },
  vietcouncil: {
    redirectUri: 'http://localhost:8082/auth/callback',
    secret: 'dev-vietcouncil-secret-CHANGE-ME',
  },
  xbottrader: {
    redirectUri: 'http://localhost:8083/auth/callback',
    secret: 'dev-xbottrader-secret-CHANGE-ME',
  },
  vote: { redirectUri: 'http://localhost:8084/auth/callback' },
  'vote-admin': { redirectUri: 'http://localhost:8085/auth/callback' },
};

const b64url = (b) => Buffer.from(b).toString('base64url');

// ---- TOTP (RFC 6238: HMAC-SHA1, 6 digits, 30s) ----------------------------
function base32Decode(s) {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const c of s.replace(/=+$/, '').toUpperCase()) {
    const i = A.indexOf(c);
    if (i >= 0) bits += i.toString(2).padStart(5, '0');
  }
  const out = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(out);
}
export function totp(secret = DEV_TOTP_SECRET) {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 1000 / 30)));
  const h = createHmac('sha1', base32Decode(secret)).update(buf).digest();
  const off = h[h.length - 1] & 0xf;
  return ((h.readUInt32BE(off) & 0x7fffffff) % 1_000_000).toString().padStart(6, '0');
}

// ---- cookie jar -----------------------------------------------------------
class Jar {
  constructor() {
    this.c = new Map();
  }
  absorb(res) {
    for (const sc of res.headers.getSetCookie?.() ?? []) {
      const [pair] = sc.split(';');
      const i = pair.indexOf('=');
      const k = pair.slice(0, i).trim();
      const v = pair.slice(i + 1).trim();
      if (v === '') this.c.delete(k);
      else this.c.set(k, v);
    }
  }
  header() {
    return [...this.c].map(([k, v]) => `${k}=${v}`).join('; ');
  }
}

async function hop(url, jar, init = {}) {
  const res = await fetch(url, {
    ...init,
    redirect: 'manual',
    headers: { ...(init.headers ?? {}), cookie: jar.header() },
  });
  jar.absorb(res);
  return res;
}

/**
 * Drive the full browser flow.
 *
 * Returns one of:
 *   { outcome: 'code',    code, verifier, mfaPrompted }
 *   { outcome: 'refused', mfaPrompted }   -- 403: mandatory MFA, not enrolled
 *   { outcome: 'error'|'stuck', detail }
 */
export async function authorize({ clientId, scope, user, resource, extra = {} }) {
  const { redirectUri } = CLIENTS[clientId];
  const jar = new Jar();
  const verifier = randomBytes(32).toString('base64url');
  const q = new URLSearchParams({
    client_id: clientId,
    response_type: 'code',
    redirect_uri: redirectUri,
    scope,
    code_challenge: b64url(createHash('sha256').update(verifier).digest()),
    code_challenge_method: 'S256',
    state: randomBytes(6).toString('hex'),
    nonce: randomBytes(6).toString('hex'),
    ...(resource ? { resource } : {}),
    ...extra,
  });

  let url = `${BASE}/auth?${q}`;
  let mfaPrompted = false;

  for (let i = 0; i < 25; i++) {
    const res = await hop(url, jar);

    if (res.status >= 300 && res.status < 400) {
      const loc = res.headers.get('location');
      if (loc.startsWith(redirectUri)) {
        const u = new URL(loc);
        const err = u.searchParams.get('error');
        if (err) return { outcome: 'error', mfaPrompted, detail: `${err}: ${u.searchParams.get('error_description')}` };
        return { outcome: 'code', code: u.searchParams.get('code'), verifier, mfaPrompted };
      }
      url = new URL(loc, BASE).toString();
      continue;
    }

    let body = await res.text();
    const uid = url.match(/\/interaction\/([^/?#]+)/)?.[1];
    if (!uid) return { outcome: 'stuck', mfaPrompted, detail: `HTTP ${res.status} at ${url}` };

    // Submit whatever form is on screen, repeatedly: a step can answer 200 with
    // the NEXT form rather than a redirect (password -> MFA).
    for (let step = 0; step < 4; step++) {
      const isMfa = /\/mfa\b/.test(body) || /second factor|authenticator|two-factor/i.test(body);
      if (isMfa) mfaPrompted = true;
      const target = `${BASE}/interaction/${uid}/${isMfa ? 'mfa' : 'login'}`;
      const form = isMfa
        ? new URLSearchParams({ code: totp() })
        : new URLSearchParams({ email: user.email, password: user.password });

      const post = await hop(target, jar, {
        method: 'POST',
        body: form,
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
      });

      if (post.status === 403) return { outcome: 'refused', mfaPrompted };
      if (post.status >= 300 && post.status < 400) {
        url = new URL(post.headers.get('location'), BASE).toString();
        break;
      }
      if (post.status !== 200) return { outcome: 'error', mfaPrompted, detail: `HTTP ${post.status}` };
      body = await post.text();
    }
  }
  return { outcome: 'stuck', mfaPrompted, detail: 'too many redirects' };
}

/** Exchange an authorization code for tokens. */
export async function exchange({ clientId, code, verifier, resource }) {
  const { redirectUri, secret } = CLIENTS[clientId];
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: redirectUri,
    code_verifier: verifier,
    ...(resource ? { resource } : {}),
  });
  const headers = { 'content-type': 'application/x-www-form-urlencoded' };
  if (secret) headers.authorization = 'Basic ' + Buffer.from(`${clientId}:${secret}`).toString('base64');
  else body.set('client_id', clientId);

  const res = await fetch(`${BASE}/token`, { method: 'POST', body, headers });
  const json = await res.json();
  if (!res.ok) throw new Error(`token endpoint ${res.status}: ${JSON.stringify(json)}`);
  return json;
}

/** Decode a JWT without verifying (the probes assert on claims, not signatures). */
export function decodeJwt(t) {
  const parts = (t ?? '').split('.');
  if (parts.length !== 3) return { opaque: true, segments: parts.length };
  return {
    opaque: false,
    header: JSON.parse(Buffer.from(parts[0], 'base64url')),
    payload: JSON.parse(Buffer.from(parts[1], 'base64url')),
  };
}

/** One-shot: full flow, returns { tokens, at, idt }. */
export async function login({ clientId, scope, user = ENROLLED_USER, resource, extra }) {
  const r = await authorize({ clientId, scope, user, resource, extra });
  if (r.outcome !== 'code') return { ...r, tokens: null };
  const tokens = await exchange({ clientId, code: r.code, verifier: r.verifier, resource });
  return {
    ...r,
    tokens,
    at: decodeJwt(tokens.access_token),
    idt: decodeJwt(tokens.id_token),
  };
}

// ---- tiny assertion harness ----------------------------------------------
let failures = 0;
export function check(name, cond, detail = '') {
  if (cond) console.log(`  PASS  ${name}`);
  else {
    console.log(`  FAIL  ${name}${detail ? ` — ${detail}` : ''}`);
    failures++;
  }
}
export function done(label) {
  if (failures) {
    console.log(`\n${label}: ${failures} check(s) FAILED\n`);
    process.exit(1);
  }
  console.log(`\n${label}: all checks passed\n`);
  process.exit(0);
}
