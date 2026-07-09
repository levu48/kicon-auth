// Phase 0 learning sandbox — findAccount claim projection.
//
// NOT the real IdP. No NestJS, no node-oidc-provider, no Postgres, no Redis.
// Everything is in-memory. The point is to SEE the one idea that matters:
//
//   ONE stable user (sub) → THREE clients → THREE different ID tokens,
//   because claims are PROJECTED per-tenant at mint time in findAccount().
//
// It also mints REAL ES256-signed JWTs and verifies them against a JWKS,
// so you see the trust machinery (asymmetric signing + kid) for real.
//
// Run:  npm install && npm run demo
//
// Companion reading: ../../docs/phase-0-study-notes.md  (Part 4)

import { generateKeyPair, exportJWK, SignJWT, jwtVerify, createLocalJWKSet } from 'jose';

const ISSUER = 'https://auth.kicon.com';
const KID = 'kicon-es256-2026-07'; // in production this rotates; see study notes

// ─────────────────────────────────────────────────────────────────────────
// In-memory "database" — mirrors the three rings from CLAUDE.md / study notes
// ─────────────────────────────────────────────────────────────────────────

// Ring 1: shared core. Thin. Low-sensitivity. One row per human.
const users = {
  u_8f3c: {
    id: 'u_8f3c',
    primary_email: 'lan@example.com',
    name: 'Lan Nguyen',
    default_locale: 'vi-VN', // the global default (central kicon.com account page)
    default_zoneinfo: 'Asia/Ho_Chi_Minh',
  },
};

// Ring 2: sparse per-tenant overrides for TRUE-shared attributes.
// A row exists ONLY when a tenant overrode the global default.
const userTenantPrefs = [
  //{ user_id: 'u_8f3c', tenant_id: 'food', locale: 'vi-VN' }, // food explicitly set vi-VN
  { user_id: 'u_8f3c', tenant_id: 'trader', locale: 'en-US' }, // trader wants English
  // NOTE: no 'civic' row → civic falls through to the global default.
];

// Ring 3: hard-partitioned, never cross-read. Only the owning tenant touches these.
const civicResidency = {
  u_8f3c: { verified_address: '12 Lê Lợi, Q1', district_id: 'D3', verified_at: '2025-11-02' },
};
// (food_delivery_addresses / trader_profile also exist in reality, but they are
//  NOT identity claims — they live behind resource-server APIs. See study notes.)

// ─────────────────────────────────────────────────────────────────────────
// Config: which client belongs to which tenant, and what each client requests.
// Tenant is a property of WHO IS ASKING, never stored on the user.
// ─────────────────────────────────────────────────────────────────────────
const CLIENTS = {
  banmua: {
    tenant: 'food',
    scope: 'openid profile email offline_access food:orders food:addresses',
  },
  vietcouncil: {
    tenant: 'civic',
    scope: 'openid profile email offline_access civic:member civic:district',
  },
  xbottrader: {
    tenant: 'trader',
    scope: 'openid profile email offline_access',
  },
};

const tenantOf = (clientId) => CLIENTS[clientId]?.tenant;

// ─────────────────────────────────────────────────────────────────────────
// The Ring-2 cascade:  value = tenant_override ?? global_default ?? detected
// Returns { value, source } so the demo can show you WHERE each value came from.
// ─────────────────────────────────────────────────────────────────────────
function resolveShared(user, tenant, attr, ctx) {
  const row = userTenantPrefs.find((p) => p.user_id === user.id && p.tenant_id === tenant);
  if (row && row[attr] != null) return { value: row[attr], source: 'tenant-override' };

  const globalDefault = user[`default_${attr}`];
  if (globalDefault != null) return { value: globalDefault, source: 'global-default' };

  const detected = ctx.detected?.[attr];
  if (detected != null) return { value: detected, source: 'detected (not persisted)' };

  return { value: undefined, source: 'none' };
}

// ─────────────────────────────────────────────────────────────────────────
// projectClaims — the heart of it. Same user, different projection per tenant.
// `trace` is a teaching side-channel; a real impl would just return the claims.
// ─────────────────────────────────────────────────────────────────────────
async function projectClaims({ user, tenant, use, scope, ctx, trace }) {
  const scopes = scope.split(' ');
  const claims = { sub: user.id }; // always; opaque, stable, NEVER the email

  if (scopes.includes('email')) claims.email = user.primary_email;

  if (scopes.includes('profile')) {
    claims.name = user.name;
    const loc = resolveShared(user, tenant, 'locale', ctx);
    const tz = resolveShared(user, tenant, 'zoneinfo', ctx);
    claims.locale = loc.value;
    claims.zoneinfo = tz.value;
    trace.push(`locale   = ${loc.value}  (${loc.source})`);
    trace.push(`zoneinfo = ${tz.value}  (${tz.source})`);
  }

  // Ring 3 — ONLY the owning tenant, ONLY identity-grade derived facts.
  // This single guard is the entire hard partition.
  if (tenant === 'civic' && scopes.includes('civic:district')) {
    const res = civicResidency[user.id];
    if (res?.verified_at) {
      claims.district = res.district_id; // emit the DISTRICT, never the raw address
      trace.push(`district = ${res.district_id}  (Ring 3: civic table, verified ${res.verified_at})`);
    }
  }
  // food & trader emit NO Ring-3 identity claims — their app data travels via the
  // access token to a resource server, not baked into the ID token.

  return claims;
}

// ─────────────────────────────────────────────────────────────────────────
// findAccount — the seam. ctx tells us the client → the tenant.
// (Shape is illustrative; verify the real node-oidc-provider signature later.)
// ─────────────────────────────────────────────────────────────────────────
async function findAccount(ctx, sub) {
  const tenant = tenantOf(ctx.clientId);
  const user = users[sub];
  if (!user) return undefined;

  return {
    accountId: sub,
    async claims(use, scope, trace) {
      return projectClaims({ user, tenant, use, scope, ctx, trace });
    },
  };
}

// ─────────────────────────────────────────────────────────────────────────
// Trust machinery: one ES256 signing key + its public JWKS (what /jwks.json serves)
// ─────────────────────────────────────────────────────────────────────────
const { publicKey, privateKey } = await generateKeyPair('ES256', { extractable: true });
const publicJwk = { ...(await exportJWK(publicKey)), kid: KID, alg: 'ES256', use: 'sig' };
const jwks = createLocalJWKSet({ keys: [publicJwk] }); // stand-in for GET /jwks.json

async function mintIdToken(claims, audience, nonce) {
  const { sub, ...rest } = claims;
  return new SignJWT({ ...rest, nonce })
    .setProtectedHeader({ alg: 'ES256', kid: KID, typ: 'JWT' })
    .setSubject(sub)
    .setIssuer(ISSUER)
    .setAudience(audience)
    .setIssuedAt()
    .setExpirationTime('15m')
    .sign(privateKey);
}

// ─────────────────────────────────────────────────────────────────────────
// Drive it: same user, three clients.
// ─────────────────────────────────────────────────────────────────────────
const SUB = 'u_8f3c';
const rows = []; // for the comparison table at the end

for (const clientId of Object.keys(CLIENTS)) {
  const { scope } = CLIENTS[clientId];
  // ctx carries who's asking + a simulated Accept-Language for the detection fallback.
  const ctx = { clientId, detected: { locale: 'en-US', zoneinfo: 'UTC' } };

  const account = await findAccount(ctx, SUB);
  const trace = [];
  const claims = await account.claims('id_token', scope, trace);

  const token = await mintIdToken(claims, clientId, 'nonce-' + clientId);
  const { payload, protectedHeader } = await jwtVerify(token, jwks, {
    issuer: ISSUER,
    audience: clientId,
  }); // verifies signature via JWKS + checks iss/aud — the client's job in step 6

  console.log('\n' + '═'.repeat(72));
  console.log(`CLIENT: ${clientId}   →   TENANT: ${tenantOf(clientId)}`);
  console.log('═'.repeat(72));
  console.log('cascade resolution:');
  trace.forEach((t) => console.log('   ' + t));
  console.log('\nsigned ID token (real ES256 JWT — three dot-separated parts):');
  console.log('   ' + token.slice(0, 78) + '…');
  console.log('\nverified header:', JSON.stringify(protectedHeader));
  console.log('verified claims:');
  console.log(
    JSON.stringify(payload, null, 2)
      .split('\n')
      .map((l) => '   ' + l)
      .join('\n'),
  );

  rows.push({
    client: clientId,
    tenant: tenantOf(clientId),
    sub: payload.sub,
    email: payload.email ?? '—',
    locale: payload.locale ?? '—',
    district: payload.district ?? '—',
  });
}

console.log('\n' + '═'.repeat(72));
console.log('SAME sub, THREE projections  (this is the whole lesson)');
console.log('═'.repeat(72));
console.table(rows);
console.log(
  '\nNotice: sub is identical everywhere (shared pool). locale differs by\n' +
    'tenant override vs global default (Ring 2 cascade). Only civic gets\n' +
    "district (Ring 3 hard partition). Nobody gets another tenant's data.\n",
);
