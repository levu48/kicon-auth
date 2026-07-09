// Phase 2 test relying party — stands in for banmua.com.
//
// A minimal, hand-rolled OAuth client so you can WATCH the real flow:
//   browser -> RP /login -> IdP /authorize -> IdP login page -> back to RP
//   -> RP swaps the code for tokens -> shows decoded ID token + /userinfo.
//
// Hand-rolled on purpose (no openid-client lib) so every step of the flow from
// docs/phase-0-study-notes.md Part 3 is visible in the code.
//
// Run the IdP first (npm run start:dev in the project root), then:  npm run rp
// Open http://localhost:8081

import express from 'express';
import crypto from 'node:crypto';
import { createRemoteJWKSet, jwtVerify } from 'jose';

const IDP = process.env.IDP ?? 'http://localhost:3000';
const PORT = 8081;
const CLIENT_ID = 'banmua'; // public SPA-style client + PKCE (no secret)
const REDIRECT_URI = `http://localhost:${PORT}/auth/callback`;
const SCOPE = 'openid profile email offline_access food:orders food:addresses';

// The IdP's public keys — used to verify the ID token signature (flow step 6).
const JWKS = createRemoteJWKSet(new URL(`${IDP}/jwks`));

// In-memory pending flows, keyed by `state`. Holds the PKCE verifier + nonce
// that must NOT travel to the IdP until the token exchange.
const flows = new Map();

const b64url = (buf) => Buffer.from(buf).toString('base64url');
const rand = (n = 32) => b64url(crypto.randomBytes(n));
const s256 = (verifier) => b64url(crypto.createHash('sha256').update(verifier).digest());

const app = express();

app.get('/', (_req, res) =>
  res.type('html').send(shell(`
    <h1>banmua <span class="tag">test RP</span></h1>
    <p>Stands in for the food client. Clicking below starts a real
       Authorization Code + PKCE flow against <code>${IDP}</code>.</p>
    <a class="btn" href="/login">Log in with kicon →</a>
  `)),
);

app.get('/login', (_req, res) => {
  const state = rand(16);
  const nonce = rand(16);
  const code_verifier = rand(32);
  flows.set(state, { code_verifier, nonce });

  const url = new URL(`${IDP}/auth`);
  url.search = new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: 'code',
    scope: SCOPE,
    state,
    nonce,
    // Required by spec to obtain offline_access (→ refresh token). Consent is
    // auto-approved server-side for this first-party client (no screen shown).
    prompt: 'consent',
    code_challenge: s256(code_verifier),
    code_challenge_method: 'S256',
  }).toString();

  res.redirect(url.toString());
});

app.get('/auth/callback', async (req, res) => {
  try {
    const { code, state, error, error_description } = req.query;
    if (error) return res.type('html').send(shell(`<h1>Authorization error</h1><pre>${error}: ${error_description ?? ''}</pre>`));

    const flow = flows.get(state);
    if (!flow) return res.status(400).type('html').send(shell('<h1>state mismatch</h1><p>CSRF check failed — unknown state.</p>'));
    flows.delete(state);

    // Exchange the one-time code for tokens (back channel). Public client: no
    // secret, PKCE verifier is the proof.
    const tokenRes = await fetch(`${IDP}/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: REDIRECT_URI,
        client_id: CLIENT_ID,
        code_verifier: flow.code_verifier,
      }),
    });
    const tokens = await tokenRes.json();
    if (!tokenRes.ok) return res.status(400).type('html').send(shell(`<h1>token error</h1><pre>${pretty(tokens)}</pre>`));

    // Verify the ID token: signature via JWKS + iss/aud, then the nonce binding.
    const { payload: idClaims, protectedHeader } = await jwtVerify(tokens.id_token, JWKS, {
      issuer: IDP,
      audience: CLIENT_ID,
    });
    const nonceOk = idClaims.nonce === flow.nonce;

    // Call /userinfo with the access token (the fuller claim set).
    const uiRes = await fetch(`${IDP}/me`, { headers: { authorization: `Bearer ${tokens.access_token}` } });
    const userinfo = await uiRes.json();

    res.type('html').send(shell(`
      <h1>Logged in ✓</h1>
      <p class="muted">Same flow you read about, end to end. Open DevTools → Network to replay it.</p>

      <h2>ID token — verified header</h2>
      <pre>${pretty(protectedHeader)}</pre>

      <h2>ID token — claims</h2>
      <pre>${pretty(idClaims)}</pre>
      <p class="${nonceOk ? 'ok' : 'bad'}">nonce ${nonceOk ? 'matches (replay-protected)' : 'MISMATCH'}</p>

      <h2>/userinfo</h2>
      <pre>${pretty(userinfo)}</pre>

      <h2>Raw token response</h2>
      <pre>${pretty({ ...tokens, id_token: tokens.id_token?.slice(0, 40) + '…' })}</pre>
      <p class="muted">access_token is opaque (introspect at /token/introspection, not decodable).
        refresh_token present because <code>offline_access</code> was granted.</p>

      <a class="btn" href="/login">Run it again →</a>
    `));
  } catch (e) {
    res.status(500).type('html').send(shell(`<h1>RP error</h1><pre>${e.stack}</pre>`));
  }
});

app.listen(PORT, () => console.log(`test RP (banmua) on http://localhost:${PORT}  — IdP: ${IDP}`));

const pretty = (o) => escapeHtml(JSON.stringify(o, null, 2));
function escapeHtml(s) {
  return String(s).replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' })[c]);
}
function shell(body) {
  return `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>banmua (test RP)</title><style>
    :root{color-scheme:light dark}body{font:15px/1.55 system-ui,sans-serif;max-width:760px;margin:40px auto;padding:0 20px;background:#0f1115;color:#e7e9ee}
    h1{font-size:1.3rem}h2{font-size:.85rem;text-transform:uppercase;letter-spacing:.04em;color:#8b93a3;margin:26px 0 6px}
    a.btn{display:inline-block;margin-top:18px;background:#4f7cff;color:#fff;padding:10px 16px;border-radius:9px;text-decoration:none;font-weight:600}
    pre{background:#171a21;border:1px solid #262b36;border-radius:10px;padding:14px;overflow:auto;font-size:.82rem}
    code{background:#171a21;border:1px solid #262b36;border-radius:5px;padding:1px 6px;font-size:.85em}
    .tag{font-size:.6em;vertical-align:middle;background:#262b36;padding:2px 7px;border-radius:20px;color:#aab1c0}
    .muted{color:#8b93a3;font-size:.85rem}.ok{color:#6ee7a8}.bad{color:#ff8b98}
  </style><body>${body}</body>`;
}
