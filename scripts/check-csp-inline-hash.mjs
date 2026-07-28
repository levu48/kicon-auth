/**
 * Guards the CSP `script-src` hash in deploy/nginx/nginx.conf against drift.
 *
 * oidc-provider renders ONE inline script — the auto-submitting form used by the
 * form_post response mode (lib/response_modes/form_post.js). It is reached on
 * ordinary paths: an account switch during resume, RP-initiated logout with no
 * active session, and the device flow. The IdP's CSP is a STATIC nginx header, so
 * oidc-provider's own `pushInlineSha` helper — which appends the hash to a CSP the
 * application set on the response — never sees it and cannot help. The hash is
 * therefore pinned by hand in nginx.conf.
 *
 * Hand-pinned means it silently rots: bump oidc-provider, have that template gain
 * so much as a space, and every login that hits one of those paths dies at a
 * blocked inline script with no server-side error. That is precisely how this bug
 * reached production the first time. This check fails the build instead.
 *
 * Run: node scripts/check-csp-inline-hash.mjs
 */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

const FORM_POST = 'node_modules/oidc-provider/lib/response_modes/form_post.js';
const NGINX_CONF = 'deploy/nginx/nginx.conf';

function fail(msg) {
  console.error(`\n✗ CSP inline-script hash check failed\n\n${msg}\n`);
  process.exit(1);
}

let source;
try {
  source = readFileSync(FORM_POST, 'utf8');
} catch {
  fail(`Could not read ${FORM_POST}. Run \`npm ci\` first, or oidc-provider moved the file — if it moved, this script needs updating, not deleting.`);
}

// The inline script is the template literal handed to pushInlineSha(ctx, `…`).
const match = source.match(/pushInlineSha\(ctx, `([\s\S]*?)`\)/);
if (!match) {
  fail(`Could not find the pushInlineSha(ctx, \`…\`) template in ${FORM_POST}.\noidc-provider changed how it emits the inline script. Re-derive the hash by hand and update both that expectation and ${NGINX_CONF}.`);
}

const expected = createHash('sha256').update(match[1]).digest('base64');
const directive = `'sha256-${expected}'`;

const conf = readFileSync(NGINX_CONF, 'utf8');
const cspLine = conf.split('\n').find((l) => l.includes('Content-Security-Policy'));
if (!cspLine) fail(`No Content-Security-Policy header found in ${NGINX_CONF}.`);

if (!cspLine.includes(directive)) {
  const found = cspLine.match(/'sha256-[A-Za-z0-9+/=]+'/g);
  fail(
    `oidc-provider's inline script hashes to:\n\n    ${directive}\n\n` +
      `but ${NGINX_CONF} pins:\n\n    ${found ? found.join('\n    ') : '(no sha256- source at all)'}\n\n` +
      `Every login that renders form_post — account switch, logout with no session,\n` +
      `device flow — will be blocked by CSP until script-src carries the value above.\n` +
      `Update the script-src directive in ${NGINX_CONF}, then redeploy the IdP.`,
  );
}

console.log(`✓ CSP script-src pins oidc-provider's inline script hash (${directive})`);
