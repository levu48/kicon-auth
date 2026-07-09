import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { generateKeyPair, exportJWK, type JWK } from 'jose';

/**
 * Signing keystore management. The IdP signs ID tokens with ES256 and publishes
 * the public halves at /jwks so clients can verify by `kid`.
 *
 * Rotation model: the keystore is an ORDERED list of private JWKs. The FIRST key
 * is the active signer for new tokens; the rest remain published so tokens signed
 * before a rotation still verify until they expire. Rotating = prepend a new key.
 *
 * Keys live OUTSIDE the repo (CLAUDE.md): a gitignored file in dev, a mounted
 * secret in prod. Never commit private keys.
 */

export interface Keystore {
  keys: JWK[];
}

export function keystorePath(): string {
  return process.env.JWKS_PATH ?? join(process.cwd(), 'secrets', 'jwks.json');
}

export function readKeystore(): Keystore | null {
  try {
    const parsed = JSON.parse(readFileSync(keystorePath(), 'utf8'));
    return Array.isArray(parsed?.keys) && parsed.keys.length ? parsed : null;
  } catch {
    return null;
  }
}

export function writeKeystore(ks: Keystore): void {
  const path = keystorePath();
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(ks, null, 2), { mode: 0o600 }); // owner-only
}

/** Generate a fresh ES256 signing key as a private JWK with a readable kid. */
export async function generateSigningKey(): Promise<JWK> {
  const { privateKey } = await generateKeyPair('ES256', { extractable: true });
  const jwk = await exportJWK(privateKey);
  const stamp = new Date().toISOString().replace(/[-:T]/g, '').slice(0, 14);
  const kid = `es256-${stamp}-${randomBytes(3).toString('hex')}`;
  return { ...jwk, kid, alg: 'ES256', use: 'sig' };
}

/**
 * Load the signing keystore for the running provider.
 * - If a keystore file exists, use it (keys persist across restarts).
 * - Dev with no keystore: generate one and persist it (so dev is stable too).
 * - Production with no keystore: fail hard — a real key must be provided.
 */
export async function loadSigningKeystore(): Promise<{ keystore: Keystore; generated: boolean }> {
  const existing = readKeystore();
  if (existing) return { keystore: existing, generated: false };

  if (process.env.NODE_ENV === 'production') {
    throw new Error(
      `No signing keystore at ${keystorePath()}. Provide one (mounted secret) in production; ` +
        `never auto-generate keys in prod.`,
    );
  }

  const keystore: Keystore = { keys: [await generateSigningKey()] };
  writeKeystore(keystore);
  return { keystore, generated: true };
}
