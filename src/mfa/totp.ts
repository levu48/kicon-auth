import { createHmac, randomBytes } from 'node:crypto';

/**
 * Minimal RFC 6238 TOTP (SHA1, 6 digits, 30s step) + RFC 4648 base32, no external
 * deps. Compatible with Google Authenticator / Authy etc. Kept small and readable
 * on purpose — this is core auth machinery worth understanding.
 */

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(buf: Buffer): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(s: string): Buffer {
  const clean = s.replace(/=+$/, '').replace(/\s/g, '').toUpperCase();
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = B32.indexOf(ch);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/** New random base32 secret (default 20 bytes = 160 bits, per RFC 6238). */
export function generateSecret(bytes = 20): string {
  return base32Encode(randomBytes(bytes));
}

export function generateToken(
  secretB32: string,
  forTimeMs = Date.now(),
  step = 30,
  digits = 6,
): string {
  const key = base32Decode(secretB32);
  let counter = Math.floor(forTimeMs / 1000 / step);
  const buf = Buffer.alloc(8);
  for (let i = 7; i >= 0; i--) {
    buf[i] = counter & 0xff;
    counter = Math.floor(counter / 256);
  }
  const hmac = createHmac('sha1', key).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const bin =
    ((hmac[offset] & 0x7f) << 24) |
    (hmac[offset + 1] << 16) |
    (hmac[offset + 2] << 8) |
    hmac[offset + 3];
  return (bin % 10 ** digits).toString().padStart(digits, '0');
}

/** Verify with a +/- window (default 1 step) to tolerate clock skew. */
export function verifyToken(secretB32: string, token: string, window = 1): boolean {
  const t = (token ?? '').trim();
  if (!/^\d{6}$/.test(t)) return false;
  const now = Date.now();
  for (let w = -window; w <= window; w++) {
    if (generateToken(secretB32, now + w * 30 * 1000) === t) return true;
  }
  return false;
}

/** otpauth:// URI for authenticator-app enrollment (render as a QR in real UX). */
export function keyuri(secretB32: string, account: string, issuer: string): string {
  const label = encodeURIComponent(`${issuer}:${account}`);
  const params = new URLSearchParams({
    secret: secretB32,
    issuer,
    algorithm: 'SHA1',
    digits: '6',
    period: '30',
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}
