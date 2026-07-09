import { Injectable } from '@nestjs/common';
import { redis } from '../oidc/redis/redis-client';

/**
 * Login rate limiting + account lockout, backed by Redis counters.
 * - per-IP: at most LOGIN_IP_MAX attempts per LOGIN_IP_WINDOW seconds.
 * - per-account: after LOGIN_ACCOUNT_MAX_FAILURES bad passwords, lock the account
 *   for LOGIN_LOCKOUT_SECONDS (even a correct password is rejected while locked).
 *
 * Tradeoff noted: account lockout keyed by email enables a targeted lockout DoS.
 * Acceptable for now; a later refinement is IP+account scoping / exponential
 * backoff. Counters reset on a successful password.
 */
const IP_WINDOW = Number(process.env.LOGIN_IP_WINDOW ?? 60);
const IP_MAX = Number(process.env.LOGIN_IP_MAX ?? 20);
const ACCOUNT_MAX = Number(process.env.LOGIN_ACCOUNT_MAX_FAILURES ?? 5);
const LOCKOUT_TTL = Number(process.env.LOGIN_LOCKOUT_SECONDS ?? 900);

export interface ThrottleDecision {
  allowed: boolean;
  reason?: 'account_locked' | 'ip_rate_limited';
  retryAfter?: number;
}

@Injectable()
export class LoginThrottleService {
  private key(kind: string, id: string): string {
    return `throttle:${kind}:${id}`;
  }
  private norm(email?: string): string {
    return (email ?? '').trim().toLowerCase();
  }

  /** Call before verifying a password. */
  async check(ip: string | undefined, email?: string): Promise<ThrottleDecision> {
    const r = redis();
    const em = this.norm(email);
    if (em) {
      const lockTtl = await r.ttl(this.key('lock', em));
      if (lockTtl > 0) return { allowed: false, reason: 'account_locked', retryAfter: lockTtl };
    }
    const ipKey = this.key('ip', ip ?? 'unknown');
    const count = Number((await r.get(ipKey)) ?? 0);
    if (count >= IP_MAX) {
      const ttl = await r.ttl(ipKey);
      return { allowed: false, reason: 'ip_rate_limited', retryAfter: ttl > 0 ? ttl : IP_WINDOW };
    }
    return { allowed: true };
  }

  /** Count this attempt toward the per-IP window. */
  async onAttempt(ip: string | undefined): Promise<void> {
    const r = redis();
    const ipKey = this.key('ip', ip ?? 'unknown');
    const n = await r.incr(ipKey);
    if (n === 1) await r.expire(ipKey, IP_WINDOW);
  }

  /** A bad password: bump the account failure counter and lock at the threshold. */
  async onFailure(email?: string): Promise<number> {
    const em = this.norm(email);
    if (!em) return 0;
    const r = redis();
    const failKey = this.key('fail', em);
    const n = await r.incr(failKey);
    if (n === 1) await r.expire(failKey, LOCKOUT_TTL);
    if (n >= ACCOUNT_MAX) {
      await r.set(this.key('lock', em), '1', 'EX', LOCKOUT_TTL);
    }
    return n;
  }

  /** A correct password: clear the failure counter and any lock. */
  async onSuccess(email?: string): Promise<void> {
    const em = this.norm(email);
    if (!em) return;
    const r = redis();
    await r.del(this.key('fail', em), this.key('lock', em));
  }
}
