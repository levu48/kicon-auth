import { Injectable, Logger } from '@nestjs/common';
import { createHash } from 'node:crypto';

/**
 * Breached-password check via the Have I Been Pwned range API using
 * k-anonymity: only the first 5 hex chars of the SHA-1 leave the system; HIBP
 * returns all suffixes for that prefix and we match locally. The full password
 * (and its full hash) never leave the process.
 *
 * Fail-open: on any network/availability error we return 0 (not breached) so a
 * HIBP outage can never block logins. Intended for password-set time; here it is
 * also run advisory-only at login to flag already-compromised passwords.
 */
@Injectable()
export class BreachedPasswordService {
  private readonly logger = new Logger(BreachedPasswordService.name);

  async pwnedCount(password: string): Promise<number> {
    if (!password) return 0;
    try {
      const sha1 = createHash('sha1').update(password, 'utf8').digest('hex').toUpperCase();
      const prefix = sha1.slice(0, 5);
      const suffix = sha1.slice(5);

      const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
        headers: { 'Add-Padding': 'true', 'User-Agent': 'auth.kicon.com-idp' },
        signal: AbortSignal.timeout(3000),
      });
      if (!res.ok) return 0;

      const body = await res.text();
      for (const line of body.split('\n')) {
        const [suf, count] = line.trim().split(':');
        if (suf === suffix) return Number(count) || 0;
      }
      return 0;
    } catch (e: any) {
      this.logger.warn(`HIBP check failed (fail-open): ${e?.message ?? e}`);
      return 0;
    }
  }

  async isBreached(password: string): Promise<boolean> {
    return (await this.pwnedCount(password)) > 0;
  }
}
