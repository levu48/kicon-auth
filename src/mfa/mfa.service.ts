import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { UserMfa } from '../database/entities';
import { ACR_MFA } from './acr';
import { generateSecret, verifyToken, keyuri } from './totp';

/**
 * Surfaces where a second factor is MANDATORY — the user cannot complete login
 * without one, and is refused (not downgraded) if they have not enrolled.
 *
 * This is a per-CLIENT list rather than per-tenant because the vote app's two
 * surfaces share the `apps` tenant but have opposite requirements: the
 * embeddable consumer widget is standard assurance, the admin origin is not.
 *
 * NOTE: this can NOT be derived from the client's default_acr_values. Both
 * `vote-admin` (mandatory) and `vietcouncil` (encouraged) declare ACR_MFA, so
 * treating that declaration as mandatory would lock every un-enrolled civic user
 * out — contradicting the documented civic policy. default_acr_values says
 * "loa2 is wanted", not "loa2 or nothing".
 */
const MFA_MANDATORY_CLIENTS = new Set(['vote-admin']);

/**
 * MFA policy (CLAUDE.md), in precedence order:
 *
 *   mandatory client (vote-admin) → always; refuse if not enrolled
 *   trader tenant                 → always; refuse if not enrolled
 *   request asked for loa2 AND the user is enrolled → yes (honour it / step-up)
 *   civic tenant                  → once the user has enrolled
 *   food / apps consumer          → no
 *
 * Why the acr clause requires `enrolled`: asking for loa2 is a request, not a
 * command (OIDC treats acr_values as voluntary). Honour it when we can; fall
 * back to loa1 when the user has no second factor, and let the resource server
 * decide whether the resulting acr is good enough. Mandatory surfaces are the
 * ones listed above, where falling back is not acceptable.
 *
 * This gap is why the change exists: `vote-admin` advertised
 * default_acr_values:[ACR_MFA] and clients.ts claimed "MFA mandatory (enforced
 * in the login step)", but its tenant fell through to `return false`, so no
 * second factor was ever requested and the admin surface issued loa1 tokens.
 * api.kicon.com gates destructive admin routes on acr === loa2, and an
 * unenforced acr is a control that only LOOKS enforced.
 */
export function mfaRequired(
  tenant: string,
  enrolled: boolean,
  opts: { clientId?: string; acrValues?: string | string[] } = {},
): boolean {
  if (opts.clientId && MFA_MANDATORY_CLIENTS.has(opts.clientId)) return true;
  if (tenant === 'trader') return true;

  const requested = Array.isArray(opts.acrValues)
    ? opts.acrValues
    : (opts.acrValues ?? '').split(' ').filter(Boolean);
  if (requested.includes(ACR_MFA) && enrolled) return true;

  if (tenant === 'civic') return enrolled;
  return false;
}

@Injectable()
export class MfaService {
  constructor(@InjectRepository(UserMfa) private readonly repo: Repository<UserMfa>) {}

  async isEnrolled(userId: string): Promise<boolean> {
    const row = await this.repo.findOne({ where: { user_id: userId } });
    return !!row?.enabled_at;
  }

  async verify(userId: string, token: string): Promise<boolean> {
    const row = await this.repo.findOne({ where: { user_id: userId } });
    return row?.secret ? verifyToken(row.secret, token) : false;
  }

  /** Begin enrollment: create a secret and return it + an otpauth URI (QR data). */
  async enroll(userId: string, issuer = 'auth.kicon.com', account = userId) {
    const secret = generateSecret();
    await this.repo.save(this.repo.create({ user_id: userId, type: 'totp', secret, enabled_at: new Date() }));
    return { secret, otpauth: keyuri(secret, account, issuer) };
  }
}
