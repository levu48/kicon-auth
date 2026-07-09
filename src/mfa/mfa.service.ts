import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { UserMfa } from '../database/entities';
import { generateSecret, verifyToken, keyuri } from './totp';

/**
 * Per-tenant MFA policy (CLAUDE.md):
 *   trader → mandatory second factor
 *   civic  → encouraged (required once the user has enrolled)
 *   food   → none
 */
export function mfaRequired(tenant: string, enrolled: boolean): boolean {
  if (tenant === 'trader') return true;
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
