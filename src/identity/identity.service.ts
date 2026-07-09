import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User, UserTenantPref, CivicResidency } from '../database/entities';

/**
 * The claim projection — the heart of the identity model, now Postgres-backed.
 * Same core user, different projection per tenant, computed at token-mint /
 * userinfo time. See docs/phase-0-study-notes.md Part 4.
 */
@Injectable()
export class IdentityService {
  constructor(
    @InjectRepository(UserTenantPref) private readonly prefs: Repository<UserTenantPref>,
    @InjectRepository(CivicResidency) private readonly civic: Repository<CivicResidency>,
  ) {}

  /** Ring-2 cascade: tenant_override ?? global_default. */
  private async resolveShared(
    user: User,
    tenant: string,
    attr: 'locale' | 'zoneinfo',
  ): Promise<string | null> {
    const row = await this.prefs.findOne({ where: { user_id: user.id, tenant_id: tenant } });
    if (row && row[attr] != null) return row[attr];
    return attr === 'locale' ? user.default_locale : user.default_zoneinfo;
  }

  async projectClaims(user: User, tenant: string, scope: string): Promise<Record<string, any>> {
    const scopes = (scope ?? '').split(' ');
    const claims: Record<string, any> = { sub: user.id }; // opaque, stable, never the email

    if (scopes.includes('email')) claims.email = user.primary_email;

    if (scopes.includes('profile')) {
      claims.name = user.name;
      claims.locale = await this.resolveShared(user, tenant, 'locale');
      claims.zoneinfo = await this.resolveShared(user, tenant, 'zoneinfo');
    }

    // Ring 3 — only civic, only the derived identity fact (district, not address).
    if (tenant === 'civic' && scopes.includes('civic:district')) {
      const res = await this.civic.findOne({ where: { user_id: user.id } });
      if (res?.verified_at) claims.district = res.district_id;
    }

    return claims;
  }
}
