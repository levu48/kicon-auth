import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User, UserTenantPref, CivicResidency, UserMfa } from './entities';
import { AccountsService } from '../accounts/accounts.service';
import { DEV_PASSWORD, DEV_TOTP_SECRET } from '../accounts/dev-credentials';

/**
 * Idempotent dev seed — reproduces the Phase 0/2 demo against the real DB:
 * one core user (Lan), a trader locale override (en-US), and a verified civic
 * residency (district D3). Guarded to non-production in main.ts.
 */
@Injectable()
export class DevSeeder {
  private readonly logger = new Logger(DevSeeder.name);

  constructor(
    @InjectRepository(User) private readonly users: Repository<User>,
    @InjectRepository(UserTenantPref) private readonly prefs: Repository<UserTenantPref>,
    @InjectRepository(CivicResidency) private readonly civic: Repository<CivicResidency>,
    @InjectRepository(UserMfa) private readonly mfa: Repository<UserMfa>,
    private readonly accounts: AccountsService,
  ) {}

  async seed(): Promise<void> {
    const existing = await this.users.findOne({ where: { id: 'u_8f3c' } });
    if (!existing) {
      await this.users.save(
        this.users.create({
          id: 'u_8f3c',
          primary_email: 'lan@example.com',
          name: 'Lan Nguyen',
          default_locale: 'vi-VN',
          default_zoneinfo: 'Asia/Ho_Chi_Minh',
          password_hash: await this.accounts.hash(DEV_PASSWORD),
        }),
      );
      this.logger.log('seeded dev user u_8f3c (lan@example.com)');
    }

    // Ring 2 override + Ring 3 residency — save() upserts by primary key.
    await this.prefs.save(
      this.prefs.create({ user_id: 'u_8f3c', tenant_id: 'trader', locale: 'en-US', zoneinfo: null }),
    );
    await this.civic.save(
      this.civic.create({
        user_id: 'u_8f3c',
        verified_address: '12 Lê Lợi, Q1',
        district_id: 'D3',
        verified_at: new Date('2025-11-02'),
      }),
    );

    // Enroll the dev user in TOTP with a fixed secret (so trader/civic MFA can be
    // exercised and codes computed by the verifier).
    await this.mfa.save(
      this.mfa.create({
        user_id: 'u_8f3c',
        type: 'totp',
        secret: DEV_TOTP_SECRET,
        enabled_at: new Date('2025-11-02'),
      }),
    );
  }
}
