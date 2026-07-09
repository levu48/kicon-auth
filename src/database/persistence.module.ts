import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ENTITIES } from './entities';
import { AccountsService } from '../accounts/accounts.service';
import { IdentityService } from '../identity/identity.service';
import { AuditService } from '../audit/audit.service';
import { MfaService } from '../mfa/mfa.service';
import { DevSeeder } from './dev-seeder';

/**
 * Wires the repositories and the identity/audit services in one place, and
 * exports them so OidcModule (findAccount + audit hooks) and main.ts (login
 * router + dev seed) can use them.
 */
@Module({
  imports: [TypeOrmModule.forFeature(ENTITIES)],
  providers: [AccountsService, IdentityService, AuditService, MfaService, DevSeeder],
  exports: [AccountsService, IdentityService, AuditService, MfaService, DevSeeder],
})
export class PersistenceModule {}
