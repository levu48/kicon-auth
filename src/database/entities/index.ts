import { User } from './user.entity';
import { UserTenantPref } from './user-tenant-pref.entity';
import { CivicResidency } from './civic-residency.entity';
import { TraderProfile } from './trader-profile.entity';
import { AuditLog } from './audit-log.entity';
import { UserMfa } from './user-mfa.entity';

// Single source of truth for the entity list — used by both the Nest TypeORM
// module and the standalone DataSource the migration CLI uses.
export const ENTITIES = [User, UserTenantPref, CivicResidency, TraderProfile, AuditLog, UserMfa];

export { User, UserTenantPref, CivicResidency, TraderProfile, AuditLog, UserMfa };
