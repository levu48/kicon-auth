import { Entity, Column, PrimaryColumn } from 'typeorm';

/**
 * Ring 2 — sparse per-tenant overrides for TRUE-shared attributes. A row exists
 * ONLY when a tenant overrode a global default. Composite PK (user_id, tenant_id).
 */
@Entity('user_tenant_prefs')
export class UserTenantPref {
  @PrimaryColumn('varchar', { name: 'user_id' })
  user_id: string;

  @PrimaryColumn('varchar', { name: 'tenant_id' })
  tenant_id: string;

  @Column('varchar', { nullable: true })
  locale: string | null;

  @Column('varchar', { nullable: true })
  zoneinfo: string | null;
}
