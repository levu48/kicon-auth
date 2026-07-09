import { Entity, Column, PrimaryColumn } from 'typeorm';

/**
 * Ring 3 — hard-partitioned, SENSITIVE. Owned by the civic tenant, never
 * cross-read. `verified_at` gates whether we emit the derived `district` claim
 * (we emit the district, never the raw address). Lives behind the IdP boundary
 * (see docs/data-ownership.md), not in any app's database.
 */
@Entity('civic_residency')
export class CivicResidency {
  @PrimaryColumn('varchar', { name: 'user_id' })
  user_id: string;

  @Column('varchar', { name: 'verified_address', nullable: true })
  verified_address: string | null;

  @Column('varchar', { name: 'district_id', nullable: true })
  district_id: string | null;

  @Column('timestamptz', { name: 'verified_at', nullable: true })
  verified_at: Date | null;
}
