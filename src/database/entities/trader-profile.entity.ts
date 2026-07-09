import { Entity, Column, PrimaryColumn, CreateDateColumn } from 'typeorm';

/**
 * Ring 3 — hard-partitioned, SENSITIVE / FINANCIAL. Owned by the trader tenant.
 * Minimal stub for now; trading-specific data is enforced by the xbottrader
 * resource server, not the IdP. Lives behind the IdP boundary, never an identity
 * claim.
 */
@Entity('trader_profile')
export class TraderProfile {
  @PrimaryColumn('varchar', { name: 'user_id' })
  user_id: string;

  @Column('varchar', { name: 'kyc_status', default: 'unverified' })
  kyc_status: string;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  created_at: Date;
}
