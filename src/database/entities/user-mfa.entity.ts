import { Entity, Column, PrimaryColumn } from 'typeorm';

/**
 * Second-factor credential (TOTP). One row per enrolled user.
 *
 * NOTE: the secret is stored in plaintext for dev. In production it must be
 * encrypted at rest (envelope encryption / KMS) — it is a bearer credential.
 * Flagged for Phase 5 hardening.
 */
@Entity('user_mfa')
export class UserMfa {
  @PrimaryColumn('varchar', { name: 'user_id' })
  user_id: string;

  @Column('varchar', { default: 'totp' })
  type: string;

  @Column('varchar')
  secret: string; // base32 TOTP secret (encrypt in prod)

  @Column('timestamptz', { name: 'enabled_at', nullable: true })
  enabled_at: Date | null; // set once enrollment is confirmed
}
