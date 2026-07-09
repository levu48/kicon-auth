import { Entity, Column, PrimaryColumn, CreateDateColumn } from 'typeorm';

/**
 * Ring 1 — the thin shared core, one row per human. Plus credentials
 * (Argon2id hash). Low-sensitivity identity every client may see (projected via
 * claims). Keep this small: resist adding phone/dob/address here.
 */
@Entity('users')
export class User {
  @PrimaryColumn('varchar')
  id: string; // opaque stable `sub`

  @Column('varchar', { unique: true })
  primary_email: string;

  @Column('varchar')
  name: string;

  @Column('varchar', { name: 'default_locale', nullable: true })
  default_locale: string | null;

  @Column('varchar', { name: 'default_zoneinfo', nullable: true })
  default_zoneinfo: string | null;

  @Column('varchar', { name: 'password_hash', nullable: true })
  password_hash: string | null;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  created_at: Date;
}
