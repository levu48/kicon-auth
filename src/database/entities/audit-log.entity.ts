import { Entity, Column, PrimaryGeneratedColumn, CreateDateColumn, Index } from 'typeorm';

/**
 * Append-only audit trail (CLAUDE.md: "Audit-log every auth event"). Lives in the
 * IdP Postgres. Written only by AuditService.record() — never updated or deleted
 * in code. (DB-level INSERT-only privileges are a Phase 5 hardening step.)
 */
@Entity('audit_log')
export class AuditLog {
  @PrimaryGeneratedColumn('increment', { type: 'bigint' })
  id: string;

  @Index()
  @CreateDateColumn({ name: 'occurred_at', type: 'timestamptz' })
  occurred_at: Date;

  @Index()
  @Column('varchar')
  event: string; // e.g. login.success, token.grant, grant.revoked

  @Column('varchar', { nullable: true })
  outcome: string | null; // 'success' | 'failure'

  @Index()
  @Column('varchar', { name: 'actor_sub', nullable: true })
  actor_sub: string | null; // the user, when known

  @Column('varchar', { name: 'client_id', nullable: true })
  client_id: string | null;

  @Column('varchar', { nullable: true })
  tenant: string | null;

  @Column('varchar', { nullable: true })
  ip: string | null;

  @Column('varchar', { name: 'user_agent', nullable: true })
  user_agent: string | null;

  @Column('jsonb', { nullable: true })
  detail: Record<string, any> | null; // extra structured context (never secrets)
}
