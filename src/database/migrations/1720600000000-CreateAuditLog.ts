import { MigrationInterface, QueryRunner } from 'typeorm';

/** Append-only audit trail for every auth event (CLAUDE.md). */
export class CreateAuditLog1720600000000 implements MigrationInterface {
  name = 'CreateAuditLog1720600000000';

  public async up(q: QueryRunner): Promise<void> {
    await q.query(`
      CREATE TABLE "audit_log" (
        "id"          bigserial PRIMARY KEY,
        "occurred_at" timestamptz NOT NULL DEFAULT now(),
        "event"       varchar NOT NULL,
        "outcome"     varchar,
        "actor_sub"   varchar,
        "client_id"   varchar,
        "tenant"      varchar,
        "ip"          varchar,
        "user_agent"  varchar,
        "detail"      jsonb
      )
    `);
    await q.query(`CREATE INDEX "idx_audit_occurred_at" ON "audit_log" ("occurred_at")`);
    await q.query(`CREATE INDEX "idx_audit_event" ON "audit_log" ("event")`);
    await q.query(`CREATE INDEX "idx_audit_actor_sub" ON "audit_log" ("actor_sub")`);
  }

  public async down(q: QueryRunner): Promise<void> {
    await q.query(`DROP TABLE "audit_log"`);
  }
}
