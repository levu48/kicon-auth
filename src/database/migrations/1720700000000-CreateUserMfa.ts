import { MigrationInterface, QueryRunner } from 'typeorm';

/** TOTP second-factor credentials, one row per enrolled user. */
export class CreateUserMfa1720700000000 implements MigrationInterface {
  name = 'CreateUserMfa1720700000000';

  public async up(q: QueryRunner): Promise<void> {
    await q.query(`
      CREATE TABLE "user_mfa" (
        "user_id"    varchar PRIMARY KEY REFERENCES "users"("id") ON DELETE CASCADE,
        "type"       varchar NOT NULL DEFAULT 'totp',
        "secret"     varchar NOT NULL,
        "enabled_at" timestamptz
      )
    `);
  }

  public async down(q: QueryRunner): Promise<void> {
    await q.query(`DROP TABLE "user_mfa"`);
  }
}
