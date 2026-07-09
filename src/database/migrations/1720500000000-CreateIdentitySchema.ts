import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Initial IdP identity schema — Rings 1/2/3 + credentials. Deliberately does NOT
 * include food_delivery_addresses (that is banmua's app data; see
 * docs/data-ownership.md). Audit log arrives in Phase 4.
 */
export class CreateIdentitySchema1720500000000 implements MigrationInterface {
  name = 'CreateIdentitySchema1720500000000';

  public async up(q: QueryRunner): Promise<void> {
    await q.query(`
      CREATE TABLE "users" (
        "id"               varchar PRIMARY KEY,
        "primary_email"    varchar NOT NULL UNIQUE,
        "name"             varchar NOT NULL,
        "default_locale"   varchar,
        "default_zoneinfo" varchar,
        "password_hash"    varchar,
        "created_at"       timestamptz NOT NULL DEFAULT now()
      )
    `);

    await q.query(`
      CREATE TABLE "user_tenant_prefs" (
        "user_id"   varchar NOT NULL REFERENCES "users"("id") ON DELETE CASCADE,
        "tenant_id" varchar NOT NULL,
        "locale"    varchar,
        "zoneinfo"  varchar,
        PRIMARY KEY ("user_id", "tenant_id")
      )
    `);

    await q.query(`
      CREATE TABLE "civic_residency" (
        "user_id"          varchar PRIMARY KEY REFERENCES "users"("id") ON DELETE CASCADE,
        "verified_address" varchar,
        "district_id"      varchar,
        "verified_at"      timestamptz
      )
    `);

    await q.query(`
      CREATE TABLE "trader_profile" (
        "user_id"    varchar PRIMARY KEY REFERENCES "users"("id") ON DELETE CASCADE,
        "kyc_status" varchar NOT NULL DEFAULT 'unverified',
        "created_at" timestamptz NOT NULL DEFAULT now()
      )
    `);
  }

  public async down(q: QueryRunner): Promise<void> {
    await q.query(`DROP TABLE "trader_profile"`);
    await q.query(`DROP TABLE "civic_residency"`);
    await q.query(`DROP TABLE "user_tenant_prefs"`);
    await q.query(`DROP TABLE "users"`);
  }
}
