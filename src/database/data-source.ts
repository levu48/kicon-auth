import 'reflect-metadata';
import { join } from 'node:path';
import { DataSource, DataSourceOptions } from 'typeorm';
import { ENTITIES } from './entities';

/**
 * Standalone DataSource for the TypeORM migration CLI (npm run migration:*).
 * The running app configures TypeORM separately via TypeOrmModule.forRootAsync
 * (see app.module.ts) — both point at the same DB and entity list.
 *
 * The CLI does not load .env, so we default to the local dev URL; override with
 * DATABASE_URL when running elsewhere.
 */
export const dataSourceOptions: DataSourceOptions = {
  type: 'postgres',
  url: process.env.DATABASE_URL ?? 'postgres://thachle@localhost:5432/kicon_idp',
  entities: ENTITIES,
  migrations: [join(__dirname, 'migrations', '*.{ts,js}')],
  synchronize: false, // NEVER — schema changes go through reviewed migrations
  logging: ['error', 'migration'],
};

export default new DataSource(dataSourceOptions);
