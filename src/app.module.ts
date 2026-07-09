import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ENTITIES } from './database/entities';
import { PersistenceModule } from './database/persistence.module';
import { SecurityModule } from './security/security.module';
import { OidcModule } from './oidc/oidc.module';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }), // reads .env
    TypeOrmModule.forRootAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        type: 'postgres',
        url: config.getOrThrow<string>('DATABASE_URL'),
        entities: ENTITIES,
        synchronize: false, // schema is owned by reviewed migrations, never auto-sync
        migrationsRun: false, // migrations run explicitly via `npm run migration:run`
      }),
    }),
    PersistenceModule,
    SecurityModule,
    OidcModule,
  ],
})
export class AppModule {}
