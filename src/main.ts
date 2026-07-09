import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { Logger } from '@nestjs/common';
import type { Express } from 'express';
import { AppModule } from './app.module';
import { OidcService } from './oidc/oidc.service';
import { AccountsService } from './accounts/accounts.service';
import { AuditService } from './audit/audit.service';
import { MfaService } from './mfa/mfa.service';
import { LoginThrottleService } from './security/login-throttle.service';
import { BreachedPasswordService } from './security/breached-password.service';
import { DevSeeder } from './database/dev-seeder';
import { buildInteractionsRouter } from './interactions/interactions.router';

async function bootstrap() {
  // bodyParser:false — oidc-provider parses request bodies itself (e.g. /token).
  // Letting Nest's global body parser consume them first would break those endpoints.
  const app = await NestFactory.create(AppModule, { bodyParser: false });

  // Build the Provider explicitly (async) before we mount it. Must precede
  // listen() so the instance exists when we reference it.
  const oidcService = app.get(OidcService);
  await oidcService.init();

  // Seed the dev account/data (idempotent) — never in production.
  if (process.env.NODE_ENV !== 'production') {
    await app.get(DevSeeder).seed();
  }

  // Mount the oidc handler NOW, before Nest initializes. app.listen() runs
  // Nest's init afterward, which appends Nest's router + terminal 404 handler
  // BEHIND our mount — so our OIDC routes are reached first. (Do NOT call
  // app.init() here: that would register Nest's 404 ahead of oidc and shadow it.)
  const express = app.getHttpAdapter().getInstance() as Express;
  // Behind nginx in prod (CLAUDE.md): honour X-Forwarded-* so the issuer/redirects
  // are computed against the real https origin, not the internal http hop.
  express.set('trust proxy', true);

  // A tiny health route, registered BEFORE the oidc catch-all so it wins.
  express.get('/healthz', (_req, res) => res.json({ status: 'ok' }));

  // Our login UI. Also BEFORE the oidc catch-all so /interaction/* is handled
  // by us, not by oidc-provider's router.
  express.use(
    buildInteractionsRouter(
      oidcService.provider,
      app.get(AccountsService),
      app.get(AuditService),
      app.get(MfaService),
      app.get(LoginThrottleService),
      app.get(BreachedPasswordService),
    ),
  );

  // Mount the whole OIDC surface at the issuer root: /authorize, /token,
  // /jwks, /userinfo, /.well-known/openid-configuration, etc.
  express.use(oidcService.provider.callback());

  const port = Number(process.env.PORT ?? 3000);
  await app.listen(port);

  const log = new Logger('Bootstrap');
  log.log(`IdP listening on http://localhost:${port}`);
  log.log(`discovery: http://localhost:${port}/.well-known/openid-configuration`);
}

bootstrap();
