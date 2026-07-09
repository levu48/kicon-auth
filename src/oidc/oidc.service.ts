import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { loadOidc } from './provider-loader';
import { loadSigningKeystore } from './keys/keystore';
import { buildConfiguration } from './oidc.config';
import { RedisAdapter } from './redis/redis-adapter';
import { AccountsService } from '../accounts/accounts.service';
import { IdentityService } from '../identity/identity.service';
import { AuditService } from '../audit/audit.service';
import { tenantOf } from '../identity/tenants';

/**
 * Owns the single oidc-provider instance. Built by an explicit async `init()`
 * (called from main.ts before mounting). Construction is async — it dynamically
 * imports the ESM-only package and generates dev keys — so it can't be a plain
 * constructor.
 */
@Injectable()
export class OidcService {
  private readonly logger = new Logger(OidcService.name);
  public provider: any; // Provider type comes from an ESM-only pkg; kept loose here.

  constructor(
    private readonly config: ConfigService,
    private readonly accounts: AccountsService,
    private readonly identity: IdentityService,
    private readonly audit: AuditService,
  ) {}

  async init() {
    const { Provider } = await loadOidc();

    const issuer = this.config.getOrThrow<string>('ISSUER');
    const cookieKeys = (this.config.get<string>('COOKIE_KEYS') ?? 'dev-insecure-key')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);

    const { keystore, generated } = await loadSigningKeystore();

    // findAccount closure: ctx → client → tenant; then project the Postgres-backed
    // core user per tenant. This is the seam where identity meets the protocol.
    const findAccount = async (ctx: any, sub: string) => {
      const user = await this.accounts.findById(sub);
      if (!user) return undefined;
      const tenant = tenantOf(ctx?.oidc?.client?.clientId);
      return {
        accountId: sub,
        claims: async (_use: string, scope: string) =>
          this.identity.projectClaims(user, tenant, scope),
      };
    };

    this.provider = new Provider(
      issuer,
      buildConfiguration({
        jwks: keystore,
        cookieKeys,
        adapter: RedisAdapter,
        findAccount,
      }),
    );
    // Trust X-Forwarded-* behind nginx in prod (CLAUDE.md).
    this.provider.proxy = true;

    this.wireAudit(this.provider);

    const kids = keystore.keys.map((k) => k.kid).join(', ');
    this.logger.log(
      `oidc-provider initialised (issuer=${issuer}, adapter=Redis, signing kids=[${kids}], active=${keystore.keys[0].kid})`,
    );
    if (generated) {
      this.logger.warn(
        `Auto-generated a DEV signing keystore at secrets/jwks.json — persists across restarts, ` +
          `but provide a real keystore via secret in production.`,
      );
    }
  }

  /**
   * Subscribe to oidc-provider's event stream and mirror the security-relevant
   * events into the audit log. Handlers are fire-and-forget (never block or fail
   * a request). Our own login success/failure is audited in the interaction router.
   */
  private wireAudit(provider: any) {
    const a = this.audit;

    provider.on('authorization.success', (ctx: any) =>
      a.emit('authorization.success', a.fromCtx(ctx, { outcome: 'success' })),
    );
    provider.on('authorization.error', (ctx: any, err: any) =>
      a.emit('authorization.error', a.fromCtx(ctx, { outcome: 'failure', detail: { error: err?.message } })),
    );
    // Token endpoint — covers code exchange, refresh, client_credentials.
    provider.on('grant.success', (ctx: any) =>
      a.emit('token.grant', a.fromCtx(ctx, { outcome: 'success', detail: { grant_type: ctx?.oidc?.params?.grant_type } })),
    );
    provider.on('grant.error', (ctx: any, err: any) =>
      a.emit('token.grant', a.fromCtx(ctx, { outcome: 'failure', detail: { grant_type: ctx?.oidc?.params?.grant_type, error: err?.message } })),
    );
    // Refresh-token reuse detection kills the whole family — high-value to audit.
    provider.on('grant.revoked', (ctx: any, grantId: string) =>
      a.emit('grant.revoked', a.fromCtx(ctx, { outcome: 'success', detail: { grantId } })),
    );
    provider.on('revocation.success', (ctx: any) =>
      a.emit('token.revoked', a.fromCtx(ctx, { outcome: 'success' })),
    );
    provider.on('end_session.success', (ctx: any) =>
      a.emit('session.ended', a.fromCtx(ctx, { outcome: 'success' })),
    );
    provider.on('server_error', (ctx: any, err: any) =>
      a.emit('server_error', a.fromCtx(ctx, { outcome: 'failure', detail: { error: err?.message } })),
    );
  }
}
