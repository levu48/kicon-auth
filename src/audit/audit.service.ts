import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { AuditLog } from '../database/entities';
import { tenantOf } from '../identity/tenants';

/**
 * Writes the append-only audit trail. record() NEVER throws into the auth path —
 * a failed audit write is logged, not propagated (auditing must not break login).
 */
@Injectable()
export class AuditService {
  private readonly logger = new Logger(AuditService.name);

  constructor(@InjectRepository(AuditLog) private readonly repo: Repository<AuditLog>) {}

  async record(event: string, fields: Partial<AuditLog> = {}): Promise<void> {
    try {
      await this.repo.insert({ event, ...fields });
    } catch (e: any) {
      this.logger.error(`failed to write audit event "${event}": ${e?.message ?? e}`);
    }
  }

  /** Fire-and-forget wrapper for use inside synchronous event handlers. */
  emit(event: string, fields: Partial<AuditLog> = {}): void {
    void this.record(event, fields);
  }

  /** Extract common fields from an oidc-provider Koa ctx (best-effort). */
  fromCtx(ctx: any, extra: Partial<AuditLog> = {}): Partial<AuditLog> {
    const clientId = ctx?.oidc?.client?.clientId ?? null;
    const actor =
      ctx?.oidc?.account?.accountId ??
      ctx?.oidc?.entities?.Account?.accountId ??
      ctx?.oidc?.entities?.RefreshToken?.accountId ??
      ctx?.oidc?.entities?.AccessToken?.accountId ??
      null;
    return {
      actor_sub: actor,
      client_id: clientId,
      tenant: clientId ? tenantOf(clientId) : null,
      ip: ctx?.ip ?? null,
      user_agent: (typeof ctx?.get === 'function' ? ctx.get('user-agent') : null) ?? null,
      ...extra,
    };
  }
}
