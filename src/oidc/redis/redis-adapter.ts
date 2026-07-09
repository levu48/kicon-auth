import { redis } from './redis-client';

/**
 * Redis storage adapter for oidc-provider — replaces the in-memory adapter so
 * sessions, authorization codes, tokens, and grants survive restarts and can be
 * shared across instances (Phase 5: two instances behind nginx).
 *
 * Ported from the canonical panva oidc-provider ioredis example. oidc-provider
 * instantiates `new RedisAdapter(name)` per model at runtime.
 *
 * Verify against your installed oidc-provider version's Adapter interface
 * (CLAUDE.md standing rule): upsert/find/findByUid/findByUserCode/consume/
 * destroy/revokeByGrantId.
 */

// Models whose keys are tracked under a grant, so revokeByGrantId can cascade.
const grantable = new Set([
  'AccessToken',
  'AuthorizationCode',
  'RefreshToken',
  'DeviceCode',
  'BackchannelAuthenticationRequest',
]);

// Models stored as a hash (so a `consumed` marker can be added in place).
const consumable = new Set([
  'AuthorizationCode',
  'RefreshToken',
  'DeviceCode',
  'BackchannelAuthenticationRequest',
]);

const grantKeyFor = (id: string) => `grant:${id}`;
const userCodeKeyFor = (userCode: string) => `userCode:${userCode}`;
const uidKeyFor = (uid: string) => `uid:${uid}`;

export class RedisAdapter {
  constructor(private readonly name: string) {}

  private key(id: string): string {
    return `${this.name}:${id}`;
  }

  async upsert(id: string, payload: Record<string, any>, expiresIn: number): Promise<void> {
    const key = this.key(id);
    const store = consumable.has(this.name)
      ? { payload: JSON.stringify(payload) }
      : JSON.stringify(payload);

    const multi = redis().multi();
    if (typeof store === 'string') multi.set(key, store);
    else multi.hmset(key, store);

    if (expiresIn) multi.expire(key, expiresIn);

    if (grantable.has(this.name) && payload.grantId) {
      const grantKey = grantKeyFor(payload.grantId);
      multi.rpush(grantKey, key);
      // The grant-key list expires with the longest-lived token it tracks.
      const ttl = await redis().ttl(grantKey);
      if (expiresIn > ttl) multi.expire(grantKey, expiresIn);
    }

    if (payload.userCode) {
      const uc = userCodeKeyFor(payload.userCode);
      multi.set(uc, id);
      if (expiresIn) multi.expire(uc, expiresIn);
    }
    if (payload.uid) {
      const uidKey = uidKeyFor(payload.uid);
      multi.set(uidKey, id);
      if (expiresIn) multi.expire(uidKey, expiresIn);
    }

    await multi.exec();
  }

  async find(id: string): Promise<Record<string, any> | undefined> {
    const data = consumable.has(this.name)
      ? await redis().hgetall(this.key(id))
      : await redis().get(this.key(id));

    if (!data || (typeof data === 'object' && !Object.keys(data).length)) {
      return undefined;
    }
    if (typeof data === 'string') {
      return JSON.parse(data);
    }
    const { payload, ...rest } = data as Record<string, string>;
    return { ...rest, ...JSON.parse(payload) };
  }

  async findByUid(uid: string): Promise<Record<string, any> | undefined> {
    const id = await redis().get(uidKeyFor(uid));
    return id ? this.find(id) : undefined;
  }

  async findByUserCode(userCode: string): Promise<Record<string, any> | undefined> {
    const id = await redis().get(userCodeKeyFor(userCode));
    return id ? this.find(id) : undefined;
  }

  async consume(id: string): Promise<void> {
    await redis().hset(this.key(id), 'consumed', Math.floor(Date.now() / 1000));
  }

  async destroy(id: string): Promise<void> {
    await redis().del(this.key(id));
  }

  async revokeByGrantId(grantId: string): Promise<void> {
    const grantKey = grantKeyFor(grantId);
    const tokens = await redis().lrange(grantKey, 0, -1);
    const multi = redis().multi();
    tokens.forEach((token) => multi.del(token));
    multi.del(grantKey);
    await multi.exec();
  }
}
