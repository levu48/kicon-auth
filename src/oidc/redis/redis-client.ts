import Redis from 'ioredis';

/**
 * Lazily-created singleton ioredis client. Created on first use (after
 * ConfigModule has loaded .env into process.env), so REDIS_URL is available.
 */
let client: Redis | null = null;

export function redis(): Redis {
  if (!client) {
    client = new Redis(process.env.REDIS_URL ?? 'redis://localhost:6379', {
      keyPrefix: 'oidc:',
    });
  }
  return client;
}
