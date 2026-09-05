import Redis from "ioredis";

let redis: Redis | null = null;

export function getRedis(): Redis {
  if (!redis) {
    const url = process.env.REDIS_URL || "redis://localhost:6379";
    redis = new Redis(url, {
      maxRetriesPerRequest: 3,
      lazyConnect: true,
    });
    redis.on("error", () => {});
  }
  return redis;
}

export async function cacheGet<T>(key: string): Promise<T | null> {
  try {
    const client = getRedis();
    const value = await client.get(key);
    return value ? JSON.parse(value) as T : null;
  } catch {
    return null;
  }
}

export async function cacheSet(key: string, value: unknown, ttlSeconds = 60): Promise<void> {
  try {
    const client = getRedis();
    await client.setex(key, ttlSeconds, JSON.stringify(value));
  } catch {
    // Cache failures should not break the application
  }
}

export async function cacheDel(pattern: string): Promise<void> {
  try {
    const client = getRedis();
    const keys = await client.keys(pattern);
    if (keys.length) await client.del(...keys);
  } catch {
    // ignore
  }
}

export async function publish(channel: string, message: unknown): Promise<void> {
  try {
    const client = getRedis();
    await client.publish(channel, JSON.stringify(message));
  } catch {
    // ignore
  }
}
