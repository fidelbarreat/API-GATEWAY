// redis.js
const Redis = require('ioredis');

const redis = new Redis(process.env.REDIS_URI, {
  retryStrategy: (times) => Math.min(times * 50, 2000),
});

redis.on('connect', () => console.log('✅ Redis conectado'));
redis.on('error', (err) => console.error('❌ Redis error:', err.message));

// Helpers
const blacklist = {
  async add(ip, ttl = process.env.BLACKLIST_TTL_DEFAULT || 300) {
    await redis.setex(`bl:${ip}`, ttl, '1');
  },
  async exists(ip) {
    const res = await redis.exists(`bl:${ip}`);
    return res === 1;
  },
  async remove(ip) {
    await redis.del(`bl:${ip}`);
  },
  async list() {
    const keys = await redis.keys('bl:*');
    return keys.map(k => k.replace('bl:', ''));
  },
};

const metrics = {
  async incr(key) {
    const today = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
    await redis.incr(`metrics:${today}:${key}`);
    await redis.expire(`metrics:${today}:${key}`, process.env.METRICS_TTL || 86400);
  },
  async get(day = new Date().toISOString().slice(0, 10)) {
    const keys = await redis.keys(`metrics:${day}:*`);
    const obj = {};
    for (const k of keys) {
      const field = k.replace(`metrics:${day}:`, '');
      obj[field] = await redis.get(k);
    }
    return obj;
  },
  async recordLatency(uuid, ms) {
    const day = new Date().toISOString().slice(0, 10);
    const key = `lat:${day}:${uuid}`;
    await redis.lpush(key, ms);
    await redis.ltrim(key, 0, 99); // últimas 100
    await redis.expire(key, process.env.METRICS_TTL || 86400);
  },
  async getLatencies(uuid, day = new Date().toISOString().slice(0, 10)) {
    const list = await redis.lrange(`lat:${day}:${uuid}`, 0, -1);
    return list.map(Number);
  },
};

module.exports = { redis, blacklist, metrics };