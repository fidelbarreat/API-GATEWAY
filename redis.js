// redis.js - Cliente Redis con reconexión robusta y keepalive
const Redis = require('ioredis');

const redis = new Redis(process.env.REDIS_URI, {
  retryStrategy: (times) => {
    const delay = Math.min(times * 50, 2000);
    console.log(`[REDIS] Reintentando conexión en ${delay}ms (intento ${times})`);
    return delay;
  },
  keepAlive: 30000,           // Keepalive cada 30 segundos
  connectTimeout: 10000,      // 10 segundos timeout de conexión
  lazyConnect: false,         // Conectar inmediatamente
  maxRetriesPerRequest: 3,    // Reintentar operaciones fallidas
  enableReadyCheck: true,     // Verificar ready antes de comandos
  enableOfflineQueue: true,   // Encolar comandos si desconectado
  reconnectOnError: (err) => {
    const targetErrors = ['READONLY', 'ECONNRESET', 'ETIMEDOUT', 'ECONNREFUSED'];
    const shouldReconnect = targetErrors.some(e => err.message.includes(e));
    if (shouldReconnect) {
      console.log('[REDIS] Reconectando por error:', err.message);
      return true;
    }
    return false;
  }
});

// Eventos de conexión
redis.on('connect', () => {
  console.log('✅ Redis: Conexión establecida');
});

redis.on('ready', () => {
  console.log('✅ Redis: Cliente listo para operaciones');
});

redis.on('error', (err) => {
  // No cerrar el proceso, solo loggear
  console.error('❌ Redis error:', err.message);
});

redis.on('close', () => {
  console.warn('⚠️ Redis: Conexión cerrada');
});

redis.on('reconnecting', () => {
  console.log('🔄 Redis: Reconectando...');
});

redis.on('end', () => {
  console.warn('⚠️ Redis: Conexión terminada permanentemente');
});

// Helpers con manejo de errores
const blacklist = {
  async add(ip, ttl = process.env.BLACKLIST_TTL_DEFAULT || 300) {
    try {
      await redis.setex(`bl:${ip}`, ttl, '1');
      console.log(`[BLACKLIST] IP ${ip} bloqueada por ${ttl}s`);
      return true;
    } catch (error) {
      console.error('[BLACKLIST] Error al añadir:', error.message);
      throw error;
    }
  },
  
  async exists(ip) {
    try {
      const res = await redis.exists(`bl:${ip}`);
      return res === 1;
    } catch (error) {
      console.error('[BLACKLIST] Error al verificar:', error.message);
      // Si falla, asumir que no está bloqueada (fail-open)
      return false;
    }
  },
  
  async remove(ip) {
    try {
      await redis.del(`bl:${ip}`);
      console.log(`[BLACKLIST] IP ${ip} desbloqueada`);
      return true;
    } catch (error) {
      console.error('[BLACKLIST] Error al remover:', error.message);
      throw error;
    }
  },
  
  async list() {
    try {
      const keys = await redis.keys('bl:*');
      return keys.map(k => k.replace('bl:', ''));
    } catch (error) {
      console.error('[BLACKLIST] Error al listar:', error.message);
      return [];
    }
  },
};

const metrics = {
  async incr(key) {
    try {
      const today = new Date().toISOString().slice(0, 10);
      const fullKey = `metrics:${today}:${key}`;
      await redis.incr(fullKey);
      await redis.expire(fullKey, Number(process.env.METRICS_TTL || 86400));
      return true;
    } catch (error) {
      console.error('[METRICS] Error al incrementar:', error.message);
      // No propagar error para no afectar el flujo principal
      return false;
    }
  },
  
  async get(day = new Date().toISOString().slice(0, 10)) {
    try {
      const keys = await redis.keys(`metrics:${day}:*`);
      const obj = {};
      for (const k of keys) {
        const field = k.replace(`metrics:${day}:`, '');
        obj[field] = await redis.get(k);
      }
      return obj;
    } catch (error) {
      console.error('[METRICS] Error al obtener:', error.message);
      return {};
    }
  },
  
  async recordLatency(uuid, ms) {
    try {
      const day = new Date().toISOString().slice(0, 10);
      const key = `lat:${day}:${uuid}`;
      await redis.lpush(key, ms);
      await redis.ltrim(key, 0, 99); // últimas 100
      await redis.expire(key, Number(process.env.METRICS_TTL || 86400));
      return true;
    } catch (error) {
      console.error('[METRICS] Error al registrar latencia:', error.message);
      return false;
    }
  },
  
  async getLatencies(uuid, day = new Date().toISOString().slice(0, 10)) {
    try {
      const list = await redis.lrange(`lat:${day}:${uuid}`, 0, -1);
      return list.map(Number);
    } catch (error) {
      console.error('[METRICS] Error al obtener latencias:', error.message);
      return [];
    }
  },
};

// Healthcheck de Redis
async function checkRedisHealth() {
  try {
    await redis.ping();
    return { status: 'UP', timestamp: Date.now() };
  } catch (error) {
    return { status: 'DOWN', error: error.message, timestamp: Date.now() };
  }
}

module.exports = { redis, blacklist, metrics, checkRedisHealth };