// blacklist.js
const { blacklist, metrics, redis } = require('./redis');

const DOS_THRESHOLD = 20; // requests en 1 min => consideramos DoS

async function blacklistMiddleware(req, res, next) {
  const ip = req.ip || req.connection.remoteAddress;
  const isBlocked = await blacklist.exists(ip);

  if (isBlocked) {
    await metrics.incr(`bloqueos:${req.params.uuid || 'global'}`);
    return res.status(429).json({
      error: 'IP bloqueada por comportamiento sospechoso',
      ip,
      ttl: 'Consulta con el administrador',
    });
  }

  // Anti-DoS simple (contador por IP)
  const today = new Date().toISOString().slice(0, 10);
  const countKey = `count:${today}:${ip}`;
  const current = await redis.incr(countKey);
  await redis.expire(countKey, 60); // ventana 1 minuto

  if (current > DOS_THRESHOLD) {
    await blacklist.add(ip, process.env.BLACKLIST_TTL_DOS || 3600); // 1 h
    await metrics.incr(`dos_detectado:${req.params.uuid || 'global'}`);
    return res.status(429).json({
      error: 'Posible ataque DoS detectado',
      ip,
      ttl: 3600,
    });
  }

  next();
}

module.exports = blacklistMiddleware;