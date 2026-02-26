// blacklist.js - Middleware de blacklist con manejo de errores robusto
const { blacklist, metrics, redis } = require('./redis');
const { obtenerIpCliente } = require('./ip-utils');
const { enviarAlertaSeguridad } = require('./monitor');

const DOS_THRESHOLD = 20; // requests en 1 min => consideramos DoS

async function blacklistMiddleware(req, res, next) {
  const ip = obtenerIpCliente(req);

  try {
    // Verificar si IP está en blacklist
    const isBlocked = await blacklist.exists(ip);

    if (isBlocked) {
      try {
        await metrics.incr(`bloqueos:${req.params?.uuid || 'global'}`);
      } catch (metricsError) {
        console.error('[BLACKLIST] Error registrando métrica de bloqueo:', metricsError.message);
      }
      
      return res.status(429).json({
        error: 'IP bloqueada por comportamiento sospechoso',
        ip,
        ttl: 'Consulta con el administrador',
        timestamp: new Date().toISOString()
      });
    }

    // Anti-DoS simple (contador por IP)
    const today = new Date().toISOString().slice(0, 10);
    const countKey = `count:${today}:${ip}`;
    
    let current;
    try {
      current = await redis.incr(countKey);
      await redis.expire(countKey, 60); // ventana 1 minuto
    } catch (redisError) {
      console.error('[BLACKLIST] Error en contador DoS:', redisError.message);
      // Si falla Redis, permitir pasar (fail-open)
      return next();
    }

    if (current > DOS_THRESHOLD) {
      const ttl = Number(process.env.BLACKLIST_TTL_DOS || 3600);
      try {
        await blacklist.add(ip, ttl);
        await metrics.incr(`dos_detectado:${req.params?.uuid || 'global'}`);
      } catch (blockError) {
        console.error('[BLACKLIST] Error bloqueando IP por DoS:', blockError.message);
      }

      enviarAlertaSeguridad({
        tipo: 'DDOS',
        nivel: 'ALTO',
        origen: 'blacklist-middleware',
        accion: 'bloqueada',
        uuid: req.params?.uuid || 'global',
        apiNombre: req.apiConfig?.nombre || 'API desconocida',
        emailDestino: req.apiConfig?.email_notificacion || null,
        ip,
        metodo: req.method,
        ruta: req.originalUrl || req.url,
        amenazas: ['DOS_DETECTADO'],
        evidencia: `Frecuencia por IP superior al umbral de ${DOS_THRESHOLD} req/min. Conteo actual: ${current}`,
        ts: Date.now(),
      }).catch((alertError) => {
        console.error('[BLACKLIST] Error enviando alerta de seguridad:', alertError.message);
      });
      
      return res.status(429).json({
        error: 'Posible ataque DoS detectado',
        ip,
        ttl,
        threshold: DOS_THRESHOLD,
        timestamp: new Date().toISOString()
      });
    }

    next();
  } catch (error) {
    console.error('[BLACKLIST] Error crítico:', error.message);
    // Fail-open: si hay cualquier error, permitir la petición
    // Esto evita que un fallo de Redis bloquee todo el tráfico
    next();
  }
}

module.exports = blacklistMiddleware;