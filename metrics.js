// metrics.js
const { metrics } = require('./redis');
const { encolarRequestLog } = require('./request-history');

async function metricsMiddleware(req, res, next) {
  const start = Date.now();
  const fechaPeticion = new Date(start).toISOString();
  const uuid = req.params.uuid || 'global';

  res.on('finish', async () => {
    const latency = Date.now() - start;
    await metrics.incr(`requests:${uuid}`);
    await metrics.recordLatency(uuid, latency);
    if (res.statusCode >= 400) await metrics.incr(`errores:${uuid}`);

    const ai = req.aiClassification || {};
    encolarRequestLog({
      fecha_peticion: fechaPeticion,
      uuid_api: uuid,
      metodo: req.method,
      ruta: req.originalUrl || req.url,
      codigo_estado: res.statusCode,
      latencia_ms: latency,
      ip_cliente: req.ip || req.connection?.remoteAddress || null,
      agente_usuario: req.headers['user-agent'] || null,
      clasificacion_ia: ai.clasificacion || null,
      amenazas_ia: ai.amenazas_detectadas || [],
      confianza_ia: typeof ai.confianza === 'number' ? ai.confianza : null,
    });
  });

  next();
}

module.exports = metricsMiddleware;