// metrics.js
const { metrics } = require('./redis');

async function metricsMiddleware(req, res, next) {
  const start = Date.now();
  const uuid = req.params.uuid || 'global';

  res.on('finish', async () => {
    const latency = Date.now() - start;
    await metrics.incr(`requests:${uuid}`);
    await metrics.recordLatency(uuid, latency);
    if (res.statusCode >= 400) await metrics.incr(`errores:${uuid}`);
  });

  next();
}

module.exports = metricsMiddleware;