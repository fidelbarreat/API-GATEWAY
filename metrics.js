// metrics.js
const { metrics } = require('./redis');
const { encolarRequestLog } = require('./request-history');
const { obtenerIpCliente } = require('./ip-utils');

function normalizarLatenciaPromediable(valor) {
  if (typeof valor !== 'number' || !Number.isFinite(valor)) return null;
  return valor > 0 ? valor : null;
}

function normalizarAmenazaParaPersistencia(valor) {
  if (Array.isArray(valor)) {
    const primera = String(valor[0] || '').trim();
    return primera || 'NINGUNA';
  }

  const texto = String(valor || '').trim();
  if (!texto || texto === '[]' || texto === '{}' || texto.toLowerCase() === 'null') {
    return 'NINGUNA';
  }

  return texto;
}

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
      ip_cliente: obtenerIpCliente(req),
      agente_usuario: req.headers['user-agent'] || null,
      clasificacion_ia: ai.clasificacion || null,
      amenazas_ia: normalizarAmenazaParaPersistencia(ai.amenazas_detectadas),
      confianza_ia: typeof ai.confianza === 'number' ? ai.confianza : null,
      razon_ia: ai.razon || null,
      nivel_ia: ai.nivel_ia || null,
      heuristica_activada: ai.heuristica_activada === true,
      metodo_ia: ai.metodo || null,
      paso_por_llm: ai.paso_por_llm === true,
      latencia_ia_ms: normalizarLatenciaPromediable(ai.llmLatencyMs),
      latencia_heuristica_ms: typeof ai.heuristicLatencyMs === 'number' ? ai.heuristicLatencyMs : 0,
    });
  });

  next();
}

module.exports = metricsMiddleware;