// gateway.js  (versión 3.4 – Redis + blacklist + métricas + fixes)
try {
  require('dotenv').config();
} catch (_e) {
  // dotenv es opcional
}

const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const { iniciarMonitorMultiplesAPIs } = require('./monitor');
const { fetchApis } = require('./supabase');
const { iniciarRequestHistorySync, detenerRequestHistorySync } = require('./request-history');

// Middlewares Redis
const blacklistMiddleware = require('./blacklist');
const metricsMiddleware = require('./metrics');
const { blacklist, metrics: metricsAPI, checkRedisHealth } = require('./redis');

// Clasificador de amenazas con IA
const { aiClassifierMiddleware, getAIMetrics } = require('./ai-classifier');

const PUERTO = Number(process.env.PORT || process.env.PUERTO || 3000);
const HOST = process.env.HOST || '0.0.0.0';
const APIS_CACHE_TTL_MS = Number(process.env.APIS_CACHE_TTL_MS || 15000);

const app = express();
app.set('trust proxy', true);

// Cargar catálogo de APIs desde Supabase
let apisDisponibles = {};
let apisCacheTs = 0;

async function cargarAPIs() {
  return fetchApis();
}

async function obtenerAPIsActualizadas() {
  const ahora = Date.now();
  if (ahora - apisCacheTs < APIS_CACHE_TTL_MS) return apisDisponibles;

  try {
    const nuevas = await cargarAPIs();
    apisDisponibles = nuevas;
    apisCacheTs = ahora;
  } catch (err) {
    console.error('Error cargando APIs desde Supabase:', err.message);
  }

  return apisDisponibles;
}

function normalizarUrlDestino(url) {
  return String(url || '').trim().replace(/\/+$/, '');
}

// Health-check propio del gateway
app.get('/gateway/health', async (_req, res) => {
  const redisHealth = await checkRedisHealth();
  res.json({ 
    status: 'UP', 
    ts: Date.now(),
    redis: redisHealth
  });
});

// Listar APIs registradas
app.get('/gateway/apis', async (_req, res) => {
  const apis = await obtenerAPIsActualizadas();
  const lista = Object.entries(apis).map(([uuid, info]) => ({
    uuid,
    ...info
  }));
  res.json({ total: lista.length, apis: lista });
});

// Endpoints Redis con manejo de errores
// Blacklist
app.get('/gateway/blacklist', async (_req, res) => {
  try {
    const list = await blacklist.list();
    res.json({ total: list.length, ips: list });
  } catch (error) {
    res.status(500).json({ error: 'Error al obtener blacklist', message: error.message });
  }
});

app.delete('/gateway/blacklist/:ip', async (req, res) => {
  try {
    await blacklist.remove(req.params.ip);
    res.json({ msg: 'IP desbloqueada', ip: req.params.ip });
  } catch (error) {
    res.status(500).json({ error: 'Error al desbloquear IP', message: error.message });
  }
});

// Métricas
app.get('/gateway/metrics', async (_req, res) => {
  try {
    const day = new Date().toISOString().slice(0, 10);
    const data = await metricsAPI.get(day);
    res.json({ day, metrics: data });
  } catch (error) {
    res.status(500).json({ error: 'Error al obtener métricas', message: error.message });
  }
});

app.get('/gateway/metrics/:uuid/latency', async (req, res) => {
  try {
    const day = new Date().toISOString().slice(0, 10);
    const lat = await metricsAPI.getLatencies(req.params.uuid, day);
    const avg = lat.length ? (lat.reduce((a, b) => a + b, 0) / lat.length).toFixed(2) : 0;
    res.json({ uuid: req.params.uuid, day, total: lat.length, avg, latencies: lat });
  } catch (error) {
    res.status(500).json({ error: 'Error al obtener latencias', message: error.message });
  }
});

// Métricas de IA
app.get('/gateway/ai/metrics', async (_req, res) => {
  try {
    const aiMetrics = await getAIMetrics();
    res.json(aiMetrics);
  } catch (error) {
    res.status(500).json({ error: 'Error al obtener métricas de IA', message: error.message });
  }
});

// Estado del clasificador IA
app.get('/gateway/ai/status', (_req, res) => {
  res.json({
    enabled: true,
    mode: 'per-api',
    niveles_ia_soportados: ['NO', 'BAJO', 'ALTO'],
    model: process.env.AI_MODEL || 'gpt-5-mini',
    api_key_configured: !!process.env.OPENAI_API_KEY
  });
});

// Resolver API por UUID antes de middlewares de seguridad/proxy para usar configuración por API
app.use('/:uuid', async (req, res, next) => {
  const uuid = req.params.uuid;

  try {
    const apis = await obtenerAPIsActualizadas();
    const apiConfig = apis[uuid];

    if (!apiConfig) {
      return res.status(404).json({
        error: 'API no encontrada',
        uuid,
        mensaje: 'El UUID proporcionado no corresponde a ninguna API registrada'
      });
    }

    if (!apiConfig.activa) {
      return res.status(403).json({
        error: 'API desactivada',
        uuid,
        nombre: apiConfig.nombre
      });
    }

    req.apiConfig = {
      uuid,
      ...apiConfig,
    };

    next();
  } catch (error) {
    console.error('[GATEWAY] Error resolviendo API por UUID:', error.message);
    return res.status(500).json({ error: 'Error resolviendo API destino' });
  }
});

// Filtrado temprano para IPs bloqueadas / DoS (antes de parsear body)
app.use('/:uuid', blacklistMiddleware);

// Middleware para parsear JSON (necesario para análisis de body)
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// Middlewares antes del proxy: IA classifier -> metrics
app.use('/:uuid', aiClassifierMiddleware, metricsMiddleware);

// Middleware de extracción de UUID + proxy dinámico
app.use(async (req, res, next) => {
  // Ignorar rutas internas del gateway
  if (req.originalUrl.startsWith('/gateway')) {
    return next();
  }

  const match = req.originalUrl.match(/^\/([a-zA-Z0-9\-]+)\/(.*)$/);
  if (!match) return next(); // pasará a la ruta por defecto

  const [, uuid, rest] = match;
  const apiConfig = req.apiConfig;

  if (!apiConfig) {
    return res.status(500).json({
      error: 'Configuración de API no disponible',
      uuid,
    });
  }

  const rutaReal = `/${rest}`;
  const destino = normalizarUrlDestino(apiConfig.url);

  if (!destino) {
    return res.status(502).json({
      error: 'API destino sin URL configurada',
      uuid,
      nombre: apiConfig.nombre
    });
  }

  const proxy = createProxyMiddleware({
    target: destino,
    changeOrigin: true,
    pathRewrite: () => rutaReal,
    ws: true,
    onProxyReq: (proxyReq, req) => {
      console.log(`[PROXY] ${apiConfig.nombre} → ${destino}${rutaReal}`);
    },
    onError: (err, _req, res) => {
      console.error(`[ERROR] ${apiConfig.nombre}:`, err.message);
      if (!res.headersSent) {
        res.status(502).json({ error: 'Error en la API destino', api: apiConfig.nombre });
      }
    }
  });

  return proxy(req, res, next);
});

// Ruta por defecto (cuando no hay UUID)
app.use('/', (_req, res) => {
  res.status(400).json({
    error: 'UUID requerido',
    formato: '/gateway/apis para ver APIs disponibles',
    ejemplo: 'localhost:3000/{UUID}/recurso'
  });
});

// Manejo de errores global
app.use((err, _req, res, _next) => {
  console.error('[EXPRESS] Error no manejado:', err);
  res.status(500).json({ error: 'Error interno del servidor' });
});

async function iniciarServidor() {
  try {
    apisDisponibles = await cargarAPIs();
    apisCacheTs = Date.now();
  } catch (err) {
    console.error('Error inicial cargando APIs desde Supabase:', err.message);
  }

  // Iniciar monitoreo multi-API (health-check + alertas)
  iniciarMonitorMultiplesAPIs(app, apisDisponibles);
  iniciarRequestHistorySync();

  app.listen(PUERTO, HOST, () => {
    console.log(`\n🚀 Gateway running on http://${HOST}:${PUERTO}`);
    console.log(`📋 Ver APIs: http://${HOST}:${PUERTO}/gateway/apis\n`);

    Object.entries(apisDisponibles).forEach(([uuid, info]) => {
      if (info.activa) {
        console.log(`  ✓ ${info.nombre} → localhost:${PUERTO}/${uuid}/...`);
      }
    });
    console.log('');
  });
  console.log('');
}

let cerrando = false;

async function apagarGateway(signal) {
  if (cerrando) return;
  cerrando = true;

  console.log(`\n[SHUTDOWN] Señal recibida: ${signal}. Sincronizando reportes pendientes...`);
  await detenerRequestHistorySync();
  process.exit(0);
}

process.on('SIGINT', () => {
  apagarGateway('SIGINT').catch((err) => {
    console.error('[SHUTDOWN] Error al cerrar:', err.message);
    process.exit(1);
  });
});

process.on('SIGTERM', () => {
  apagarGateway('SIGTERM').catch((err) => {
    console.error('[SHUTDOWN] Error al cerrar:', err.message);
    process.exit(1);
  });
});

iniciarServidor();
