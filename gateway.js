// gateway.js  (versión 3.3 – Redis + blacklist + métricas)
try {
  require('dotenv').config();
} catch (_e) {
  // dotenv es opcional; si no está instalado, se usan variables del entorno del sistema.
}

const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const { iniciarMonitorMultiplesAPIs } = require('./monitor');
const fs = require('fs');
const path = require('path');

// Middlewares Redis
const blacklistMiddleware = require('./blacklist');
const metricsMiddleware = require('./metrics');
const { blacklist, metrics: metricsAPI } = require('./redis');

// Clasificador de amenazas con IA
const { aiClassifierMiddleware, getAIMetrics } = require('./ai-classifier');

const PUERTO = Number(process.env.PUERTO || process.env.PORT || 3000);
const DB_PATH = path.join(__dirname, 'db.json');

const app = express();

// Cargar catálogo de APIs
function cargarAPIs() {
  try {
    const data = fs.readFileSync(DB_PATH, 'utf-8');
    const db = JSON.parse(data);
    return db.apis || {};
  } catch (err) {
    console.error('Error cargando db.json:', err.message);
    return {};
  }
}

let apisDisponibles = cargarAPIs();

// Health-check propio del gateway
app.get('/gateway/health', (_req, res) => res.json({ status: 'UP', ts: Date.now() }));

// Listar APIs registradas
app.get('/gateway/apis', (_req, res) => {
  const lista = Object.entries(apisDisponibles).map(([uuid, info]) => ({
    uuid,
    ...info
  }));
  res.json({ total: lista.length, apis: lista });
});

// Endpoints Redis
// Blacklist
app.get('/gateway/blacklist', async (_req, res) => {
  const list = await blacklist.list();
  res.json({ total: list.length, ips: list });
});

app.delete('/gateway/blacklist/:ip', async (req, res) => {
  await blacklist.remove(req.params.ip);
  res.json({ msg: 'IP desbloqueada', ip: req.params.ip });
});

// Métricas
app.get('/gateway/metrics', async (_req, res) => {
  const day = new Date().toISOString().slice(0, 10);
  const data = await metricsAPI.get(day);
  res.json({ day, metrics: data });
});

app.get('/gateway/metrics/:uuid/latency', async (req, res) => {
  const day = new Date().toISOString().slice(0, 10);
  const lat = await metricsAPI.getLatencies(req.params.uuid, day);
  const avg = lat.length ? (lat.reduce((a, b) => a + b, 0) / lat.length).toFixed(2) : 0;
  res.json({ uuid: req.params.uuid, day, total: lat.length, avg, latencies: lat });
});

// Métricas de IA
app.get('/gateway/ai/metrics', async (_req, res) => {
  const aiMetrics = await getAIMetrics();
  res.json(aiMetrics);
});

// Estado del clasificador IA
app.get('/gateway/ai/status', (_req, res) => {
  res.json({
    enabled: process.env.AI_ENABLED !== 'false',
    model: process.env.AI_MODEL || 'gpt-5-mini',
    api_key_configured: !!process.env.OPENAI_API_KEY
  });
});

// Iniciar monitoreo multi-API (health-check + alertas)
iniciarMonitorMultiplesAPIs(app, apisDisponibles);

// Middleware para parsear JSON (necesario para análisis de body)
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

//  Middlewares antes del proxy: blacklist -> IA classifier -> metrics
app.use('/:uuid', blacklistMiddleware, aiClassifierMiddleware, metricsMiddleware);

// Middleware de extracción de UUID + proxy dinámico
app.use((req, res, next) => {
  // Ignorar rutas internas del gateway
  if (req.originalUrl.startsWith('/gateway')) {
    return next();
  }

  const match = req.originalUrl.match(/^\/([a-zA-Z0-9\-]+)\/(.*)$/);
  if (!match) return next(); // pasará a la ruta por defecto

  const [, uuid, rest] = match;
  const apiConfig = apisDisponibles[uuid];

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

  const rutaReal = `/${rest}`;

  const proxy = createProxyMiddleware({
    target: apiConfig.url,
    changeOrigin: true,
    pathRewrite: () => rutaReal,
    ws: true,
    onProxyReq: () => {
      console.log(`[PROXY] ${apiConfig.nombre} → ${apiConfig.url}${rutaReal}`);
    },
    onError: (err, _req, res) => {
      console.error(`[ERROR] ${apiConfig.nombre}:`, err.message);
      res.status(502).json({ error: 'Error en la API destino', api: apiConfig.nombre });
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

app.listen(PUERTO, () => {
  console.log(`\nGateway running on http://localhost:${PUERTO}`);
  console.log(`Ver APIs: http://localhost:${PUERTO}/gateway/apis\n`);

  Object.entries(apisDisponibles).forEach(([uuid, info]) => {
    if (info.activa) {
      console.log(`  ✓ ${info.nombre} → localhost:${PUERTO}/${uuid}/...`);
    }
  });
  console.log('');
});