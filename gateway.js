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

const PUERTO = Number(process.env.PUERTO || process.env.PORT || 3000);
const DB_PATH = path.join(__dirname, 'db.json');

const app = express();

// Cargar base de datos de APIs
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

// Health-check propio
app.get('/gateway/health', (_req, res) => res.json({ status: 'UP', ts: Date.now() }));

// Endpoint para listar APIs disponibles
app.get('/gateway/apis', (_req, res) => {
  const lista = Object.entries(apisDisponibles).map(([uuid, info]) => ({
    uuid,
    ...info
  }));
  res.json({ total: lista.length, apis: lista });
});

// Iniciar sistema de monitoreo (esto registra rutas /gateway/salud)
iniciarMonitorMultiplesAPIs(app, apisDisponibles);

// Middleware para extraer UUID y redirigir a la API correspondiente
app.use((req, res, next) => {
  // Ignorar rutas del gateway
  if (req.originalUrl.startsWith('/gateway')) {
    return next();
  }

  const match = req.originalUrl.match(/^\/([a-zA-Z0-9\-]+)\/(.*)$/);
  
  if (!match) {
    return next();
  }

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

  // Construir la ruta real
  const rutaReal = `/${rest}`;
  
  // Crear proxy dinámico
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

// Ruta por defecto (sin UUID)
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