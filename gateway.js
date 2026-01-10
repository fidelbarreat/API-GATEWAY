try {
  require('dotenv').config();
} catch (_e) {
  // dotenv es opcional; si no está instalado, se usan variables del entorno del sistema.
}

const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const { iniciarMonitorSaludBackend } = require('./monitor');

const DESTINO = process.env.DESTINO || process.env.TARGET || 'http://localhost:4000';
const PUERTO = Number(process.env.PUERTO || process.env.PORT || 3000);

const app = express();

// Health-check propio
app.get('/gateway/health', (_req, res) => res.json({ status: 'UP', ts: Date.now() }));

// Logger de latencia
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const latency = Date.now() - start;
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.url} → ${res.statusCode} (${latency} ms)`);
  });
  next();
});

iniciarMonitorSaludBackend(app, { destino: DESTINO });

// Proxy reverso
app.use('/', createProxyMiddleware({
  target: DESTINO,
  changeOrigin: true,
  ws: true,
  onError: (err, _req, res) => {
    console.error('Proxy error:', err.message);
    res.status(502).json({ error: 'Bad Gateway' });
  }
}));

app.listen(PUERTO, () => console.log(`Gateway running on http://localhost:${PUERTO} → ${DESTINO}`));