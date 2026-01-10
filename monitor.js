try {
  require('dotenv').config();
} catch (_e) {
  // dotenv es opcional; si no está instalado, se usan variables del entorno del sistema.
}

const nodemailer = require('nodemailer');
const http = require('http');
const https = require('https');

function obtenerNumeroEnv(nombre, valorPorDefecto) {
  const valor = process.env[nombre];
  if (valor === undefined || valor === null || valor === '') return valorPorDefecto;
  const numero = Number(valor);
  return Number.isFinite(numero) ? numero : valorPorDefecto;
}

function obtenerBooleanoEnv(nombre, valorPorDefecto) {
  const valor = process.env[nombre];
  if (valor === undefined || valor === null || valor === '') return valorPorDefecto;
  return ['1', 'true', 'TRUE', 'si', 'SI', 'yes', 'YES'].includes(String(valor));
}

function construirUrlHealthcheckExterno({ destino }) {
  const urlDirecta = process.env.URL_HEALTHCHECK_EXTERNO || process.env.HEALTHCHECK_URL;
  if (urlDirecta) return urlDirecta;

  const ruta = process.env.RUTA_HEALTHCHECK_EXTERNO || process.env.HEALTHCHECK_PATH || '/health';
  const base = String(destino).replace(/\/$/, '');
  const rutaNormalizada = String(ruta).startsWith('/') ? ruta : `/${ruta}`;
  return `${base}${rutaNormalizada}`;
}

function solicitarUrl({ url, timeoutMs }) {
  return new Promise((resolve, reject) => {
    let urlObj;
    try {
      urlObj = new URL(url);
    } catch (_e) {
      reject(new Error(`URL inválida: ${url}`));
      return;
    }

    const cliente = urlObj.protocol === 'https:' ? https : http;
    const inicio = Date.now();

    const req = cliente.request(
      urlObj,
      { method: 'GET', headers: { 'user-agent': 'api-gateway-healthcheck/1.0' } },
      (res) => {
        res.resume();
        res.on('end', () => {
          const latenciaMs = Date.now() - inicio;
          resolve({ statusCode: res.statusCode || 0, latenciaMs });
        });
      }
    );

    req.on('error', reject);
    req.setTimeout(timeoutMs, () => req.destroy(new Error('Timeout')));
    req.end();
  });
}

function crearTransportadorCorreo() {
  const HOST_SMTP = process.env.HOST_SMTP || process.env.SMTP_HOST;
  const PUERTO_SMTP = obtenerNumeroEnv('PUERTO_SMTP', obtenerNumeroEnv('SMTP_PORT', 587));
  const USUARIO_SMTP = process.env.USUARIO_SMTP || process.env.SMTP_USER;
  const CLAVE_SMTP = process.env.CLAVE_SMTP || process.env.SMTP_PASS;
  const DESDE_SMTP = process.env.DESDE_SMTP || process.env.SMTP_FROM || USUARIO_SMTP;
  const ALERTA_PARA = process.env.ALERTA_PARA || process.env.ALERT_TO;

  const transportadorCorreo = (HOST_SMTP && USUARIO_SMTP && CLAVE_SMTP && ALERTA_PARA)
    ? nodemailer.createTransport({
        host: HOST_SMTP,
        port: PUERTO_SMTP,
        secure: PUERTO_SMTP === 465,
        auth: { user: USUARIO_SMTP, pass: CLAVE_SMTP },
      })
    : null;

  return {
    transportadorCorreo,
    DESDE_SMTP,
    ALERTA_PARA,
  };
}

function iniciarMonitorSaludBackend(app, { destino } = {}) {
  if (!app) throw new Error('iniciarMonitorSaludBackend requiere una instancia de Express (app).');
  if (!destino) throw new Error('iniciarMonitorSaludBackend requiere { destino }.');

  const URL_HEALTHCHECK_EXTERNO = construirUrlHealthcheckExterno({ destino });

  const INTERVALO_HEALTHCHECK_MS = obtenerNumeroEnv(
    'INTERVALO_HEALTHCHECK_MS',
    obtenerNumeroEnv('HEALTHCHECK_INTERVAL_MS', 30_000)
  );
  const TIMEOUT_HEALTHCHECK_MS = obtenerNumeroEnv(
    'TIMEOUT_HEALTHCHECK_MS',
    obtenerNumeroEnv('HEALTHCHECK_TIMEOUT_MS', 5_000)
  );

  const UMBRAL_LATENCIA_MS = obtenerNumeroEnv(
    'UMBRAL_LATENCIA_MS',
    obtenerNumeroEnv('HEALTHCHECK_MAX_LATENCY_MS', 1500)
  );
  const GOLPES_LATENCIA_ALTA = obtenerNumeroEnv(
    'GOLPES_LATENCIA_ALTA',
    obtenerNumeroEnv('HEALTHCHECK_HIGH_LATENCY_STRIKES', 2)
  );
  const GOLPES_FALLO = obtenerNumeroEnv(
    'GOLPES_FALLO',
    obtenerNumeroEnv('HEALTHCHECK_FAIL_STRIKES', 2)
  );

  const ENFRIAMIENTO_ALERTA_MS = obtenerNumeroEnv(
    'ENFRIAMIENTO_ALERTA_MS',
    obtenerNumeroEnv('ALERT_COOLDOWN_MS', 10 * 60_000)
  );
  const ALERTAR_RECUPERACION = obtenerBooleanoEnv('ALERTAR_RECUPERACION', true);

  const { transportadorCorreo, DESDE_SMTP, ALERTA_PARA } = crearTransportadorCorreo();

  const estadoMonitor = {
    urlBackend: URL_HEALTHCHECK_EXTERNO,
    ultimoChequeoTs: null,
    ultimoOkTs: null,
    ultimoFalloTs: null,
    ultimoEstado: 'DESCONOCIDO', // ARRIBA | ABAJO | DEGRADADO | DESCONOCIDO
    ultimaLatenciaMs: null,
    fallosConsecutivos: 0,
    latenciaAltaConsecutiva: 0,
    ultimoError: null,
    ultimaAlertaTs: 0,
  };

  async function enviarAlertaCorreo(asunto, texto) {
    const ahora = Date.now();
    if (ahora - estadoMonitor.ultimaAlertaTs < ENFRIAMIENTO_ALERTA_MS) return;
    estadoMonitor.ultimaAlertaTs = ahora;

    if (!transportadorCorreo) {
      console.warn('[ALERTA omitida] SMTP no configurado:', { asunto, texto });
      return;
    }

    await transportadorCorreo.sendMail({
      from: DESDE_SMTP,
      to: ALERTA_PARA,
      subject: asunto,
      text: texto,
    });
  }

  async function verificarBackendUnaVez() {
    const ahora = Date.now();
    estadoMonitor.ultimoChequeoTs = ahora;

    try {
      const { statusCode, latenciaMs } = await solicitarUrl({
        url: URL_HEALTHCHECK_EXTERNO,
        timeoutMs: TIMEOUT_HEALTHCHECK_MS,
      });

      estadoMonitor.ultimaLatenciaMs = latenciaMs;

      const esOk = statusCode >= 200 && statusCode < 300;
      const esErrorServidor = statusCode >= 500;

      if (!esOk || esErrorServidor) {
        estadoMonitor.fallosConsecutivos += 1;
        estadoMonitor.ultimoFalloTs = ahora;
        estadoMonitor.ultimoError = `Status inesperado: ${statusCode}`;
      } else {
        estadoMonitor.fallosConsecutivos = 0;
        estadoMonitor.ultimoOkTs = ahora;
        estadoMonitor.ultimoError = null;
      }

      if (latenciaMs > UMBRAL_LATENCIA_MS) {
        estadoMonitor.latenciaAltaConsecutiva += 1;
      } else {
        estadoMonitor.latenciaAltaConsecutiva = 0;
      }

      const estadoAnterior = estadoMonitor.ultimoEstado;

      if (estadoMonitor.fallosConsecutivos >= GOLPES_FALLO) {
        estadoMonitor.ultimoEstado = 'ABAJO';
      } else if (estadoMonitor.latenciaAltaConsecutiva >= GOLPES_LATENCIA_ALTA) {
        estadoMonitor.ultimoEstado = 'DEGRADADO';
      } else if (estadoMonitor.fallosConsecutivos === 0) {
        estadoMonitor.ultimoEstado = 'ARRIBA';
      } else {
        estadoMonitor.ultimoEstado = 'DEGRADADO';
      }

      if (estadoAnterior !== estadoMonitor.ultimoEstado) {
        const detalle = [
          `Backend: ${URL_HEALTHCHECK_EXTERNO}`,
          `Estado: ${estadoAnterior} -> ${estadoMonitor.ultimoEstado}`,
          `Latencia: ${latenciaMs} ms (umbral ${UMBRAL_LATENCIA_MS} ms)`,
          `Fallos consecutivos: ${estadoMonitor.fallosConsecutivos} (umbral ${GOLPES_FALLO})`,
          `Latencia alta consecutiva: ${estadoMonitor.latenciaAltaConsecutiva} (umbral ${GOLPES_LATENCIA_ALTA})`,
          `Error: ${estadoMonitor.ultimoError || 'ninguno'}`,
          `Ts: ${new Date(ahora).toISOString()}`,
        ].join('\n');

        if (estadoMonitor.ultimoEstado === 'ABAJO') {
          await enviarAlertaCorreo('[API-GW] BACKEND ABAJO', detalle);
        } else if (estadoMonitor.ultimoEstado === 'DEGRADADO') {
          await enviarAlertaCorreo('[API-GW] BACKEND DEGRADADO', detalle);
        } else if (
          estadoMonitor.ultimoEstado === 'ARRIBA' &&
          ALERTAR_RECUPERACION &&
          (estadoAnterior === 'ABAJO' || estadoAnterior === 'DEGRADADO')
        ) {
          await enviarAlertaCorreo('[API-GW] BACKEND RECUPERADO', detalle);
        }
      }
    } catch (err) {
      estadoMonitor.ultimaLatenciaMs = null;
      estadoMonitor.ultimoFalloTs = ahora;
      estadoMonitor.fallosConsecutivos += 1;
      estadoMonitor.ultimoError = err && err.message ? err.message : String(err);

      const estadoAnterior = estadoMonitor.ultimoEstado;
      estadoMonitor.ultimoEstado = (estadoMonitor.fallosConsecutivos >= GOLPES_FALLO) ? 'ABAJO' : 'DEGRADADO';

      if (estadoAnterior !== estadoMonitor.ultimoEstado && estadoMonitor.ultimoEstado === 'ABAJO') {
        const detalle = [
          `Backend: ${URL_HEALTHCHECK_EXTERNO}`,
          `Estado: ${estadoAnterior} -> ${estadoMonitor.ultimoEstado}`,
          `Error: ${estadoMonitor.ultimoError}`,
          `Ts: ${new Date(ahora).toISOString()}`,
        ].join('\n');
        await enviarAlertaCorreo('[API-GW] BACKEND ABAJO', detalle);
      }
    }
  }

  app.get('/gateway/salud-backend', (_req, res) => res.json({ ...estadoMonitor, ts: Date.now() }));
  app.get('/gateway/backend-health', (_req, res) => res.json({ ...estadoMonitor, ts: Date.now() }));

  setTimeout(() => {
    verificarBackendUnaVez().catch((e) => console.error('Healthcheck inicial falló:', e));
    setInterval(() => {
      verificarBackendUnaVez().catch((e) => console.error('Healthcheck periódico falló:', e));
    }, INTERVALO_HEALTHCHECK_MS);
  }, 500);

  return {
    obtenerEstado: () => ({ ...estadoMonitor, ts: Date.now() }),
  };
}

module.exports = {
  iniciarMonitorSaludBackend,
};
