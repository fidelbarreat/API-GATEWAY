try {
  require('dotenv').config();
} catch (_e) {
  // dotenv es opcional; si no está instalado, se usan variables del entorno del sistema.
}

const nodemailer = require('nodemailer');
const http = require('http');
const https = require('https');

const estadoAlertasSeguridad = {
  ultimaAlertaPorClave: new Map(),
};

let canalAlertasSeguridad = null;

// Lee un valor numérico desde las variables de entorno y devuelve un valor por defecto si no está configurado.
function obtenerNumeroEnv(nombre, valorPorDefecto) {
  const valor = process.env[nombre];
  if (valor === undefined || valor === null || valor === '') return valorPorDefecto;
  const numero = Number(valor);
  return Number.isFinite(numero) ? numero : valorPorDefecto;
}

// Interpreta un valor de entorno como booleano, aceptando variantes comunes como "true", "1", "yes", etc.
function obtenerBooleanoEnv(nombre, valorPorDefecto) {
  const valor = process.env[nombre];
  if (valor === undefined || valor === null || valor === '') return valorPorDefecto;
  return ['1', 'true', 'TRUE', 'si', 'SI', 'yes', 'YES'].includes(String(valor));
}

// Construye la URL completa para el healthcheck del backend, combinando la URL base con la ruta configurada.
function construirUrlHealthcheckExterno({ destino }) {
  const urlDirecta = process.env.URL_HEALTHCHECK_EXTERNO || process.env.HEALTHCHECK_URL;
  if (urlDirecta) return urlDirecta;

  const ruta = process.env.RUTA_HEALTHCHECK_EXTERNO || process.env.HEALTHCHECK_PATH || '/health';
  const base = String(destino).replace(/\/$/, '');
  const rutaNormalizada = String(ruta).startsWith('/') ? ruta : `/${ruta}`;
  return `${base}${rutaNormalizada}`;
}

// Realiza una solicitud HTTP/HTTPS a una URL y devuelve el código de estado y el tiempo de respuesta.
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

// Configura el transportador de correo SMTP basándose en las variables de entorno disponibles.
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

function normalizarTipoAmenaza(tipo) {
  const valor = String(tipo || 'PETICION_SOSPECHOSA').trim().toUpperCase();
  if (!valor) return 'PETICION_SOSPECHOSA';
  return valor.replace(/\s+/g, '_');
}

function obtenerCanalAlertasSeguridad() {
  if (canalAlertasSeguridad) return canalAlertasSeguridad;

  const { transportadorCorreo, DESDE_SMTP, ALERTA_PARA } = crearTransportadorCorreo();
  canalAlertasSeguridad = { transportadorCorreo, DESDE_SMTP, ALERTA_PARA };
  return canalAlertasSeguridad;
}

async function enviarAlertaSeguridad(evento = {}) {
  const habilitadas = obtenerBooleanoEnv('ALERTAS_SEGURIDAD_HABILITADAS', true);
  if (!habilitadas) return { sent: false, reason: 'disabled' };

  const tipo = normalizarTipoAmenaza(evento.tipo);
  const nivel = String(evento.nivel || 'MEDIO').toUpperCase();
  const origen = String(evento.origen || 'desconocido');
  const accion = String(evento.accion || 'alerta');
  const ip = String(evento.ip || 'desconocida');
  const uuid = String(evento.uuid || 'global');
  const apiNombre = String(evento.apiNombre || 'N/A');
  const ruta = String(evento.ruta || 'N/A');
  const metodo = String(evento.metodo || 'N/A');
  const confianza = Number(evento.confianza);
  const amenazasTexto = Array.isArray(evento.amenazas)
    ? evento.amenazas.filter(Boolean).join(', ')
    : String(evento.amenazas || '').trim();
  const evidencia = String(evento.evidencia || '').slice(0, 500);
  const emailDestinoEvento = String(evento.emailDestino || '').trim();
  const timestampIso = evento.ts ? new Date(evento.ts).toISOString() : new Date().toISOString();

  const enfriamientoMs = obtenerNumeroEnv('ENFRIAMIENTO_ALERTA_SEGURIDAD_MS', 120_000);
  const clave = `${tipo}:${nivel}:${ip}:${uuid}`;
  const ahora = Date.now();
  const ultima = estadoAlertasSeguridad.ultimaAlertaPorClave.get(clave) || 0;

  if (ahora - ultima < enfriamientoMs) {
    return { sent: false, reason: 'cooldown' };
  }

  estadoAlertasSeguridad.ultimaAlertaPorClave.set(clave, ahora);

  const { transportadorCorreo, DESDE_SMTP, ALERTA_PARA } = obtenerCanalAlertasSeguridad();
  const destinoCorreo = emailDestinoEvento || ALERTA_PARA;

  if (!transportadorCorreo || !destinoCorreo) {
    console.warn('[ALERTA SEGURIDAD omitida] SMTP no configurado:', { tipo, ip, uuid });
    return { sent: false, reason: 'smtp-not-configured' };
  }

  const asunto = `[API-GW][SECURITY][${nivel}] ${tipo} en ${apiNombre}`;
  const cuerpo = [
    'Se detectó un evento de seguridad en API Gateway.',
    '',
    `Tipo: ${tipo}`,
    `Nivel: ${nivel}`,
    `Origen detección: ${origen}`,
    `Acción aplicada: ${accion}`,
    `UUID API: ${uuid}`,
    `Nombre API: ${apiNombre}`,
    `IP cliente: ${ip}`,
    `Método: ${metodo}`,
    `Ruta: ${ruta}`,
    `Amenazas: ${amenazasTexto || 'N/A'}`,
    `Confianza: ${Number.isFinite(confianza) ? confianza : 'N/A'}`,
    `Evidencia: ${evidencia || 'N/A'}`,
    `Timestamp: ${timestampIso}`,
  ].join('\n');

  await transportadorCorreo.sendMail({
    from: DESDE_SMTP,
    to: destinoCorreo,
    subject: asunto,
    text: cuerpo,
  });

  return { sent: true };
}

// Crea un monitor individual para una API específica.
function crearMonitorAPI({ uuid, nombre, url, transportadorCorreo, DESDE_SMTP, ALERTA_PARA_API }) {
  const INTERVALO_HEALTHCHECK_MS = obtenerNumeroEnv('INTERVALO_HEALTHCHECK_MS', 30_000);
  const TIMEOUT_HEALTHCHECK_MS = obtenerNumeroEnv('TIMEOUT_HEALTHCHECK_MS', 5_000);
  const UMBRAL_LATENCIA_MS = obtenerNumeroEnv('UMBRAL_LATENCIA_MS', 1500);
  const GOLPES_LATENCIA_ALTA = obtenerNumeroEnv('GOLPES_LATENCIA_ALTA', 2);
  const GOLPES_FALLO = obtenerNumeroEnv('GOLPES_FALLO', 2);
  const ENFRIAMIENTO_ALERTA_MS = obtenerNumeroEnv('ENFRIAMIENTO_ALERTA_MS', 600_000);
  const ALERTAR_RECUPERACION = obtenerBooleanoEnv('ALERTAR_RECUPERACION', true);

  const estadoMonitor = {
    uuid,
    nombre,
    url,
    ultimoChequeoTs: null,
    ultimoOkTs: null,
    ultimoFalloTs: null,
    ultimoEstado: 'DESCONOCIDO',
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

    if (!transportadorCorreo || !ALERTA_PARA_API) {
      console.warn('[ALERTA omitida] SMTP no configurado:', { asunto });
      return;
    }

    await transportadorCorreo.sendMail({
      from: DESDE_SMTP,
      to: ALERTA_PARA_API,
      subject: asunto,
      text: texto,
    });
  }

  async function verificarUnaVez() {
    const ahora = Date.now();
    estadoMonitor.ultimoChequeoTs = ahora;

    try {
      const { statusCode, latenciaMs } = await solicitarUrl({
        url,
        timeoutMs: TIMEOUT_HEALTHCHECK_MS,
      });

      estadoMonitor.ultimaLatenciaMs = latenciaMs;
      const esOk = statusCode >= 200 && statusCode < 300;
      const esErrorServidor = statusCode >= 500;

      if (!esOk || esErrorServidor) {
        estadoMonitor.fallosConsecutivos += 1;
        estadoMonitor.ultimoFalloTs = ahora;
        estadoMonitor.ultimoError = `Status: ${statusCode}`;
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
        estadoMonitor.ultimoEstado = 'CAIDO';
      } else if (estadoMonitor.latenciaAltaConsecutiva >= GOLPES_LATENCIA_ALTA) {
        estadoMonitor.ultimoEstado = 'DEGRADADO';
      } else if (estadoMonitor.fallosConsecutivos === 0) {
        estadoMonitor.ultimoEstado = 'ARRIBA';
      } else {
        estadoMonitor.ultimoEstado = 'DEGRADADO';
      }

      if (estadoAnterior !== estadoMonitor.ultimoEstado) {
        const detalle = `API: ${nombre} (${uuid})\nURL: ${url}\nEstado: ${estadoAnterior} → ${estadoMonitor.ultimoEstado}\nLatencia: ${latenciaMs}ms\nTs: ${new Date(ahora).toISOString()}`;

        if (estadoMonitor.ultimoEstado === 'CAIDO') {
          await enviarAlertaCorreo(`[API-GW] ${nombre} CAIDO`, detalle);
        } else if (estadoMonitor.ultimoEstado === 'DEGRADADO') {
          await enviarAlertaCorreo(`[API-GW] ${nombre} DEGRADADO`, detalle);
        } else if (
          estadoMonitor.ultimoEstado === 'ARRIBA' &&
          ALERTAR_RECUPERACION &&
          (estadoAnterior === 'CAIDO' || estadoAnterior === 'DEGRADADO')
        ) {
          await enviarAlertaCorreo(`[API-GW] ${nombre} RECUPERADO`, detalle);
        }
      }
    } catch (err) {
      estadoMonitor.ultimaLatenciaMs = null;
      estadoMonitor.ultimoFalloTs = ahora;
      estadoMonitor.fallosConsecutivos += 1;
      estadoMonitor.ultimoError = err?.message || String(err);

      const estadoAnterior = estadoMonitor.ultimoEstado;
      estadoMonitor.ultimoEstado = estadoMonitor.fallosConsecutivos >= GOLPES_FALLO ? 'CAIDO' : 'DEGRADADO';

      if (estadoAnterior !== estadoMonitor.ultimoEstado && estadoMonitor.ultimoEstado === 'CAIDO') {
        const detalle = `API: ${nombre} (${uuid})\nURL: ${url}\nError: ${estadoMonitor.ultimoError}\nTs: ${new Date(ahora).toISOString()}`;
        await enviarAlertaCorreo(`[API-GW] ${nombre} CAIDO`, detalle);
      }
    }
  }

  // Iniciar chequeo periódico
  setTimeout(() => {
    verificarUnaVez().catch((e) => console.error(`[${nombre}] Healthcheck falló:`, e));
    setInterval(() => {
      verificarUnaVez().catch((e) => console.error(`[${nombre}] Healthcheck falló:`, e));
    }, INTERVALO_HEALTHCHECK_MS);
  }, 500);

  return {
    obtenerEstado: () => ({ ...estadoMonitor, ts: Date.now() }),
  };
}

// Inicia el sistema de monitoreo para múltiples APIs.
function iniciarMonitorMultiplesAPIs(app, apisConfig = {}) {
  if (!app) throw new Error('iniciarMonitorMultiplesAPIs requiere una instancia de Express (app).');

  const { transportadorCorreo, DESDE_SMTP, ALERTA_PARA } = crearTransportadorCorreo();
  const monitores = {};

  // Crear monitor para cada API activa
  Object.entries(apisConfig).forEach(([uuid, config]) => {
    if (config.activa) {
      const alertaParaApi = String(config.email_notificacion || '').trim() || ALERTA_PARA;
      monitores[uuid] = crearMonitorAPI({
        uuid,
        nombre: config.nombre,
        url: config.url,
        transportadorCorreo,
        DESDE_SMTP,
        ALERTA_PARA_API: alertaParaApi,
      });
      console.log(`✓ Monitor iniciado: ${config.nombre} (${uuid})`);
    }
  });

  // Endpoint: Estado individual por UUID
  app.get('/gateway/salud/:uuid', (req, res) => {
    const { uuid } = req.params;
    const monitor = monitores[uuid];
    
    if (!monitor) {
      return res.status(404).json({ error: 'API no encontrada o sin monitoreo' });
    }
    
    res.json(monitor.obtenerEstado());
  });

  // Endpoint: Estado global de todas las APIs
  app.get('/gateway/salud-global', (_req, res) => {
    const estadoGlobal = {
      ts: Date.now(),
      totalAPIs: Object.keys(monitores).length,
      resumen: {
        arriba: 0,
        CAIDO: 0,
        degradado: 0,
        desconocido: 0,
      },
      apis: {},
    };

    Object.entries(monitores).forEach(([uuid, monitor]) => {
      const estado = monitor.obtenerEstado();
      estadoGlobal.apis[uuid] = estado;
      
      const estadoKey = estado.ultimoEstado.toLowerCase();
      if (estadoGlobal.resumen[estadoKey] !== undefined) {
        estadoGlobal.resumen[estadoKey]++;
      }
    });

    res.json(estadoGlobal);
  });

  return {
    obtenerMonitor: (uuid) => monitores[uuid],
    obtenerTodos: () => Object.entries(monitores).map(([uuid, m]) => ({ uuid, ...m.obtenerEstado() })),
  };
}

module.exports = {
  iniciarMonitorMultiplesAPIs,
  enviarAlertaSeguridad,
};
