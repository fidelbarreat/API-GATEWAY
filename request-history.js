const { randomUUID } = require('crypto');
const { insertarRegistrosPeticiones, insertarDiarioSincronizacion } = require('./supabase');

const INTERVALO_SINCRONIZACION_MS = Number(
  process.env.INTERVALO_SINCRONIZACION_MS
  || process.env.REQUEST_SYNC_INTERVAL_MS
  || 15000
);
const MAX_BUFFER_PETICIONES = Number(
  process.env.MAX_BUFFER_PETICIONES
  || process.env.REQUEST_BUFFER_MAX
  || 10000
);

let bufferPeticiones = [];
let temporizadorSincronizacion = null;
let enSincronizacion = false;

let totalEncoladas = 0;
let totalSincronizadas = 0;
let totalErroresSincronizacion = 0;
let ultimaSincronizacion = null;
let ultimoErrorSincronizacion = null;

function encolarRequestLog(log) {
  const registroPeticion = {
    id_peticion: randomUUID(),
    fecha_peticion: log.fecha_peticion || new Date().toISOString(),
    uuid_api: log.uuid_api || 'global',
    metodo: String(log.metodo || 'GET').toUpperCase(),
    ruta: String(log.ruta || '/'),
    codigo_estado: Number(log.codigo_estado || 0),
    latencia_ms: Number(log.latencia_ms || 0),
    ip_cliente: log.ip_cliente || null,
    agente_usuario: log.agente_usuario || null,
    clasificacion_ia: log.clasificacion_ia || null,
    amenazas_ia: Array.isArray(log.amenazas_ia) ? log.amenazas_ia : [],
    confianza_ia: typeof log.confianza_ia === 'number' ? log.confianza_ia : null,
  };

  bufferPeticiones.push(registroPeticion);
  totalEncoladas += 1;

  if (bufferPeticiones.length > MAX_BUFFER_PETICIONES) {
    const excedente = bufferPeticiones.length - MAX_BUFFER_PETICIONES;
    bufferPeticiones.splice(0, excedente);
  }
}

async function sincronizarRequestLogs(origen = 'interval') {
  if (enSincronizacion || bufferPeticiones.length === 0) {
    return;
  }

  enSincronizacion = true;
  const lotePendiente = bufferPeticiones;
  bufferPeticiones = [];

  try {
    const { insertados } = await insertarRegistrosPeticiones(lotePendiente);
    totalSincronizadas += insertados;
    ultimaSincronizacion = new Date().toISOString();
    ultimoErrorSincronizacion = null;

    try {
      await insertarDiarioSincronizacion({
        registros_intentados: lotePendiente.length,
        registros_insertados: insertados,
        estado: 'ok',
      });
    } catch (errorDiario) {
      console.error('[REQUEST-SYNC] No se pudo registrar diario OK:', errorDiario.message);
    }

    if (insertados > 0) {
      console.log(`[REQUEST-SYNC] ${insertados} reportes sincronizados (${origen})`);
    }
  } catch (error) {
    totalErroresSincronizacion += 1;
    ultimoErrorSincronizacion = error.message;
    bufferPeticiones = lotePendiente.concat(bufferPeticiones);

    if (bufferPeticiones.length > MAX_BUFFER_PETICIONES) {
      bufferPeticiones = bufferPeticiones.slice(bufferPeticiones.length - MAX_BUFFER_PETICIONES);
    }

    console.error('[REQUEST-SYNC] Error al sincronizar con Supabase:', error.message);

    try {
      await insertarDiarioSincronizacion({
        registros_intentados: lotePendiente.length,
        registros_insertados: 0,
        estado: 'error',
        mensaje_error: error.message,
      });
    } catch (errorDiario) {
      console.error('[REQUEST-SYNC] No se pudo registrar diario ERROR:', errorDiario.message);
    }
  } finally {
    enSincronizacion = false;
  }
}

function iniciarRequestHistorySync() {
  if (temporizadorSincronizacion) {
    return;
  }

  temporizadorSincronizacion = setInterval(() => {
    sincronizarRequestLogs('interval').catch((err) => {
      console.error('[REQUEST-SYNC] Error no manejado en intervalo:', err.message);
    });
  }, INTERVALO_SINCRONIZACION_MS);

  if (typeof temporizadorSincronizacion.unref === 'function') {
    temporizadorSincronizacion.unref();
  }

  console.log(`[REQUEST-SYNC] Sincronización iniciada cada ${INTERVALO_SINCRONIZACION_MS}ms`);
}

async function detenerRequestHistorySync() {
  if (temporizadorSincronizacion) {
    clearInterval(temporizadorSincronizacion);
    temporizadorSincronizacion = null;
  }

  await sincronizarRequestLogs('shutdown');
}

function obtenerEstadoRequestHistorySync() {
  return {
    tamano_buffer: bufferPeticiones.length,
    en_sincronizacion: enSincronizacion,
    total_encoladas: totalEncoladas,
    total_sincronizadas: totalSincronizadas,
    total_errores_sincronizacion: totalErroresSincronizacion,
    ultima_sincronizacion: ultimaSincronizacion,
    ultimo_error_sincronizacion: ultimoErrorSincronizacion,
    intervalo_sincronizacion_ms: INTERVALO_SINCRONIZACION_MS,
    max_buffer_peticiones: MAX_BUFFER_PETICIONES,
  };
}

module.exports = {
  encolarRequestLog,
  sincronizarRequestLogs,
  iniciarRequestHistorySync,
  detenerRequestHistorySync,
  obtenerEstadoRequestHistorySync,
};
