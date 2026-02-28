const { createClient } = require('@supabase/supabase-js');

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY;

if (!SUPABASE_URL || !SUPABASE_KEY) {
  console.warn('[SUPABASE] Faltan SUPABASE_URL o SUPABASE_KEY en el entorno.');
}

const supabase = createClient(SUPABASE_URL || '', SUPABASE_KEY || '');
const TABLA_HISTORIAL_PETICIONES = process.env.SUPABASE_TABLA_HISTORIAL_PETICIONES
  || process.env.SUPABASE_REQUEST_LOGS_TABLE
  || 'historial_peticiones';
const TAMANO_LOTE_SINCRONIZACION = Number(
  process.env.TAMANO_LOTE_SINCRONIZACION
  || process.env.REQUEST_LOGS_BATCH_SIZE
  || 500
);
const TABLA_DIARIO_SINCRONIZACION = process.env.SUPABASE_TABLA_DIARIO_SINCRONIZACION
  || process.env.SUPABASE_SYNC_JOURNAL_TABLE
  || 'diario_sincronizacion';
const TABLA_CONFIGURACION = process.env.SUPABASE_TABLA_CONFIGURACION || 'configuracion';
const NIVELES_IA_VALIDOS = new Set(['NO', 'BAJO', 'ALTO']);
const CONFIG_CACHE_TTL_MS = Number(process.env.CONFIG_CACHE_TTL_MS || 10_000);
const CONFIG_REFRESH_INTERVAL_MS = Number(process.env.CONFIG_REFRESH_INTERVAL_MS || 60_000);
const DEFAULT_AI_MODEL = String(process.env.AI_MODEL || 'gpt-5-mini').trim() || 'gpt-5-mini';

const cacheConfiguracion = new Map();
let temporizadorConfig = null;
let ultimaSincronizacionConfiguracion = null;
let ultimoErrorSincronizacionConfiguracion = null;

function normalizarUrlDestino(url) {
  return String(url || '').trim().replace(/\/+$/, '');
}

function normalizarNivelIA(nivel) {
  const nivelNormalizado = String(nivel || 'BAJO').trim().toUpperCase();
  return NIVELES_IA_VALIDOS.has(nivelNormalizado) ? nivelNormalizado : 'BAJO';
}

function normalizarModeloIA(modelo) {
  const valor = String(modelo || '').trim();
  return valor || DEFAULT_AI_MODEL;
}

function normalizarAmenazaPersistida(valor) {
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

function normalizarLatenciaEntera(valor, { permitirNull = false } = {}) {
  const numero = Number(valor);
  if (!Number.isFinite(numero)) return permitirNull ? null : 0;

  const ms = Math.round(numero);
  if (ms <= 0) return permitirNull ? null : 0;
  return ms;
}

function mapearApi(row) {
  const emailNotificacion = String(row.email_notificacion || '').trim();

  return {
    uuid: row.api_id,
    nombre: row.nombre,
    url: normalizarUrlDestino(row.url),
    descripcion: row.descripcion || null,
    activa: Boolean(row.activo),
    nivel_ia: normalizarNivelIA(row.nivel_ia),
    ai_model: normalizarModeloIA(row.ai_model),
    heuristica_activada: row.heuristica_activada !== false,
    email_notificacion: emailNotificacion || null,
    service_tier_priority: row.service_tier_priority === true,
  };
}

async function fetchApis() {
  if (!SUPABASE_URL || !SUPABASE_KEY) {
    throw new Error('SUPABASE_URL o SUPABASE_KEY no configuradas');
  }

  const { data, error } = await supabase
    .from('apis')
    .select('api_id,nombre,url,descripcion,activo,nivel_ia,ai_model,heuristica_activada,email_notificacion,service_tier_priority');

  if (error) {
    throw new Error(error.message || 'Error consultando Supabase');
  }

  const apis = {};
  (data || []).forEach((row) => {
    const api = mapearApi(row);
    if (api.uuid) {
      apis[api.uuid] = {
        nombre: api.nombre,
        url: api.url,
        descripcion: api.descripcion,
        activa: api.activa,
        nivel_ia: api.nivel_ia,
        ai_model: api.ai_model,
        heuristica_activada: api.heuristica_activada,
        email_notificacion: api.email_notificacion,
        service_tier_priority: api.service_tier_priority,
      };
    }
  });

  return apis;
}

function mapearRegistroPeticion(log) {
  return {
    id_peticion: log.id_peticion,
    fecha_peticion: log.fecha_peticion,
    fecha_sincronizacion: new Date().toISOString(),
    uuid_api: log.uuid_api,
    metodo: log.metodo,
    ruta: log.ruta,
    codigo_estado: Number(log.codigo_estado),
    latencia_ms: normalizarLatenciaEntera(log.latencia_ms),
    ip_cliente: log.ip_cliente || null,
    agente_usuario: log.agente_usuario || null,
    clasificacion_ia: log.clasificacion_ia || null,
    amenazas_ia: normalizarAmenazaPersistida(log.amenazas_ia),
    confianza_ia: typeof log.confianza_ia === 'number' ? log.confianza_ia : null,
    razon_ia: log.razon_ia || null,
    nivel_ia: log.nivel_ia || null,
    heuristica_activada: log.heuristica_activada === true,
    metodo_ia: log.metodo_ia || null,
    paso_por_llm: Boolean(log.paso_por_llm),
    latencia_ia_ms: normalizarLatenciaEntera(log.latencia_ia_ms, { permitirNull: true }),
    latencia_heuristica_ms: normalizarLatenciaEntera(log.latencia_heuristica_ms),
  };
}

async function insertarRegistrosPeticiones(registros) {
  if (!Array.isArray(registros) || registros.length === 0) {
    return { insertados: 0 };
  }

  if (!SUPABASE_URL || !SUPABASE_KEY) {
    throw new Error('SUPABASE_URL o SUPABASE_KEY no configuradas');
  }

  let insertados = 0;

  for (let i = 0; i < registros.length; i += TAMANO_LOTE_SINCRONIZACION) {
    const lote = registros.slice(i, i + TAMANO_LOTE_SINCRONIZACION).map(mapearRegistroPeticion);

    const { error } = await supabase
      .from(TABLA_HISTORIAL_PETICIONES)
      .insert(lote);

    if (error) {
      throw new Error(error.message || 'Error insertando histórico de peticiones en Supabase');
    }

    insertados += lote.length;
  }

  return { insertados };
}

async function insertarDiarioSincronizacion(entrada) {
  if (!SUPABASE_URL || !SUPABASE_KEY) {
    throw new Error('SUPABASE_URL o SUPABASE_KEY no configuradas');
  }

  const payload = {
    fecha_sincronizacion: new Date().toISOString(),
    registros_intentados: Number(entrada.registros_intentados || 0),
    registros_insertados: Number(entrada.registros_insertados || 0),
    estado: entrada.estado || 'desconocido',
    mensaje_error: entrada.mensaje_error || null,
  };

  const { error } = await supabase
    .from(TABLA_DIARIO_SINCRONIZACION)
    .insert(payload);

  if (error) {
    throw new Error(error.message || 'Error registrando diario de sincronización en Supabase');
  }
}

async function obtenerValorConfiguracion(atributo) {
  if (!SUPABASE_URL || !SUPABASE_KEY) {
    throw new Error('SUPABASE_URL o SUPABASE_KEY no configuradas');
  }

  const clave = String(atributo || '').trim().toUpperCase();
  if (!clave) return null;

  const ahora = Date.now();
  const cache = cacheConfiguracion.get(clave);
  if (cache && ahora - cache.ts < CONFIG_CACHE_TTL_MS) {
    return cache.valor;
  }

  const { data, error } = await supabase
    .from(TABLA_CONFIGURACION)
    .select('atributo,valor')
    .eq('atributo', clave)
    .maybeSingle();

  if (error) {
    throw new Error(error.message || `Error consultando configuración (${clave})`);
  }

  const valor = data?.valor ?? null;
  cacheConfiguracion.set(clave, { valor, ts: ahora });
  return valor;
}

async function refrescarConfiguracionCache() {
  if (!SUPABASE_URL || !SUPABASE_KEY) {
    throw new Error('SUPABASE_URL o SUPABASE_KEY no configuradas');
  }

  const { data, error } = await supabase
    .from(TABLA_CONFIGURACION)
    .select('atributo,valor');

  if (error) {
    throw new Error(error.message || 'Error refrescando configuración');
  }

  const ahora = Date.now();
  (data || []).forEach((row) => {
    const clave = String(row.atributo || '').trim().toUpperCase();
    if (!clave) return;
    cacheConfiguracion.set(clave, { valor: row.valor ?? null, ts: ahora });
  });

  ultimaSincronizacionConfiguracion = new Date(ahora).toISOString();
  ultimoErrorSincronizacionConfiguracion = null;
}

function iniciarSincronizacionConfiguracion() {
  if (temporizadorConfig) return;

  refrescarConfiguracionCache().catch((error) => {
    ultimoErrorSincronizacionConfiguracion = error.message;
    console.error('[SUPABASE] Error en refresco inicial de configuración:', error.message);
  });

  temporizadorConfig = setInterval(() => {
    refrescarConfiguracionCache().catch((error) => {
      ultimoErrorSincronizacionConfiguracion = error.message;
      console.error('[SUPABASE] Error refrescando configuración:', error.message);
    });
  }, CONFIG_REFRESH_INTERVAL_MS);

  if (typeof temporizadorConfig.unref === 'function') {
    temporizadorConfig.unref();
  }

  console.log(`[SUPABASE] Sincronización de configuración activa cada ${CONFIG_REFRESH_INTERVAL_MS}ms`);
}

function detenerSincronizacionConfiguracion() {
  if (!temporizadorConfig) return;
  clearInterval(temporizadorConfig);
  temporizadorConfig = null;
}

async function isIpBlockingEnabled() {
  try {
    const valor = await obtenerValorConfiguracion('BLOQIP');
    return String(valor ?? '').trim() === '1';
  } catch (error) {
    console.error('[SUPABASE] Error leyendo BLOQIP, se desactiva bloqueo por seguridad de pruebas:', error.message);
    return false;
  }
}

async function obtenerEstadoBloqueoIp() {
  const valor = await obtenerValorConfiguracion('BLOQIP');
  const bloqueoIpActivo = String(valor ?? '').trim() === '1';

  return {
    atributo: 'BLOQIP',
    valor: valor ?? null,
    bloqueo_ip_activo: bloqueoIpActivo,
    ultima_sincronizacion_configuracion: ultimaSincronizacionConfiguracion,
    ultimo_error_sincronizacion_configuracion: ultimoErrorSincronizacionConfiguracion,
    config_refresh_interval_ms: CONFIG_REFRESH_INTERVAL_MS,
    config_cache_ttl_ms: CONFIG_CACHE_TTL_MS,
  };
}

module.exports = {
  fetchApis,
  insertarRegistrosPeticiones,
  insertarDiarioSincronizacion,
  obtenerValorConfiguracion,
  isIpBlockingEnabled,
  obtenerEstadoBloqueoIp,
  iniciarSincronizacionConfiguracion,
  detenerSincronizacionConfiguracion,
  refrescarConfiguracionCache,
};
