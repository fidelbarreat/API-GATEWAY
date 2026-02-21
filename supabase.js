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
const NIVELES_IA_VALIDOS = new Set(['NO', 'BAJO', 'ALTO']);

function normalizarUrlDestino(url) {
  return String(url || '').trim().replace(/\/+$/, '');
}

function normalizarNivelIA(nivel) {
  const nivelNormalizado = String(nivel || 'BAJO').trim().toUpperCase();
  return NIVELES_IA_VALIDOS.has(nivelNormalizado) ? nivelNormalizado : 'BAJO';
}

function mapearApi(row) {
  return {
    uuid: row.api_id,
    nombre: row.nombre,
    url: normalizarUrlDestino(row.url),
    descripcion: row.descripcion || null,
    activa: Boolean(row.activo),
    nivel_ia: normalizarNivelIA(row.nivel_ia),
  };
}

async function fetchApis() {
  if (!SUPABASE_URL || !SUPABASE_KEY) {
    throw new Error('SUPABASE_URL o SUPABASE_KEY no configuradas');
  }

  const { data, error } = await supabase
    .from('apis')
    .select('api_id,nombre,url,descripcion,activo,nivel_ia');

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
    latencia_ms: Number(log.latencia_ms),
    ip_cliente: log.ip_cliente || null,
    agente_usuario: log.agente_usuario || null,
    clasificacion_ia: log.clasificacion_ia || null,
    amenazas_ia: Array.isArray(log.amenazas_ia) ? log.amenazas_ia : [],
    confianza_ia: typeof log.confianza_ia === 'number' ? log.confianza_ia : null,
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

module.exports = { fetchApis, insertarRegistrosPeticiones, insertarDiarioSincronizacion };
