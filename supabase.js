const { createClient } = require('@supabase/supabase-js');

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY;

if (!SUPABASE_URL || !SUPABASE_KEY) {
  console.warn('[SUPABASE] Faltan SUPABASE_URL o SUPABASE_KEY en el entorno.');
}

const supabase = createClient(SUPABASE_URL || '', SUPABASE_KEY || '');

function normalizarUrlDestino(url) {
  return String(url || '').trim().replace(/\/+$/, '');
}

function mapearApi(row) {
  return {
    uuid: row.api_id,
    nombre: row.nombre,
    url: normalizarUrlDestino(row.url),
    descripcion: row.descripcion || null,
    activa: Boolean(row.activo),
  };
}

async function fetchApis() {
  if (!SUPABASE_URL || !SUPABASE_KEY) {
    throw new Error('SUPABASE_URL o SUPABASE_KEY no configuradas');
  }

  const { data, error } = await supabase
    .from('apis')
    .select('api_id,nombre,url,descripcion,activo');

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
      };
    }
  });

  return apis;
}

module.exports = { fetchApis };
