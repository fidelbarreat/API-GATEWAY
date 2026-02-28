try {
  require('dotenv').config();
} catch (_e) {
  // dotenv es opcional
}

const { setTimeout: sleep } = require('timers/promises');

function leerNumeroEnv(nombre, porDefecto) {
  const valor = process.env[nombre];
  if (valor === undefined || valor === null || valor === '') return porDefecto;
  const n = Number(valor);
  return Number.isFinite(n) ? n : porDefecto;
}

function normalizarBase(url) {
  return String(url || '').trim().replace(/\/+$/, '');
}

function leerStringEnv(nombre, porDefecto = '') {
  const valor = process.env[nombre];
  if (valor === undefined || valor === null) return porDefecto;
  const texto = String(valor).trim();
  return texto || porDefecto;
}

function leerBooleanoEnv(nombre, porDefecto = false) {
  const valor = process.env[nombre];
  if (valor === undefined || valor === null || valor === '') return porDefecto;
  const texto = String(valor).trim().toLowerCase();
  return texto === '1' || texto === 'true' || texto === 'yes' || texto === 'on';
}

function leerJsonEnv(nombre, porDefecto = null) {
  const valor = process.env[nombre];
  if (valor === undefined || valor === null || String(valor).trim() === '') return porDefecto;
  try {
    return JSON.parse(valor);
  } catch (error) {
    throw new Error(`${nombre} no contiene JSON válido: ${error.message}`);
  }
}

function normalizarMetodo(method) {
  const metodo = String(method || 'GET').trim().toUpperCase();
  const validos = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']);
  return validos.has(metodo) ? metodo : 'GET';
}

function construirHeaders({ userAgent, contentType, extraHeaders }) {
  const headers = {
    'user-agent': userAgent,
  };

  if (contentType) {
    headers['content-type'] = contentType;
  }

  if (extraHeaders && typeof extraHeaders === 'object' && !Array.isArray(extraHeaders)) {
    for (const [key, value] of Object.entries(extraHeaders)) {
      if (value === undefined || value === null) continue;
      headers[String(key).toLowerCase()] = String(value);
    }
  }

  return headers;
}

function normalizarTextoComparacion(valor) {
  return String(valor || '')
    .normalize('NFD')
    .replace(/\p{Diacritic}/gu, '')
    .toLowerCase();
}

function detectarEscenarioPorNombre(nombreApi) {
  const nombre = normalizarTextoComparacion(nombreApi);

  if (nombre.includes('sql injection') || nombre.includes('sqli')) return 'sqli';
  if (nombre.includes('xss')) return 'xss';
  if (nombre.includes('path traversal') || nombre.includes('traversal')) return 'traversal';
  if (nombre.includes('scraping')) return 'scraping';
  if (nombre.includes('admin')) return 'admin';
  if (nombre.includes('ddos')) return 'ddos';

  return 'normal';
}

function construirPeticionEscenario({ escenario, indice }) {
  const idx = Number(indice || 1);

  switch (escenario) {
    case 'sqli': {
      const payload = encodeURIComponent('1 OR 1=1--');
      return {
        method: 'GET',
        path: `/search?q=${payload}&n=${idx}`,
        userAgent: 'Mozilla/5.0 Attack-SQLi',
        body: null,
      };
    }

    case 'xss': {
      const payload = encodeURIComponent('<script>alert(1)</script>');
      return {
        method: 'GET',
        path: `/comentarios?texto=${payload}&n=${idx}`,
        userAgent: 'Mozilla/5.0 Attack-XSS',
        body: null,
      };
    }

    case 'traversal':
      return {
        method: 'GET',
        path: `/download?file=../../etc/passwd&n=${idx}`,
        userAgent: 'Mozilla/5.0 Attack-Traversal',
        body: null,
      };

    case 'scraping':
      return {
        method: 'GET',
        path: `/catalogo?page=${idx}`,
        userAgent: 'python-requests/2.31',
        body: null,
      };

    case 'admin':
      return {
        method: 'DELETE',
        path: `/api/admin/users/${(idx % 7) + 1}`,
        userAgent: 'curl/8.4.0',
        body: null,
      };

    case 'ddos':
      return {
        method: 'GET',
        path: `/health?burst=${idx}`,
        userAgent: 'ddos-simulator/1.0',
        body: null,
      };

    case 'normal':
    default:
      return {
        method: 'GET',
        path: `/health?escenario=normal&n=${idx}`,
        userAgent: 'Mozilla/5.0 QA-Valid-Client',
        body: null,
      };
  }
}

async function requestConTimeout(url, options) {
  const { timeoutMs, method, headers, body } = options;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const inicio = Date.now();

  try {
    const response = await fetch(url, {
      method,
      signal: controller.signal,
      headers,
      body,
    });

    await response.arrayBuffer();

    return {
      ok: true,
      status: response.status,
      latencyMs: Date.now() - inicio,
    };
  } catch (error) {
    return {
      ok: false,
      error: error?.message || String(error),
      latencyMs: Date.now() - inicio,
    };
  } finally {
    clearTimeout(timer);
  }
}

async function obtenerApisDesdeGateway(gatewayBase, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(`${gatewayBase}/gateway/apis`, {
      method: 'GET',
      signal: controller.signal,
      headers: {
        'user-agent': 'api-gateway-repeat-get/2.0',
      },
    });

    if (!response.ok) {
      const body = await response.text();
      throw new Error(`GET /gateway/apis -> ${response.status} ${body.slice(0, 300)}`);
    }

    const payload = await response.json();
    if (!Array.isArray(payload?.apis)) {
      throw new Error('Respuesta de /gateway/apis sin campo apis[]');
    }

    return payload.apis
      .filter((api) => api && api.uuid)
      .map((api) => ({
        uuid: String(api.uuid),
        nombre: String(api.nombre || api.uuid),
      }));
  } finally {
    clearTimeout(timer);
  }
}

function crearStats() {
  return {
    total: 0,
    ok: 0,
    error: 0,
    latencias: [],
    porStatus: {},
  };
}

function imprimirResumen(etiqueta, stats) {
  const avg = stats.latencias.length
    ? (stats.latencias.reduce((a, b) => a + b, 0) / stats.latencias.length).toFixed(2)
    : '0.00';
  const min = stats.latencias.length ? Math.min(...stats.latencias) : 0;
  const max = stats.latencias.length ? Math.max(...stats.latencias) : 0;

  console.log(`\n[REPEAT-GET] Resumen ${etiqueta}`);
  console.log(`[REPEAT-GET] Total=${stats.total} OK=${stats.ok} Error=${stats.error}`);
  console.log(`[REPEAT-GET] Latencia avg=${avg}ms min=${min}ms max=${max}ms`);
  console.log('[REPEAT-GET] Status codes:', stats.porStatus);
}

async function ejecutarSecuencia({
  etiqueta,
  resolverRequest,
  requests,
  timeoutMs,
  intervalMs,
  jitterMs,
  contentType,
  extraHeaders,
  onTick,
  isInterrupted,
}) {
  const stats = crearStats();

  for (let i = 1; i <= requests; i++) {
    if (isInterrupted()) break;

    const spec = resolverRequest(i);
    const method = normalizarMetodo(spec.method);
    const bodyPayload = spec.body !== null && spec.body !== undefined && method !== 'GET' && method !== 'HEAD'
      ? JSON.stringify(spec.body)
      : null;

    const headers = construirHeaders({
      userAgent: spec.userAgent || 'api-gateway-repeat-get/2.0',
      contentType: bodyPayload ? contentType : '',
      extraHeaders,
    });

    const resultado = await requestConTimeout(spec.url, {
      timeoutMs,
      method,
      headers,
      body: bodyPayload,
    });

    stats.total += 1;
    stats.latencias.push(resultado.latencyMs);

    if (resultado.ok) {
      stats.ok += 1;
      const key = String(resultado.status);
      stats.porStatus[key] = (stats.porStatus[key] || 0) + 1;
      if (typeof onTick === 'function') {
        onTick({ ok: true, i, method, status: resultado.status, latencyMs: resultado.latencyMs, etiqueta });
      }
    } else {
      stats.error += 1;
      if (typeof onTick === 'function') {
        onTick({ ok: false, i, method, error: resultado.error, latencyMs: resultado.latencyMs, etiqueta });
      }
    }

    if (i < requests && !isInterrupted()) {
      const jitter = jitterMs > 0 ? Math.floor(Math.random() * (2 * jitterMs + 1)) - jitterMs : 0;
      const espera = Math.max(0, intervalMs + jitter);
      await sleep(espera);
    }
  }

  return stats;
}

async function main() {
  const objetivo = normalizarBase(process.env.REPEAT_GET_URL || process.argv[2] || '');
  const modo = leerStringEnv('REPEAT_GET_MODE', objetivo ? 'single' : 'all').toLowerCase();

  const intervalMs = Math.max(200, leerNumeroEnv('REPEAT_GET_INTERVAL_MS', 1500));
  const maxRequests = Math.max(1, leerNumeroEnv('REPEAT_GET_REQUESTS', 30));
  const requestsPerApi = Math.max(1, leerNumeroEnv('REPEAT_GET_REQUESTS_PER_API', 50));
  const timeoutMs = Math.max(500, leerNumeroEnv('REPEAT_GET_TIMEOUT_MS', 8000));
  const jitterMs = Math.max(0, leerNumeroEnv('REPEAT_GET_JITTER_MS', 150));
  const method = normalizarMetodo(leerStringEnv('REPEAT_GET_METHOD', 'GET'));
  const userAgent = leerStringEnv('REPEAT_GET_USER_AGENT', 'api-gateway-repeat-get/1.0');
  const contentType = leerStringEnv('REPEAT_GET_CONTENT_TYPE', 'application/json');
  const includeCounter = leerBooleanoEnv('REPEAT_GET_APPEND_COUNTER', false);
  const bodyJson = leerJsonEnv('REPEAT_GET_BODY_JSON', null);
  const extraHeaders = leerJsonEnv('REPEAT_GET_HEADERS_JSON', {});
  const gatewayBase = normalizarBase(
    leerStringEnv('REPEAT_GET_GATEWAY_BASE', 'https://api-gateway-test-hn9e.onrender.com')
  );
  const apiNameFilter = normalizarTextoComparacion(leerStringEnv('REPEAT_GET_API_NAME_FILTER', ''));

  let bodyPayload = null;
  if (bodyJson !== null && method !== 'GET' && method !== 'HEAD') {
    bodyPayload = JSON.stringify(bodyJson);
  }

  let interrumpido = false;
  process.on('SIGINT', () => {
    interrumpido = true;
    console.log('\n[REPEAT-GET] Interrumpido por usuario, cerrando...');
  });

  if (modo === 'single') {
    if (!objetivo) {
      console.error('[REPEAT-GET] Modo single requiere REPEAT_GET_URL o URL como argumento.');
      process.exit(1);
    }

    console.log('[REPEAT-GET] Modo single');
    console.log(`[REPEAT-GET] URL objetivo: ${objetivo}`);
    console.log(`[REPEAT-GET] Método: ${method} | User-Agent: ${userAgent}`);
    console.log(`[REPEAT-GET] Intervalo base: ${intervalMs}ms | Jitter: ±${jitterMs}ms | Requests: ${maxRequests} | Timeout: ${timeoutMs}ms`);

    const stats = await ejecutarSecuencia({
      etiqueta: 'single',
      requests: maxRequests,
      timeoutMs,
      intervalMs,
      jitterMs,
      contentType,
      extraHeaders,
      isInterrupted: () => interrumpido,
      resolverRequest: (i) => ({
        method,
        url: includeCounter
          ? `${objetivo}${objetivo.includes('?') ? '&' : '?'}n=${i}`
          : objetivo,
        userAgent,
        body: bodyJson,
      }),
      onTick: ({ ok, i, method: m, status, error, latencyMs }) => {
        if (ok) {
          console.log(`[REPEAT-GET] #${i} ${m} status=${status} latency=${latencyMs}ms`);
        } else {
          console.log(`[REPEAT-GET] #${i} ${m} error=${error} latency=${latencyMs}ms`);
        }
      },
    });

    imprimirResumen('single', stats);
    return;
  }

  console.log('[REPEAT-GET] Modo all (campaña por API)');
  console.log(`[REPEAT-GET] Gateway base: ${gatewayBase}`);
  console.log(`[REPEAT-GET] Requests por API: ${requestsPerApi}`);
  console.log(`[REPEAT-GET] Intervalo base: ${intervalMs}ms | Jitter: ±${jitterMs}ms | Timeout: ${timeoutMs}ms`);

  let apis = await obtenerApisDesdeGateway(gatewayBase, timeoutMs);
  if (apiNameFilter) {
    apis = apis.filter((api) => normalizarTextoComparacion(api.nombre).includes(apiNameFilter));
  }

  if (apis.length === 0) {
    console.log('[REPEAT-GET] No se encontraron APIs para ejecutar campaña.');
    return;
  }

  console.log(`[REPEAT-GET] APIs detectadas: ${apis.length}`);
  const globalStats = crearStats();

  for (const api of apis) {
    if (interrumpido) break;

    const escenario = detectarEscenarioPorNombre(api.nombre);
    const baseApi = `${gatewayBase}/${api.uuid}`;

    console.log(`\n[REPEAT-GET] API: ${api.nombre} (${api.uuid}) | escenario=${escenario}`);

    const statsApi = await ejecutarSecuencia({
      etiqueta: api.nombre,
      requests: requestsPerApi,
      timeoutMs,
      intervalMs,
      jitterMs,
      contentType,
      extraHeaders,
      isInterrupted: () => interrumpido,
      resolverRequest: (i) => {
        const spec = construirPeticionEscenario({ escenario, indice: i });
        return {
          method: spec.method,
          url: `${baseApi}${spec.path}`,
          userAgent: spec.userAgent,
          body: spec.body,
        };
      },
      onTick: ({ ok, i, method: m, status, error, latencyMs }) => {
        if (ok) {
          console.log(`[REPEAT-GET] [${api.uuid}] #${i} ${m} status=${status} latency=${latencyMs}ms`);
        } else {
          console.log(`[REPEAT-GET] [${api.uuid}] #${i} ${m} error=${error} latency=${latencyMs}ms`);
        }
      },
    });

    globalStats.total += statsApi.total;
    globalStats.ok += statsApi.ok;
    globalStats.error += statsApi.error;
    globalStats.latencias.push(...statsApi.latencias);
    for (const [status, cantidad] of Object.entries(statsApi.porStatus)) {
      globalStats.porStatus[status] = (globalStats.porStatus[status] || 0) + cantidad;
    }

    imprimirResumen(api.nombre, statsApi);
  }

  imprimirResumen('global campaña', globalStats);
}

main().catch((error) => {
  console.error('[REPEAT-GET] Error no controlado:', error.message);
  process.exit(1);
});
