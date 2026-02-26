const { setTimeout: sleep } = require('timers/promises');

function leerNumeroEnv(nombre, porDefecto) {
  const valor = process.env[nombre];
  if (valor === undefined || valor === null || valor === '') return porDefecto;
  const n = Number(valor);
  return Number.isFinite(n) ? n : porDefecto;
}

function normalizarBase(url) {
  return String(url || '').trim();
}

async function requestConTimeout(url, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const inicio = Date.now();

  try {
    const response = await fetch(url, {
      method: 'GET',
      signal: controller.signal,
      headers: {
        'user-agent': 'api-gateway-repeat-get/1.0',
      },
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

async function main() {
  const objetivo = normalizarBase(process.env.REPEAT_GET_URL || process.argv[2] || '');
  if (!objetivo) {
    console.error('[REPEAT-GET] Debes definir REPEAT_GET_URL o pasar URL como primer argumento.');
    console.error('[REPEAT-GET] Ejemplo: node repeat-get.js https://api-gateway-test-hn9e.onrender.com/test-uuid-healthcheck/health');
    process.exit(1);
  }

  const intervalMs = Math.max(200, leerNumeroEnv('REPEAT_GET_INTERVAL_MS', 1500));
  const maxRequests = Math.max(1, leerNumeroEnv('REPEAT_GET_REQUESTS', 30));
  const timeoutMs = Math.max(500, leerNumeroEnv('REPEAT_GET_TIMEOUT_MS', 8000));
  const jitterMs = Math.max(0, leerNumeroEnv('REPEAT_GET_JITTER_MS', 150));

  let interrumpido = false;
  process.on('SIGINT', () => {
    interrumpido = true;
    console.log('\n[REPEAT-GET] Interrumpido por usuario, cerrando...');
  });

  console.log('[REPEAT-GET] Iniciando solicitudes periódicas GET');
  console.log(`[REPEAT-GET] URL objetivo: ${objetivo}`);
  console.log(`[REPEAT-GET] Intervalo base: ${intervalMs}ms | Jitter: ±${jitterMs}ms | Requests: ${maxRequests} | Timeout: ${timeoutMs}ms`);

  const stats = {
    total: 0,
    ok: 0,
    error: 0,
    latencias: [],
    porStatus: {},
  };

  for (let i = 1; i <= maxRequests; i++) {
    if (interrumpido) break;

    const r = await requestConTimeout(objetivo, timeoutMs);
    stats.total += 1;
    stats.latencias.push(r.latencyMs);

    if (r.ok) {
      stats.ok += 1;
      const key = String(r.status);
      stats.porStatus[key] = (stats.porStatus[key] || 0) + 1;
      console.log(`[REPEAT-GET] #${i} status=${r.status} latency=${r.latencyMs}ms`);
    } else {
      stats.error += 1;
      console.log(`[REPEAT-GET] #${i} error=${r.error} latency=${r.latencyMs}ms`);
    }

    if (i < maxRequests && !interrumpido) {
      const jitter = jitterMs > 0 ? Math.floor(Math.random() * (2 * jitterMs + 1)) - jitterMs : 0;
      const espera = Math.max(0, intervalMs + jitter);
      await sleep(espera);
    }
  }

  const avg = stats.latencias.length
    ? (stats.latencias.reduce((a, b) => a + b, 0) / stats.latencias.length).toFixed(2)
    : '0.00';
  const min = stats.latencias.length ? Math.min(...stats.latencias) : 0;
  const max = stats.latencias.length ? Math.max(...stats.latencias) : 0;

  console.log('\n[REPEAT-GET] Resumen');
  console.log(`[REPEAT-GET] Total=${stats.total} OK=${stats.ok} Error=${stats.error}`);
  console.log(`[REPEAT-GET] Latencia avg=${avg}ms min=${min}ms max=${max}ms`);
  console.log('[REPEAT-GET] Status codes:', stats.porStatus);
}

main().catch((error) => {
  console.error('[REPEAT-GET] Error no controlado:', error.message);
  process.exit(1);
});
