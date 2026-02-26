const http = require('http');
const { setTimeout: sleep } = require('timers/promises');

function obtenerEscenario(url) {
  try {
    const urlObj = new URL(url, 'http://localhost:9999');
    return urlObj.searchParams.get('escenario') || 'normal';
  } catch (_e) {
    return 'normal';
  }
}

function iniciarServidorPrueba() {
  const servidorPrueba = http.createServer((req, res) => {
    const escenario = obtenerEscenario(req.url);

    console.log(`[TEST] Escenario backend fake: ${escenario}`);

    if (escenario === 'lento') {
      setTimeout(() => {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ status: 'ok', latencia: 2000 }));
      }, 2000);
    } else if (escenario === 'error500') {
      res.writeHead(500, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'Internal Server Error' }));
    } else if (escenario === 'timeout') {
      console.log('[TEST] No enviando respuesta (timeout)');
    } else if (escenario === 'error503') {
      res.writeHead(503, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'Service Unavailable' }));
    } else if (escenario === 'recuperado') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ status: 'recovered', timestamp: Date.now() }));
    } else {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ status: 'ok', timestamp: Date.now() }));
    }
  });

  servidorPrueba.listen(9999, () => {
    console.log('[TEST] Servidor de prueba escuchando en puerto 9999');
    console.log('[TEST] Escenarios disponibles:');
    console.log('  - http://localhost:9999/health?escenario=normal (respuesta rápida 200)');
    console.log('  - http://localhost:9999/health?escenario=lento (latencia de 2000ms)');
    console.log('  - http://localhost:9999/health?escenario=error500 (respuesta 500)');
    console.log('  - http://localhost:9999/health?escenario=error503 (respuesta 503)');
    console.log('  - http://localhost:9999/health?escenario=timeout (sin responder)');
    console.log('  - http://localhost:9999/health?escenario=recuperado (recuperación)');
  });

  process.on('SIGINT', () => {
    console.log('[TEST] Cerrando servidor de prueba...');
    servidorPrueba.close();
    process.exit(0);
  });
}

async function requestWithTimeout(url, options = {}, timeoutMs = 10_000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, { ...options, signal: controller.signal });
    const text = await response.text();
    return {
      ok: true,
      status: response.status,
      risk: response.headers.get('x-security-risk') || '',
      threats: response.headers.get('x-security-threats') || '',
      body: text.slice(0, 180),
    };
  } catch (error) {
    return {
      ok: false,
      error: error?.message || String(error),
    };
  } finally {
    clearTimeout(timer);
  }
}

async function simularAtaques() {
  const targetBaseEnv = process.env.TEST_TARGET_BASE;
  const gatewayBase = (process.env.TEST_GATEWAY_BASE || 'http://localhost:3000').replace(/\/$/, '');
  const uuidCompat = process.env.TEST_UUID;

  const targetBase = targetBaseEnv
    ? String(targetBaseEnv).replace(/\/$/, '')
    : (uuidCompat
      ? `${gatewayBase}/${uuidCompat}`.replace(/\/$/, '')
      : gatewayBase);

  const target = (path) => `${targetBase}${path}`;

  const escenarios = [
    {
      nombre: 'Tráfico normal',
      path: '/health?escenario=normal',
      options: {
        method: 'GET',
        headers: { 'user-agent': 'Mozilla/5.0 QA-Valid-Client' },
      },
    },
    {
      nombre: 'SQL Injection por query',
      path: '/search?q=1%20OR%201=1--',
      options: {
        method: 'GET',
        headers: { 'user-agent': 'Mozilla/5.0 Attack-SQLi' },
      },
    },
    {
      nombre: 'SQL Injection por body',
      path: '/login',
      options: {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'user-agent': 'Mozilla/5.0 Attack-SQLi-Body',
        },
        body: JSON.stringify({ username: "admin' OR '1'='1", password: 'irrelevante' }),
      },
    },
    {
      nombre: 'XSS reflectivo',
      path: '/comentarios?texto=%3Cscript%3Ealert(1)%3C%2Fscript%3E',
      options: {
        method: 'GET',
        headers: { 'user-agent': 'Mozilla/5.0 Attack-XSS' },
      },
    },
    {
      nombre: 'Path traversal',
      path: '/download?file=../../etc/passwd',
      options: {
        method: 'GET',
        headers: { 'user-agent': 'Mozilla/5.0 Attack-Traversal' },
      },
    },
    {
      nombre: 'Scraping por User-Agent',
      path: '/catalogo?page=1',
      options: {
        method: 'GET',
        headers: { 'user-agent': 'python-requests/2.31' },
      },
    },
    {
      nombre: 'Acceso admin sospechoso',
      path: '/api/admin/users/1',
      options: {
        method: 'DELETE',
        headers: { 'user-agent': 'curl/8.4.0' },
      },
    },
  ];

  console.log('[ATAQUES] Iniciando batería de simulación...');
  console.log(`[ATAQUES] Target base: ${targetBase}`);
  if (!targetBaseEnv && !uuidCompat) {
    console.log('[ATAQUES] Nota: sin TEST_TARGET_BASE ni TEST_UUID, se usará raíz del gateway.');
  }

  for (const escenario of escenarios) {
    const resultado = await requestWithTimeout(target(escenario.path), escenario.options);
    if (resultado.ok) {
      console.log(`\n[ATAQUES] ${escenario.nombre}`);
      console.log(`  status=${resultado.status} risk=${resultado.risk || '-'} threats=${resultado.threats || '-'}`);
      console.log(`  body=${resultado.body || '-'}`);
    } else {
      console.log(`\n[ATAQUES] ${escenario.nombre}`);
      console.log(`  error=${resultado.error}`);
    }

    await sleep(200);
  }

  console.log('\n[ATAQUES] Simulando ráfaga tipo DDoS (35 requests rápidas)...');
  const ddosPromises = Array.from({ length: 35 }, (_, index) =>
    requestWithTimeout(
      target(`/health?burst=${index}`),
      {
        method: 'GET',
        headers: { 'user-agent': 'ddos-simulator/1.0' },
      },
      5000,
    )
  );

  const ddosResults = await Promise.all(ddosPromises);
  const resumen = ddosResults.reduce((acc, item) => {
    if (item.ok) {
      const key = String(item.status);
      acc[key] = (acc[key] || 0) + 1;
    } else {
      acc.error = (acc.error || 0) + 1;
    }
    return acc;
  }, {});

  console.log('[ATAQUES] Resultado ráfaga DDoS:', resumen);
  console.log('[ATAQUES] Fin de simulación. Revisa logs del gateway + endpoint /gateway/ai/metrics');
}

const modo = String(process.argv[2] || 'servidor').trim().toLowerCase();

if (modo === 'ataques') {
  simularAtaques()
    .then(() => process.exit(0))
    .catch((error) => {
      console.error('[ATAQUES] Error general:', error.message);
      process.exit(1);
    });
} else {
  iniciarServidorPrueba();
}
