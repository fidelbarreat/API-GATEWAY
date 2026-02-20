const http = require('http');

// Servidor de prueba que simula diferentes escenarios
const servidorPrueba = http.createServer((req, res) => {
  const escenario = req.url.split('?')[1] || 'normal';

  console.log(`[TEST] Escenario: ${escenario}`);

  if (escenario === 'lento') {
    // Simular latencia alta (>1500ms)
    setTimeout(() => {
      res.writeHead(200);
      res.end(JSON.stringify({ status: 'ok', latencia: 2000 }));
    }, 2000);
  } else if (escenario === 'error500') {
    // Simular error del servidor
    res.writeHead(500);
    res.end(JSON.stringify({ error: 'Internal Server Error' }));
  } else if (escenario === 'timeout') {
    // Simular timeout (no responder)
    console.log('[TEST] No enviando respuesta (timeout)');
  } else if (escenario === 'error503') {
    // Simular servicio no disponible
    res.writeHead(503);
    res.end(JSON.stringify({ error: 'Service Unavailable' }));
  } else if (escenario === 'recuperado') {
    // Escenario de recuperación después de error
    res.writeHead(200);
    res.end(JSON.stringify({ status: 'recovered', timestamp: Date.now() }));
  } else {
    // Escenario normal
    res.writeHead(200);
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
