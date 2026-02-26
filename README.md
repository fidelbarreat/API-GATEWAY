# API-GATEWAY
Trabajo de Grado 

Diego Caceres  

Fidel Barreat

## Stack Técnico
- Node.js 20 + Express
- http-proxy-middleware (routing)
- ioredis (Redis Cloud)
- nodemailer (alertas)
- test-healthcheck.js (simulador de escenarios)

## Archivos Principales 
- `gateway.js`: servidor Express + proxies dinámicos
- `monitor.js`: health-check + alertas SMTP
- `redis.js`: conexión y helpers Redis
- `supabase.js`: lectura de APIs + escritura de histórico
- `blacklist.js`: anti-DoS + TTL auto
- `metrics.js`: contadores y latencias
- `request-history.js`: buffer en memoria + sincronización por lotes a Supabase
- `test-healthcheck.js`: simulador de escenarios (puerto 9999) y batería de ataques contra gateway
- `db.json`: catalogo de APIs (UUID, URL, activa)

## Ejecutar

1) Instalar dependencias:

```bash
npm i
```

2) Backend fake (simula caidas, lentitud, etc...) (terminal 1):

```bash
node test-healthcheck.js
```

3) Iniciar el gateway (terminal 2):

```bash
npm start
```

4) Simular ataques (terminal 3, opcional):

```bash
node test-healthcheck.js ataques
```

4.1) Generar tráfico GET periódico (sin ráfaga DDoS):

```bash
npm run repeat:get
```

Opcional por CLI:

```bash
node repeat-get.js https://api-gateway-test-hn9e.onrender.com/test-uuid-healthcheck/health
```

Variables opcionales para la simulación:

- `TEST_TARGET_BASE`: base completa a atacar (puede incluir UUID/path). Ej: `https://api-gateway-test-hn9e.onrender.com/test-uuid-healthcheck`
- `TEST_GATEWAY_BASE` (default: `http://localhost:3000`) solo para compatibilidad
- `TEST_UUID` (opcional, legado) solo si no defines `TEST_TARGET_BASE`

Variables para `repeat-get.js`:

- `REPEAT_GET_URL`: URL completa objetivo para GET periódico.
- `REPEAT_GET_INTERVAL_MS`: intervalo base entre requests (default `1500`).
- `REPEAT_GET_JITTER_MS`: variación aleatoria para evitar patrón fijo (default `150`).
- `REPEAT_GET_REQUESTS`: cantidad total de requests (default `30`).
- `REPEAT_GET_TIMEOUT_MS`: timeout por request (default `8000`).

### Checklist rápido (end-to-end)

1. Levantar backend fake (`node test-healthcheck.js`) y gateway (`npm start`).
2. Confirmar gateway arriba en `GET /gateway/health`.
3. Ejecutar `node test-healthcheck.js ataques`.
4. Verificar en consola del gateway eventos `riesgo-medio/alto` y bloqueos DoS/IA.
5. Confirmar correos de alerta (asunto `[API-GW][SECURITY]...`).
6. Revisar métricas en `GET /gateway/ai/metrics` y `GET /gateway/metrics`.
7. Si una IP quedó bloqueada de pruebas, desbloquear con `DELETE /gateway/blacklist/{ip}`.

5) Acciones (terminal 4):

```bash
curl localhost:3000/gateway/apis #Ver APIs
```

```bash
curl localhost:3000/gateway/blacklist #Ver IPs bloqueadas
```

```bash
for i in {1..22}; do curl -s localhost:3000/test-uuid-healthcheck/health > /dev/null; done #Superar umbral DoS
```

```bash
curl localhost:3000/gateway/metrics #Ver métricas del día
```

```bash
curl localhost:3000/test-uuid-healthcheck/health #Request bloqueada
```

```bash
curl -X DELETE localhost:3000/gateway/blacklist/{ip} #Desbloquear IP
```

## Endpoints

- `GET /gateway/health`: salud del gateway
- `GET /gateway/apis`: Listar APIs registradas
- `GET /gateway/salud/{UUID}`: Health de una API
- `GET /gateway/salud-global`: Health de todas las APIs
- `GET /gateway/blacklist`: IPs bloqueadas (TTL dinamico)
- `DELETE /gateway/blacklist/{ip}`: Desbloquear IP
- `GET /gateway/metrics`: Metricas del día (requests, bloqueos, errores)
- `GET /gateway/metrics/{UUID}/latency`: Latencias (últimas 100)

## Nivel IA por API (`nivel_ia`)

La configuración de IA se define por cada registro en la tabla `apis` con la columna `nivel_ia`.

Valores soportados:

- `NO`: desactiva análisis IA para esa API
- `BAJO`: IA clasifica y marca warnings, pero no bloquea
- `ALTO`: IA clasifica y puede bloquear en `riesgo-alto` (comportamiento actual)

Columna opcional por API en `apis`:

- `service_tier_priority` (`boolean`, default `false`): cuando está en `true`, el gateway solicita al LLM `service_tier: "priority"`.
  - Si la API rechaza ese parámetro, el gateway hace fallback automático al tier estándar para no interrumpir clasificación.

Script SQL para crear la columna:

- `supabase_add_service_tier_priority.sql`

Si `nivel_ia` no existe o viene inválido, el gateway usa `BAJO` por defecto.

## Heurística por API (`heuristica_activada`)

La tabla `apis` también soporta la columna booleana `heuristica_activada` (default `true`):

- `true`: aplica clasificación/bloqueo heurístico antes de IA.
- `false`: omite heurística y permite evaluar rendimiento bruto de IA.

Orden de decisión:

1. Si `heuristica_activada=true`, se ejecuta heurística (y puede bloquear en riesgo alto).
2. Luego se evalúa `nivel_ia`:
  - `NO`: se conserva resultado de heurística (sin llamar LLM).
  - `BAJO`/`ALTO`: se llama al LLM y se actúa según clasificación y nivel.

## Correo por API (`email_notificacion`)

La tabla `apis` soporta la columna `email_notificacion` para definir destinatario por API.

- Si una API tiene `email_notificacion`, todas sus alertas (health-check y seguridad) se envían a ese correo.
- Si no lo tiene, se usa el fallback global `ALERTA_PARA`.

Para crear la columna en Supabase:

- `supabase_add_email_notificacion.sql`

## Configuración dinámica de bloqueo IP (`configuracion.BLOQIP`)

La tabla `configuracion` permite activar/desactivar bloqueo real de IP sin redeploy:

- `atributo='BLOQIP'`, `valor='1'`: comportamiento normal (bloquea IP por DoS/IA).
- `atributo='BLOQIP'`, `valor='0'`: no bloquea IP, pero registra y alerta eventos como `simulada-no-bloqueada`.

Script SQL sugerido:

- `supabase_configuracion_bloqip.sql`

## Histórico de peticiones en Supabase

El gateway mantiene un diario local en memoria de cada petición proxied y lo sincroniza en lote a Supabase cada `15s` (configurable).

### Tablas

Ejecuta el script SQL en Supabase SQL Editor:

- `supabase_request_history.sql`

Este script crea:

- `historial_peticiones`: histórico de peticiones (método, ruta, latencia, estado, IP, clasificación IA)
- `diario_sincronizacion`: historial de cada sincronización (éxito/error y cantidad de registros)

Para comparar rendimiento IA vs no IA, ejecuta también:

- `supabase_historial_ia_performance.sql`
- `supabase_add_latencia_heuristica.sql`

Este script agrega en `historial_peticiones`:

- `metodo_ia`: cómo se evaluó (`disabled-by-api`, `static-skip`, `heuristic`, `llm`, etc.)
- `paso_por_llm`: `true/false` si hubo llamada al LLM
- `latencia_ia_ms`: tiempo del clasificador IA
- `latencia_heuristica_ms`: tiempo de evaluación heurística
- `nivel_ia`: nivel aplicado en esa petición (`NO`, `BAJO`, `ALTO`)

### Variables de entorno (histórico)

- `SUPABASE_TABLA_HISTORIAL_PETICIONES` (default: `historial_peticiones`)
- `SUPABASE_TABLA_DIARIO_SINCRONIZACION` (default: `diario_sincronizacion`)
- `INTERVALO_SINCRONIZACION_MS` (default: `15000`)
- `MAX_BUFFER_PETICIONES` (default: `10000`)
- `TAMANO_LOTE_SINCRONIZACION` (default: `500`)

Compatibilidad: también se aceptan los nombres anteriores en inglés (`SUPABASE_REQUEST_LOGS_TABLE`, `SUPABASE_SYNC_JOURNAL_TABLE`, `REQUEST_SYNC_INTERVAL_MS`, `REQUEST_BUFFER_MAX`, `REQUEST_LOGS_BATCH_SIZE`).

## Health-check externo (backend) + alertas por correo

El gateway realiza un health-check periódico al backend y puede enviar alertas por correo si detecta:

- Caída (timeouts / errores / status distintos al 200, 201...)
- Degradación (latencia alta)

### Variables de entorno

**Enrutamiento**

- `DESTINO`: URL del backend. Ej: `http://localhost:4000`
- `PUERTO`: puerto del gateway. Ej: `3000`

**Health-check externo**

- `URL_HEALTHCHECK_EXTERNO`: URL completa a monitorear.
- `RUTA_HEALTHCHECK_EXTERNO`: ruta a anexar a `DESTINO` si no se define `URL_HEALTHCHECK_EXTERNO`. Default: `/health`
- `INTERVALO_HEALTHCHECK_MS`: intervalo del chequeo. Default: `30000`
- `TIMEOUT_HEALTHCHECK_MS`: timeout de cada chequeo. Default: `5000`
- `UMBRAL_LATENCIA_MS`: umbral de latencia para considerar “extraño”. Default: `1500`
- `GOLPES_LATENCIA_ALTA`: cantidad de chequeos seguidos con latencia alta para marcar degradación. Default: `2`
- `GOLPES_FALLO`: cantidad de fallos seguidos para marcar caída. Default: `2`

**Alertas por correo**

- `ENFRIAMIENTO_ALERTA_MS`: cooldown entre alertas. Default: `600000` (10 min)
- `ALERTAR_RECUPERACION`: `true/false` para enviar correo al recuperar. Default: `true`
- `ALERTAS_SEGURIDAD_HABILITADAS`: habilita alertas de seguridad IA/heurística/DoS. Default: `true`
- `ENFRIAMIENTO_ALERTA_SEGURIDAD_MS`: cooldown por firma de amenaza (IP + tipo + API). Default: `120000` (2 min)

### Alertas de seguridad (IA + heurística + DoS)

Además del health-check, el monitor ahora envía correos cuando se detectan eventos maliciosos como:

- `DDOS` detectado por umbral de frecuencia en `blacklist.js`
- `SQL_INJECTION`, `XSS`, `SCRAPING`, `ACCESO_ADMIN_SOSPECHOSO` detectados por heurística/IA

Cada alerta incluye IP, UUID de API, ruta, método, amenazas detectadas, acción aplicada y evidencia.

**SMTP (correo)**

- `HOST_SMTP`
- `PUERTO_SMTP` Default: `587`
- `USUARIO_SMTP`
- `CLAVE_SMTP`
- `DESDE_SMTP` Default: `USUARIO_SMTP`
- `ALERTA_PARA`

### Ejemplo rápido (.env)

```env
DESTINO=http://localhost:4000
PUERTO=3000

RUTA_HEALTHCHECK_EXTERNO=/health
INTERVALO_HEALTHCHECK_MS=30000
TIMEOUT_HEALTHCHECK_MS=5000
UMBRAL_LATENCIA_MS=1500
GOLPES_LATENCIA_ALTA=2
GOLPES_FALLO=2
ENFRIAMIENTO_ALERTA_MS=600000
ALERTAR_RECUPERACION=true

HOST_SMTP=smtp.gmail.com
PUERTO_SMTP=587
USUARIO_SMTP=tu_correo@dominio.com
CLAVE_SMTP=tu_clave_o_app_password
DESDE_SMTP=tu_correo@dominio.com
ALERTA_PARA=destino_alertas@dominio.com

REDIS_URI=redis://default:TU_CLAVE@redis-12345.c273.us-east-1-2.ec2.cloud.redislabs.com:12345
BLACKLIST_TTL_DEFAULT=300
BLACKLIST_TTL_DOS=3600
METRICS_TTL=86400

# IA - Clasificador de amenazas
OPENAI_API_KEY=sk-xxx
AI_MODEL=gpt-5-mini
AI_ENABLED=true
AI_TIMEOUT=5000
BLACKLIST_TTL_AI=3600
```

## Clasificador de Amenazas con IA (LLM)

El gateway integra un sistema de clasificación de amenazas basado en IA que analiza cada petición y la clasifica en tres niveles de riesgo:

| Clasificación | Acción |
|---------------|--------|
| `riesgo-alto` | Bloquea IP inmediatamente y la añade a la lista negra |
| `riesgo-medio` | Permite la petición pero la marca con headers de advertencia |
| `legitimo` | Permite sin restricciones |

### Amenazas detectadas

- **SQL Injection**: Intentos de inyección SQL en URL, query params o body
- **XSS**: Cross-site scripting en cualquier parte de la petición
- **DoS/DDoS**: Patrones de denegación de servicio (combinado con contador por IP)
- **Scraping**: Detección por User-Agent y patrones de comportamiento
- **Path Traversal**: Intentos de acceso a archivos del sistema

### Arquitectura híbrida

El clasificador usa un enfoque de dos capas para optimizar latencia:

1. **Análisis heurístico (rápido)**: Patrones regex conocidos (~1-2ms)
2. **Análisis LLM (profundo)**: Solo cuando hay indicios pero no es concluyente (~200-500ms)

### Endpoints de IA

```bash
# Ver estado del clasificador IA
curl localhost:3000/gateway/ai/status

# Ver métricas de clasificación del día
curl localhost:3000/gateway/ai/metrics
```

### Variables de entorno IA

| Variable | Descripción | Default |
|----------|-------------|---------|
| `OPENAI_API_KEY` | API key de OpenAI | - |
| `AI_MODEL` | Modelo a usar | `gpt-5-mini` |
| `AI_ENABLED` | Activar/desactivar IA | `true` |
| `AI_TIMEOUT` | Timeout para llamadas LLM (ms) | `5000` |
| `BLACKLIST_TTL_AI` | TTL de bloqueo por IA (seg) | `3600`|

### Ejemplo de respuesta bloqueada

```json
{
  "error": "Petición bloqueada por sistema de seguridad IA",
  "clasificacion": "riesgo-alto",
  "amenazas": ["SQL_INJECTION"],
  "confianza": 0.85,
  "ip": "::1",
  "ttl_bloqueo": 3600,
  "mensaje": "Su IP ha sido bloqueada temporalmente..."
}
```
