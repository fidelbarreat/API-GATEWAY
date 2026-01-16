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
- `blacklist.js`: anti-DoS + TTL auto
- `metrics.js`: contadores y latencias
- `test-healthcheck.js`: simulador de escenarios (puerto 9999)
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

4) Acciones (terminal 3):

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
```
