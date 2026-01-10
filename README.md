# API-GATEWAY
Trabajo de Grado 

Diego Caceres  

Fidel Barreat

## Ejecutar

1) Instalar dependencias:

```bash
npm i
```

2) Iniciar el gateway:

```bash
npm start
```

Por defecto escucha en `http://localhost:3000` y enruta a `http://localhost:4000`.

## Endpoints

- `GET /gateway/health`: salud del gateway.
- `GET /gateway/salud-backend`: estado del health-check externo al backend.

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
```
