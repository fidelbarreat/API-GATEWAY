// ai-classifier.js - Clasificador de amenazas con LLM
// Integración con OpenAI GPT para detección de DoS/DDoS, inyección SQL y scraping

const { metrics, blacklist } = require('./redis');
const { obtenerIpCliente } = require('./ip-utils');
const { enviarAlertaSeguridad } = require('./monitor');
const { isIpBlockingEnabled } = require('./supabase');

// Configuración
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const AI_MODEL = process.env.AI_MODEL || 'gpt-5-mini';
const AI_TIMEOUT = Number(process.env.AI_TIMEOUT || 5000);
const NIVELES_IA_VALIDOS = new Set(['NO', 'BAJO', 'ALTO']);

// Umbrales de riesgo
const RISK_THRESHOLDS = {
  HIGH: 'riesgo-alto',      // Bloquear inmediatamente
  MEDIUM: 'riesgo-medio',   // Permitir pero monitorear
  LOW: 'legitimo'           // Permitir sin restricciones
};

// Patrones comunes de ataques (para clasificación rápida sin IA)
const SQL_INJECTION_PATTERNS = [
  /(\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\b.*\b(from|into|table|database)\b)/i,
  /(\b(or|and)\b\s*\d+\s*=\s*\d+)/i,
  /(\b(or|and)\b\s*['"]\d+['"]\s*=\s*['"]\d+['"])/i,
  // Comentarios SQL solo en contexto de query (no detecta "favicon")
  /(\s'--[^\n]*$|;\s*--|['"]\s*--)/i,
  /(#\s+.*$|;\s*#)/i,
  /(\/\*.*?\*\/)/i,
  /(\bwaitfor\b\s+\bdelay\b|\bsleep\b\s*\()/i,
  /('[^']*'\s*(or|and)\s*'[^']*'\s*=\s*'[^']*')/i,
  /('\s*or\s*'.*'\s*=\s*')/i
];

const XSS_PATTERNS = [
  /<script[^>]*>[\s\S]*?<\/script>/i,
  /javascript\s*:/i,
  /on\w+\s*=\s*["']?[^"']+["']?/i,
  /<iframe[^>]*>/i
];

const SCRAPING_INDICATORS = {
  userAgents: [
    /bot/i, /crawler/i, /spider/i, /scraper/i, /curl/i, /wget/i,
    /python-requests/i, /httpx/i, /aiohttp/i, /scrapy/i
  ],
  highFrequencyThreshold: 50 // requests por minuto
};

// Recursos estáticos que nunca deben analizarse
const STATIC_EXTENSIONS = /\.(ico|png|jpg|jpeg|gif|css|js|svg|woff|woff2|ttf|eot|map|json|xml)$/i;
const STATIC_PATHS = /^\/(favicon\.ico|robots\.txt|sitemap\.xml|health|ping|\.well-known\/.*)$/i;
const CLASIFICACIONES_VALIDAS = new Set([RISK_THRESHOLDS.HIGH, RISK_THRESHOLDS.MEDIUM, RISK_THRESHOLDS.LOW]);

function normalizarClasificacion(valor) {
  const texto = String(valor || '').trim().toLowerCase();
  if (texto === 'riesgo-alto' || texto === 'alto') return RISK_THRESHOLDS.HIGH;
  if (texto === 'riesgo-medio' || texto === 'medio') return RISK_THRESHOLDS.MEDIUM;
  if (texto === 'legitimo' || texto === 'legítimo' || texto === 'bajo') return RISK_THRESHOLDS.LOW;
  return null;
}

function obtenerAmenazaPrincipalDesdeLista(amenazas) {
  if (!Array.isArray(amenazas) || amenazas.length === 0) return 'NINGUNA';

  const normalizadas = amenazas
    .map((item) => String(item || '').trim().toUpperCase())
    .filter(Boolean);

  if (normalizadas.includes('SQL_INJECTION') || normalizadas.includes('SQLI')) return 'SQL_INJECTION';
  if (normalizadas.includes('XSS')) return 'XSS';
  if (normalizadas.includes('PATH_TRAVERSAL') || normalizadas.includes('PATH TRAVERSAL')) return 'PATH_TRAVERSAL';
  if (normalizadas.includes('RCE')) return 'RCE';
  if (normalizadas.includes('POTENTIAL_SCRAPER') || normalizadas.includes('SCRAPING')) return 'SCRAPING';
  if (normalizadas.includes('SUSPICIOUS_ADMIN_ACCESS')) return 'SUSPICIOUS_ADMIN_ACCESS';
  if (normalizadas.includes('ANOMALIA_HEADERS')) return 'ANOMALIA_HEADERS';

  return normalizadas[0] || 'NINGUNA';
}

function normalizarAmenazaTexto(amenaza, fallback = 'NINGUNA') {
  const respaldo = String(fallback || 'NINGUNA').trim().toUpperCase() || 'NINGUNA';

  if (Array.isArray(amenaza)) {
    return obtenerAmenazaPrincipalDesdeLista(amenaza);
  }

  const valor = String(amenaza || '').trim();
  if (!valor) return respaldo;

  const texto = valor.toUpperCase();
  if (texto === 'NINGUNA' || texto === 'LEGITIMO' || texto === 'LEGÍTIMO') return 'NINGUNA';
  if (texto === 'SQLI') return 'SQL_INJECTION';
  if (texto === 'POTENTIAL_SCRAPER') return 'SCRAPING';

  return texto;
}

function normalizarConfianza(confianza, fallback = 0.5) {
  const valor = Number(confianza);
  if (!Number.isFinite(valor)) return fallback;
  return Math.max(0, Math.min(1, valor));
}

function normalizarResultadoLLM(resultado, fallback = {}) {
  const fallbackClasificacion = CLASIFICACIONES_VALIDAS.has(fallback?.clasificacion)
    ? fallback.clasificacion
    : RISK_THRESHOLDS.LOW;
  const fallbackConfianza = Number.isFinite(Number(fallback?.confianza))
    ? Number(fallback.confianza)
    : 0.95;

  const clasificacionNormalizada = normalizarClasificacion(resultado?.clasificacion);
  const clasificacion = clasificacionNormalizada || fallbackClasificacion;
  const amenazaDetectada = normalizarAmenazaTexto(
    resultado?.amenazas_detectadas,
    fallback?.amenazas_detectadas || 'NINGUNA'
  );
  const confianza = normalizarConfianza(resultado?.confianza, fallbackConfianza);
  const razon = String(resultado?.razon || fallback?.razon || 'Clasificación generada por LLM').trim().slice(0, 180);

  if (!CLASIFICACIONES_VALIDAS.has(clasificacion)) {
    return {
      clasificacion: fallbackClasificacion,
      amenazas_detectadas: amenazaDetectada,
      confianza,
      razon,
    };
  }

  return {
    clasificacion,
    amenazas_detectadas: amenazaDetectada,
    confianza,
    razon,
  };
}

function normalizarNivelIA(nivel) {
  const nivelNormalizado = String(nivel || 'BAJO').trim().toUpperCase();
  return NIVELES_IA_VALIDOS.has(nivelNormalizado) ? nivelNormalizado : 'BAJO';
}

function notificarAlertaSeguridadDesdeClasificacion(req, classification, meta = {}) {
  if (!classification) return;

  const amenaza = normalizarAmenazaTexto(classification.amenazas_detectadas, 'NINGUNA');
  const amenazas = amenaza !== 'NINGUNA' ? [amenaza] : [];

  const clasificacion = String(classification.clasificacion || '').toLowerCase();
  if (clasificacion !== RISK_THRESHOLDS.HIGH && clasificacion !== RISK_THRESHOLDS.MEDIUM) return;

  const uuid = req.params?.uuid || req.apiConfig?.uuid || 'global';
  const apiNombre = req.apiConfig?.nombre || 'API desconocida';
  const emailDestino = req.apiConfig?.email_notificacion || null;
  const ip = obtenerIpCliente(req);

  let tipo = 'PETICION_SOSPECHOSA';
  if (amenaza === 'SQL_INJECTION') tipo = 'SQL_INJECTION';
  else if (amenaza === 'XSS') tipo = 'XSS';
  else if (amenaza === 'SCRAPING' || amenaza === 'POTENTIAL_SCRAPER') tipo = 'SCRAPING';
  else if (amenaza === 'SUSPICIOUS_ADMIN_ACCESS') tipo = 'ACCESO_ADMIN_SOSPECHOSO';

  const nivel = clasificacion === RISK_THRESHOLDS.HIGH ? 'ALTO' : 'MEDIO';

  enviarAlertaSeguridad({
    tipo,
    nivel,
    origen: meta.origen || classification.metodo || 'ai-classifier',
    accion: meta.accion || 'permitida',
    uuid,
    apiNombre,
    emailDestino,
    ip,
    metodo: req.method,
    ruta: req.originalUrl || req.url,
    amenazas,
    confianza: classification.confianza,
    evidencia: classification.razon,
    ts: Date.now(),
  }).catch((alertError) => {
    console.error('[AI-CLASSIFIER] Error enviando alerta de seguridad:', alertError.message);
  });
}

/**
 * Analiza una petición de forma rápida sin IA (heurísticas)
 * @param {Object} requestData - Datos de la petición
 * @returns {Object} Resultado del análisis rápido
 */
function quickAnalysis(requestData) {
  const { url, body, headers, method } = requestData;

  // WHITELIST: Ignorar recursos estáticos completamente
  if (STATIC_EXTENSIONS.test(url) || STATIC_PATHS.test(url)) {
    return {
      threats: [],
      riskScore: 0,
      quickClassification: RISK_THRESHOLDS.LOW,
      skipped: true
    };
  }

  const threats = [];
  let riskScore = 0;

  // Decodificar URL para detectar ataques ofuscados
  let decodedUrl = url;
  try {
    decodedUrl = decodeURIComponent(url);
  } catch (e) {
    // Si falla el decode, usar original
  }

  // Concatenar todo para análisis (excluir headers de navegador comunes)
  const fullContent = `${decodedUrl} ${JSON.stringify(body || {})}`; // Headers removidos para evitar falsos positivos
  
  console.log('[AI-CLASSIFIER] Analizando:', decodedUrl.substring(0, 100));

  // Detectar SQL Injection
  for (const pattern of SQL_INJECTION_PATTERNS) {
    if (pattern.test(fullContent)) {
      console.log('[AI-CLASSIFIER] ✓ SQL Injection detectado por patrón:', pattern);
      threats.push('SQL_INJECTION');
      riskScore += 60;
      break;
    }
  }

  // Detectar XSS
  for (const pattern of XSS_PATTERNS) {
    if (pattern.test(fullContent)) {
      threats.push('XSS');
      riskScore += 55;
      break;
    }
  }

  // Detectar posible scraping por User-Agent (solo si no es navegador legítimo)
  const userAgent = headers?.['user-agent'] || '';
  const isBrowser = /Mozilla\/5\.0.*(Chrome|Firefox|Safari|Edge)/i.test(userAgent);
  
  if (!isBrowser) {
    for (const pattern of SCRAPING_INDICATORS.userAgents) {
      if (pattern.test(userAgent)) {
        threats.push('POTENTIAL_SCRAPER');
        riskScore += 15;
        break;
      }
    }
  }

  // Métodos sospechosos en rutas sensibles
  if (['DELETE', 'PUT', 'PATCH'].includes(method?.toUpperCase())) {
    if (/admin|config|system|root|api\/users|api\/admin/i.test(url)) {
      threats.push('SUSPICIOUS_ADMIN_ACCESS');
      riskScore += 25;
    }
  }

  return {
    threats,
    riskScore,
    quickClassification: riskScore >= 50 ? RISK_THRESHOLDS.HIGH 
                       : riskScore >= 20 ? RISK_THRESHOLDS.MEDIUM 
                       : RISK_THRESHOLDS.LOW
  };
}

/**
 * Clasifica la petición usando OpenAI GPT
 * @param {Object} requestData - Datos de la petición
 * @returns {Promise<Object>} Clasificación del LLM
 */
async function classifyWithLLM(requestData, fallbackResultado = {}) {
  if (!OPENAI_API_KEY) {
    throw new Error('OPENAI_API_KEY no configurada');
  }

  const { url, method, headers, body, ip, queryParams, serviceTierPriority, heuristicContext } = requestData;

  const bodyString = JSON.stringify(body || {});
  const finalBody = bodyString.length > 1000 
      ? `${bodyString.substring(0, 1000)}... [CONTENIDO TRUNCADO POR SEGURIDAD]` 
      : bodyString;

  const instrucciones = `Eres un Analista WAF (Web Application Firewall) experto en ciberseguridad.
        Tu objetivo es analizar una única petición HTTP y clasificarla según si contiene payloads maliciosos o intenciones de ataque basado en el contenido, headers, método y URL.

        REGLAS ESTRICTAS:
        1. Responde ÚNICAMENTE con un objeto JSON válido. Cero texto adicional, cero markdown fuera del JSON.
        2. NO analices ataques volumétricos (DoS/DDoS); asume que las capas anteriores ya los mitigaron. Céntrate en la semántica, el payload y la intención.

        CRITERIOS DE RIESGO:
        - "riesgo-alto": Ataques claros y probados. Ej: Inyección SQL evidente, XSS con payloads ejecutables, Remote Code Execution (RCE), Path Traversal (../etc/passwd), LFI/RFI.
        - "riesgo-medio": Comportamiento anómalo o herramientas sospechosas. Ej: User-Agents de escáneres (Nmap, Nikto), intentos de scraping, caracteres inusuales en campos comunes, peticiones malformadas.
        - "legitimo": Tráfico normal, sin firmas maliciosas.

        CONFIANZA: Del 0.0 al 1.0, indica qué tan seguro estás de la clasificación. Sé conservador: si dudas entre medio y alto, elige medio.

        amenazas_detectadas: Texto único con la amenaza más probable. Ej: "SQL_INJECTION", "XSS", "PATH_TRAVERSAL", "RCE", "SCRAPING", "SUSPICIOUS_ADMIN_ACCESS", "ANOMALIA_HEADERS". Si no detectas ninguna, responde "NINGUNA".
        
        FORMATO DE RESPUESTA:
        {
          "clasificacion": "riesgo-alto" | "riesgo-medio" | "legitimo",
          "amenazas_detectadas": "SQL_INJECTION" | "XSS" | "PATH_TRAVERSAL" | "SCRAPING" | "RCE" | "SUSPICIOUS_ADMIN_ACCESS" | "ANOMALIA_HEADERS" | "NINGUNA",
          "confianza": 0.0-1.0,
          "razon": "Justificación técnica de máximo 20 palabras."
        }`;

  const payloadAnalisis = {
    ip,
    metodo: method,
    ruta: url,
    query_params: queryParams || {},
    headers: {
      'user-agent': headers?.['user-agent'] || 'N/A',
      'content-type': headers?.['content-type'] || 'N/A',
      host: headers?.['host'] || 'N/A',
    },
    body_preview: finalBody,
  };

  if (heuristicContext?.heuristica_ejecutada === true) {
    payloadAnalisis.contexto_heuristico_previo = heuristicContext;
  }

  const prompt = `Analiza la siguiente petición:\n\n${JSON.stringify(payloadAnalisis, null, 2)}`;

  const basePayload = {
    model: AI_MODEL,
    messages: [
      { role: 'system', content: instrucciones },
      { role: 'user', content: prompt }
    ],
    max_completion_tokens: 200,
  };

  if (serviceTierPriority === true) {
    basePayload.service_tier = 'priority';
  }

  let latenciaSolicitudesLLMMs = 0;

  async function solicitarChat(payload) {
    const inicio = Date.now();
    try {
      return await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${OPENAI_API_KEY}`
        },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(AI_TIMEOUT)
      });
    } finally {
      latenciaSolicitudesLLMMs += Date.now() - inicio;
    }
  }

  let response = await solicitarChat({
    ...basePayload,
    response_format: {
      type: 'json_schema',
      json_schema: {
        name: 'waf_classification',
        strict: true,
        schema: {
          type: 'object',
          additionalProperties: false,
          required: ['clasificacion', 'amenazas_detectadas', 'confianza', 'razon'],
          properties: {
            clasificacion: {
              type: 'string',
              enum: ['riesgo-alto', 'riesgo-medio', 'legitimo'],
            },
            amenazas_detectadas: {
              type: 'string',
              minLength: 1,
              maxLength: 80,
            },
            confianza: {
              type: 'number',
              minimum: 0,
              maximum: 1,
            },
            razon: {
              type: 'string',
              minLength: 1,
              maxLength: 180,
            },
          },
        },
      },
    },
  });

  if (!response.ok && (response.status === 400 || response.status === 404 || response.status === 422)) {
    response = await solicitarChat(basePayload);
  }

  if (
    !response.ok
    && serviceTierPriority === true
    && (response.status === 400 || response.status === 404 || response.status === 422)
  ) {
    const payloadSinPriority = { ...basePayload };
    delete payloadSinPriority.service_tier;
    response = await solicitarChat(payloadSinPriority);
  }

  if (!response.ok) {
    const error = await response.text();
    const openAIError = new Error(`OpenAI API error: ${response.status} - ${error}`);
    openAIError.llmLatencyMs = latenciaSolicitudesLLMMs;
    throw openAIError;
  }

  const data = await response.json();
  const message = data.choices?.[0]?.message;
  const content = Array.isArray(message?.content)
    ? message.content.map((item) => item?.text || '').join('')
    : (message?.content || '{}');

  if (!content || typeof content !== 'string') {
    const llmContentError = new Error('Respuesta del LLM vacía o inválida');
    llmContentError.llmLatencyMs = latenciaSolicitudesLLMMs;
    throw llmContentError;
  }

  let parsed;
  try {
    parsed = JSON.parse(content);
  } catch (_e) {
    const jsonMatch = content.match(/\{[\s\S]*\}/);
    if (!jsonMatch) {
      const llmJsonError = new Error('Respuesta del LLM no contiene JSON válido');
      llmJsonError.llmLatencyMs = latenciaSolicitudesLLMMs;
      throw llmJsonError;
    }
    parsed = JSON.parse(jsonMatch[0]);
  }

  return {
    ...normalizarResultadoLLM(parsed, fallbackResultado),
    llmLatencyMs: latenciaSolicitudesLLMMs,
  };
}

/**
 * Middleware principal de clasificación IA
 * Clasifica peticiones y ejecuta acciones según el riesgo
 */
async function aiClassifierMiddleware(req, res, next) {
  const startTime = Date.now();
  const ip = obtenerIpCliente(req);
  const uuid = req.params?.uuid || 'global';
  const bloqueoIpActivo = await isIpBlockingEnabled();
  const nivelIAApi = normalizarNivelIA(req.apiConfig?.nivel_ia);
  const nivelIAEfectivo = nivelIAApi;
  const heuristicaActivada = req.apiConfig?.heuristica_activada !== false;
  const permiteBloqueo = nivelIAEfectivo === 'ALTO' && bloqueoIpActivo;

  // Preparar datos de la petición
  const requestData = {
    ip,
    method: req.method,
    url: req.originalUrl || req.url,
    queryParams: req.query,
    serviceTierPriority: req.apiConfig?.service_tier_priority === true,
    headers: {
      'user-agent': req.headers['user-agent'],
      'content-type': req.headers['content-type'],
      'origin': req.headers['origin'],
      'referer': req.headers['referer']
    },
    body: req.body
  };

  let classification = {
    clasificacion: RISK_THRESHOLDS.LOW,
    amenazas_detectadas: 'NINGUNA',
    confianza: 1.0,
    razon: 'Sin análisis',
    metodo: 'none',
    nivel_ia: nivelIAEfectivo,
    heuristica_activada: heuristicaActivada,
    llmLatencyMs: 0,
    heuristicLatencyMs: 0,
    paso_por_llm: false,
  };
  let heuristicContext = {
    heuristica_ejecutada: false,
    clasificacion_heuristica: 'N/A',
    amenazas_heuristica: 'NINGUNA',
    puntaje_heuristica: 0,
    razon_heuristica: 'Heurística no ejecutada',
  };

  try {
    // Paso 1: Análisis heurístico (solo si está activado por API)
    let quickResult = null;
    if (heuristicaActivada) {
      const inicioHeuristica = Date.now();
      quickResult = quickAnalysis(requestData);
      const latenciaHeuristicaMs = Math.max(1, Date.now() - inicioHeuristica);
      classification.heuristicLatencyMs = latenciaHeuristicaMs;

      if (quickResult.skipped) {
        req.aiClassification = {
          ...classification,
          metodo: 'static-skip',
          razon: 'Recurso estático, análisis omitido',
          timestamp: new Date().toISOString(),
          latencyMs: Date.now() - startTime,
          llmLatencyMs: 0,
          heuristicLatencyMs: latenciaHeuristicaMs,
          paso_por_llm: false,
        };
        return next();
      }

      classification = {
        ...classification,
        clasificacion: quickResult.quickClassification,
        amenazas_detectadas: obtenerAmenazaPrincipalDesdeLista(quickResult.threats),
        confianza: quickResult.quickClassification === RISK_THRESHOLDS.LOW ? 0.95 : 0.85,
        razon: quickResult.quickClassification === RISK_THRESHOLDS.LOW
          ? 'Sin indicadores de amenaza por heurística'
          : `Detectado por heurísticas: ${quickResult.threats.join(', ')}`,
        metodo: quickResult.quickClassification === RISK_THRESHOLDS.LOW ? 'heuristic-clean' : 'heuristic',
        heuristicLatencyMs: latenciaHeuristicaMs,
      };

      heuristicContext = {
        heuristica_ejecutada: true,
        clasificacion_heuristica: classification.clasificacion,
        amenazas_heuristica: classification.amenazas_detectadas,
        puntaje_heuristica: quickResult.riskScore,
        razon_heuristica: classification.razon,
      };

      if (classification.clasificacion === RISK_THRESHOLDS.HIGH) {
        notificarAlertaSeguridadDesdeClasificacion(req, classification, {
          origen: 'heuristica',
          accion: bloqueoIpActivo ? 'bloqueada' : 'simulada-no-bloqueada',
        });

        if (!bloqueoIpActivo) {
          try {
            await metrics.incr(`ai:bloqueos-heuristica-omitidos:${uuid}`);
          } catch (_e) {
            // Ignorar error de métricas
          }

          res.setHeader('X-Security-Risk', 'high');
          res.setHeader('X-Security-Threats', classification.amenazas_detectadas || 'NINGUNA');
          res.setHeader('X-Security-Block-Mode', 'disabled-by-BLOQIP');
          classification.metodo = 'heuristic-high-no-block';
          classification.razon = `${classification.razon} | BLOQIP=0, bloqueo omitido`;
        } else {
          const ttl = Number(process.env.BLACKLIST_TTL_AI || 3600);
          try {
            await blacklist.add(ip, ttl);
            await metrics.incr(`ai:bloqueos-heuristica:${uuid}`);
          } catch (blacklistError) {
            console.error('[AI-CLASSIFIER] Error al bloquear IP por heurística:', blacklistError.message);
          }

          return res.status(403).json({
            error: 'Petición bloqueada por sistema de seguridad heurístico',
            clasificacion: classification.clasificacion,
            amenazas: classification.amenazas_detectadas,
            confianza: classification.confianza,
            ip,
            ttl_bloqueo: ttl,
            mensaje: 'Su IP ha sido bloqueada temporalmente por heurística. Contacte al administrador si cree que es un error.'
          });
        }
      }
    } else {
      classification = {
        ...classification,
        clasificacion: RISK_THRESHOLDS.LOW,
        amenazas_detectadas: 'NINGUNA',
        confianza: 0.0,
        razon: 'Heurística desactivada para esta API',
        metodo: 'heuristic-disabled',
      };

      heuristicContext = {
        heuristica_ejecutada: false,
        clasificacion_heuristica: 'NO_APLICA',
        amenazas_heuristica: 'NINGUNA',
        puntaje_heuristica: 0,
        razon_heuristica: 'Heurística desactivada para esta API',
      };
    }

    // Paso 2: Si nivel_ia es NO, conservar resultado de heurística
    if (nivelIAEfectivo === 'NO') {
      if (classification.clasificacion === RISK_THRESHOLDS.MEDIUM) {
        res.setHeader('X-Security-Risk', 'medium');
        res.setHeader('X-Security-Threats', classification.amenazas_detectadas || 'NINGUNA');
        res.setHeader('X-Security-IA-Level', nivelIAEfectivo);
      }

      req.aiClassification = {
        ...classification,
        metodo: `${classification.metodo}-solo-heuristica`,
        razon: `${classification.razon} (nivel_ia=NO)`,
        timestamp: new Date().toISOString(),
        latencyMs: Date.now() - startTime,
        llmLatencyMs: 0,
        heuristicLatencyMs: typeof classification.heuristicLatencyMs === 'number' ? classification.heuristicLatencyMs : 0,
        paso_por_llm: false,
      };
      return next();
    }

    // Paso 3: nivel_ia BAJO/ALTO => llamar IA (sin depender de heurística)
    if (OPENAI_API_KEY) {
      try {
        const llmResult = await classifyWithLLM({
          ...requestData,
          heuristicContext,
        }, {
          clasificacion: classification.clasificacion,
          confianza: classification.confianza,
          razon: classification.razon,
        });
        classification = {
          ...classification,
          ...llmResult,
          metodo: 'llm',
          llmLatencyMs: typeof llmResult.llmLatencyMs === 'number' ? llmResult.llmLatencyMs : 0,
          paso_por_llm: true,
        };
      } catch (llmError) {
        console.error('[AI-CLASSIFIER] Error LLM:', llmError.message);
        classification = {
          ...classification,
          confianza: Math.max(classification.confianza || 0, 0.6),
          razon: `${classification.razon} | Fallback por error LLM`,
          metodo: `${classification.metodo}-fallback-llm`,
          llmLatencyMs: typeof llmError.llmLatencyMs === 'number' ? llmError.llmLatencyMs : 0,
          paso_por_llm: true,
        };
      }
    } else {
      classification = {
        ...classification,
        razon: `${classification.razon} | OPENAI_API_KEY no configurada`,
        metodo: `${classification.metodo}-sin-llm`,
      };
    }

  } catch (error) {
    console.error('[AI-CLASSIFIER] Error general:', error.message);
    classification.razon = 'Error en clasificación, permitiendo por defecto';
    classification.metodo = 'error-passthrough';
    // En caso de error, permitir pasar (fail-open para no bloquear tráfico legítimo)
    req.aiClassification = {
      ...classification,
      timestamp: new Date().toISOString(),
      latencyMs: Date.now() - startTime,
      llmLatencyMs: 0,
      heuristicLatencyMs: typeof classification.heuristicLatencyMs === 'number' ? classification.heuristicLatencyMs : 0,
      paso_por_llm: false,
    };
    return next();
  }

  const latencyMs = Date.now() - startTime;

  // Registrar métricas (no bloquear si Redis falla)
  try {
    await metrics.incr(`ai:clasificaciones:${classification.clasificacion}`);
    await metrics.incr(`ai:metodo:${classification.metodo}`);
    await metrics.incr(`ai:nivel:${nivelIAEfectivo}`);
    const amenazaPrincipal = normalizarAmenazaTexto(classification.amenazas_detectadas, 'NINGUNA');
    if (amenazaPrincipal !== 'NINGUNA') {
      await metrics.incr(`ai:amenaza:${amenazaPrincipal}`);
    }
  } catch (metricsError) {
    console.error('[AI-CLASSIFIER] Error registrando métricas:', metricsError.message);
  }

  // Log para debugging
  console.log(`[AI-CLASSIFIER] IP:${ip} | ${classification.clasificacion} | ${latencyMs}ms | ${classification.metodo} | ${(classification.razon || 'Sin razón').substring(0, 50)}`);

  // Ejecutar acción según clasificación
  if (classification.clasificacion === RISK_THRESHOLDS.HIGH && permiteBloqueo) {
    notificarAlertaSeguridadDesdeClasificacion(req, classification, {
      origen: classification.metodo || 'llm',
      accion: 'bloqueada',
    });

    // Bloquear IP y añadir a lista negra
    const ttl = Number(process.env.BLACKLIST_TTL_AI || 3600);
    try {
      await blacklist.add(ip, ttl);
      await metrics.incr(`ai:bloqueos:${uuid}`);
    } catch (blacklistError) {
      console.error('[AI-CLASSIFIER] Error al bloquear IP:', blacklistError.message);
    }

    return res.status(403).json({
      error: 'Petición bloqueada por sistema de seguridad IA',
      clasificacion: classification.clasificacion,
      amenazas: classification.amenazas_detectadas,
      confianza: classification.confianza,
      ip,
      ttl_bloqueo: ttl,
      mensaje: 'Su IP ha sido bloqueada temporalmente. Contacte al administrador si cree que es un error.'
    });
  }

  if (classification.clasificacion === RISK_THRESHOLDS.HIGH && !permiteBloqueo) {
    notificarAlertaSeguridadDesdeClasificacion(req, classification, {
      origen: classification.metodo || 'llm',
      accion: 'simulada-no-bloqueada',
    });

    try {
      await metrics.incr(`ai:bloqueos-omitidos:${uuid}`);
    } catch (_e) {
      // Ignorar error de métricas
    }

    res.setHeader('X-Security-Risk', 'high');
    res.setHeader('X-Security-Threats', classification.amenazas_detectadas || 'NINGUNA');
    res.setHeader('X-Security-IA-Level', nivelIAEfectivo);
    res.setHeader('X-Security-Block-Mode', 'disabled-by-BLOQIP');
  }

  if (classification.clasificacion === RISK_THRESHOLDS.MEDIUM) {
    notificarAlertaSeguridadDesdeClasificacion(req, classification, {
      origen: classification.metodo || 'llm',
      accion: 'warning',
    });

    // Permitir pero añadir headers de advertencia
    res.setHeader('X-Security-Risk', classification.clasificacion === RISK_THRESHOLDS.HIGH ? 'high' : 'medium');
    res.setHeader('X-Security-Threats', classification.amenazas_detectadas || 'NINGUNA');
    res.setHeader('X-Security-IA-Level', nivelIAEfectivo);
    try {
      await metrics.incr(`ai:advertencias:${uuid}`);
    } catch (e) {
      // Ignorar error de métricas
    }
  }

  // Adjuntar clasificación al request para uso posterior
  req.aiClassification = {
    ...classification,
    nivel_ia: nivelIAEfectivo,
    latencyMs,
    llmLatencyMs: typeof classification.llmLatencyMs === 'number' ? classification.llmLatencyMs : 0,
    heuristicLatencyMs: typeof classification.heuristicLatencyMs === 'number' ? classification.heuristicLatencyMs : 0,
    paso_por_llm: classification.paso_por_llm === true,
    timestamp: new Date().toISOString()
  };

  next();
}

/**
 * Endpoint para obtener métricas de IA
 */
async function getAIMetrics() {
  const day = new Date().toISOString().slice(0, 10);
  const { redis } = require('./redis');
  
  try {
    const keys = await redis.keys(`metrics:${day}:ai:*`);
    const aiMetrics = {};
    
    for (const key of keys) {
      const field = key.replace(`metrics:${day}:`, '');
      aiMetrics[field] = await redis.get(key);
    }

    return {
      day,
      metrics: aiMetrics,
      config: {
        ai_enabled_global: true,
        modo: 'por-api',
        niveles_soportados: ['NO', 'BAJO', 'ALTO'],
        model: AI_MODEL,
        timeout_ms: AI_TIMEOUT
      }
    };
  } catch (error) {
    console.error('[AI-CLASSIFIER] Error obteniendo métricas:', error.message);
    return {
      day,
      metrics: {},
      error: error.message,
      config: {
        ai_enabled_global: true,
        modo: 'por-api',
        niveles_soportados: ['NO', 'BAJO', 'ALTO'],
        model: AI_MODEL,
        timeout_ms: AI_TIMEOUT
      }
    };
  }
}

module.exports = {
  aiClassifierMiddleware,
  quickAnalysis,
  classifyWithLLM,
  getAIMetrics,
  RISK_THRESHOLDS
};