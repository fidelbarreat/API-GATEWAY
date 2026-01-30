// ai-classifier.js - Clasificador de amenazas con LLM
// Integración con OpenAI GPT para detección de DoS/DDoS, inyección SQL y scraping

const { metrics, blacklist } = require('./redis');

// Configuración
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const AI_MODEL = process.env.AI_MODEL || 'gpt-5-mini';
const AI_ENABLED = process.env.AI_ENABLED !== 'false';
const AI_TIMEOUT = Number(process.env.AI_TIMEOUT || 5000);

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
  /(--|#|;|\/\*|\*\/)/,
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

/**
 * Analiza una petición de forma rápida sin IA (heurísticas)
 * @param {Object} requestData - Datos de la petición
 * @returns {Object} Resultado del análisis rápido
 */
function quickAnalysis(requestData) {
  const { url, body, headers, method } = requestData;
  const threats = [];
  let riskScore = 0;

  // Decodificar URL para detectar ataques ofuscados
  let decodedUrl = url;
  try {
    decodedUrl = decodeURIComponent(url);
  } catch (e) {
    // Si falla el decode, usar original
  }

  // Concatenar todo para análisis
  const fullContent = `${decodedUrl} ${JSON.stringify(body || {})} ${JSON.stringify(headers || {})}`;
  
  console.log('[AI-CLASSIFIER] Analizando (decodificado):', fullContent.substring(0, 150));

  // Detectar SQL Injection
  for (const pattern of SQL_INJECTION_PATTERNS) {
    if (pattern.test(fullContent)) {
      console.log('[AI-CLASSIFIER] ✓ SQL Injection detectado por patrón:', pattern);
      threats.push('SQL_INJECTION');
      riskScore += 60; // Riesgo alto inmediato
      break;
    }
  }

  // Detectar XSS
  for (const pattern of XSS_PATTERNS) {
    if (pattern.test(fullContent)) {
      threats.push('XSS');
      riskScore += 55; // Riesgo alto inmediato
      break;
    }
  }

  // Detectar posible scraping por User-Agent
  const userAgent = headers?.['user-agent'] || '';
  for (const pattern of SCRAPING_INDICATORS.userAgents) {
    if (pattern.test(userAgent)) {
      threats.push('POTENTIAL_SCRAPER');
      riskScore += 15;
      break;
    }
  }

  // Métodos sospechosos en rutas sensibles
  if (['DELETE', 'PUT', 'PATCH'].includes(method?.toUpperCase())) {
    if (/admin|config|system|root/i.test(url)) {
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
async function classifyWithLLM(requestData) {
  if (!OPENAI_API_KEY) {
    throw new Error('OPENAI_API_KEY no configurada');
  }

  const { url, method, headers, body, ip, queryParams } = requestData;

  const prompt = `Eres un sistema de seguridad de API Gateway. Analiza la siguiente petición HTTP y clasifícala.

PETICIÓN:
- IP: ${ip}
- Método: ${method}
- URL: ${url}
- Query Params: ${JSON.stringify(queryParams || {})}
- Headers relevantes: User-Agent: ${headers?.['user-agent'] || 'N/A'}, Content-Type: ${headers?.['content-type'] || 'N/A'}
- Body (primeros 500 chars): ${JSON.stringify(body || {}).substring(0, 500)}

AMENAZAS A DETECTAR:
1. DoS/DDoS: Patrones de denegación de servicio
2. SQL Injection: Intentos de inyección SQL
3. XSS: Cross-site scripting
4. Scraping: Extracción automatizada no autorizada
5. Path Traversal: Intentos de acceso a archivos del sistema

RESPONDE SOLO en formato JSON válido:
{
  "clasificacion": "riesgo-alto" | "riesgo-medio" | "legitimo",
  "amenazas_detectadas": ["TIPO_AMENAZA"],
  "confianza": 0.0-1.0,
  "razon": "explicación breve"
}`;

  const response = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${OPENAI_API_KEY}`
    },
    body: JSON.stringify({
      model: AI_MODEL,
      messages: [
        { role: 'system', content: 'Eres un experto en ciberseguridad. Responde SOLO en JSON válido.' },
        { role: 'user', content: prompt }
      ],
      max_completion_tokens: 200
    }),
    signal: AbortSignal.timeout(AI_TIMEOUT)
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`OpenAI API error: ${response.status} - ${error}`);
  }

  const data = await response.json();
  const content = data.choices?.[0]?.message?.content || '{}';
  
  // Extraer JSON de la respuesta
  const jsonMatch = content.match(/\{[\s\S]*\}/);
  if (!jsonMatch) {
    throw new Error('Respuesta del LLM no contiene JSON válido');
  }

  return JSON.parse(jsonMatch[0]);
}

/**
 * Middleware principal de clasificación IA
 * Clasifica peticiones y ejecuta acciones según el riesgo
 */
async function aiClassifierMiddleware(req, res, next) {
  const startTime = Date.now();
  const ip = req.ip || req.connection?.remoteAddress || 'unknown';
  const uuid = req.params?.uuid || 'global';

  // Preparar datos de la petición
  const requestData = {
    ip,
    method: req.method,
    url: req.originalUrl,
    queryParams: req.query,
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
    amenazas_detectadas: [],
    confianza: 1.0,
    razon: 'Sin análisis',
    metodo: 'none'
  };

  try {
    // Paso 1: Análisis rápido (heurísticas)
    const quickResult = quickAnalysis(requestData);
    
    // Si el análisis rápido detecta riesgo alto, bloquear inmediatamente
    if (quickResult.quickClassification === RISK_THRESHOLDS.HIGH) {
      classification = {
        clasificacion: RISK_THRESHOLDS.HIGH,
        amenazas_detectadas: quickResult.threats,
        confianza: 0.85,
        razon: `Detectado por heurísticas: ${quickResult.threats.join(', ')}`,
        metodo: 'heuristic'
      };
    } 
    // Si hay indicios pero no conclusivos, usar IA
    else if (AI_ENABLED && OPENAI_API_KEY && quickResult.riskScore > 0) {
      try {
        const llmResult = await classifyWithLLM(requestData);
        classification = {
          ...llmResult,
          metodo: 'llm'
        };
      } catch (llmError) {
        console.error('[AI-CLASSIFIER] Error LLM:', llmError.message);
        // Fallback a clasificación heurística
        classification = {
          clasificacion: quickResult.quickClassification,
          amenazas_detectadas: quickResult.threats,
          confianza: 0.6,
          razon: `Fallback heurístico (LLM error): ${quickResult.threats.join(', ') || 'Sin amenazas'}`,
          metodo: 'heuristic-fallback'
        };
      }
    } 
    // Petición aparentemente limpia
    else {
      classification = {
        clasificacion: RISK_THRESHOLDS.LOW,
        amenazas_detectadas: [],
        confianza: 0.95,
        razon: 'Sin indicadores de amenaza',
        metodo: 'heuristic-clean'
      };
    }

  } catch (error) {
    console.error('[AI-CLASSIFIER] Error general:', error.message);
    classification.razon = 'Error en clasificación, permitiendo por defecto';
    classification.metodo = 'error-passthrough';
  }

  const latencyMs = Date.now() - startTime;

  // Registrar métricas
  await metrics.incr(`ai:clasificaciones:${classification.clasificacion}`);
  await metrics.incr(`ai:metodo:${classification.metodo}`);
  if (classification.amenazas_detectadas?.length > 0) {
    for (const threat of classification.amenazas_detectadas) {
      await metrics.incr(`ai:amenaza:${threat}`);
    }
  }

  // Log para debugging
  console.log(`[AI-CLASSIFIER] IP:${ip} | ${classification.clasificacion} | ${latencyMs}ms | ${classification.metodo} | ${(classification.razon || 'Sin razón').substring(0, 50)}`);

  // Ejecutar acción según clasificación
  if (classification.clasificacion === RISK_THRESHOLDS.HIGH) {
    // Bloquear IP y añadir a lista negra
    const ttl = Number(process.env.BLACKLIST_TTL_AI || 3600); // 1 hora por defecto
    await blacklist.add(ip, ttl);
    await metrics.incr(`ai:bloqueos:${uuid}`);

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

  if (classification.clasificacion === RISK_THRESHOLDS.MEDIUM) {
    // Permitir pero añadir headers de advertencia y registrar
    res.setHeader('X-Security-Risk', 'medium');
    res.setHeader('X-Security-Threats', classification.amenazas_detectadas.join(','));
    await metrics.incr(`ai:advertencias:${uuid}`);
  }

  // Adjuntar clasificación al request para uso posterior
  req.aiClassification = {
    ...classification,
    latencyMs,
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
      ai_enabled: AI_ENABLED,
      model: AI_MODEL,
      timeout_ms: AI_TIMEOUT
    }
  };
}

module.exports = {
  aiClassifierMiddleware,
  quickAnalysis,
  classifyWithLLM,
  getAIMetrics,
  RISK_THRESHOLDS
};
