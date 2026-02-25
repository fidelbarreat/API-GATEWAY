function normalizarIp(valor) {
  if (!valor) return null;
  const ip = String(valor).trim();
  if (!ip) return null;
  if (ip.startsWith('::ffff:')) {
    return ip.substring(7);
  }
  return ip;
}

function extraerPrimerIp(headerValue) {
  if (!headerValue) return null;
  const primerValor = String(headerValue).split(',')[0];
  return normalizarIp(primerValor);
}

function obtenerIpCliente(req) {
  const forwardedFor = extraerPrimerIp(req.headers['x-forwarded-for']);
  if (forwardedFor) return forwardedFor;

  const realIp = normalizarIp(req.headers['x-real-ip']);
  if (realIp) return realIp;

  const cfIp = normalizarIp(req.headers['cf-connecting-ip']);
  if (cfIp) return cfIp;

  const ipExpress = normalizarIp(req.ip);
  if (ipExpress) return ipExpress;

  const ipSocket = normalizarIp(req.connection?.remoteAddress || req.socket?.remoteAddress);
  if (ipSocket) return ipSocket;

  return 'unknown';
}

module.exports = { obtenerIpCliente };
