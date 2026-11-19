// Listen on a specific host via the HOST environment variable
var host = process.env.HOST || '0.0.0.0';
// Listen on a specific port via the PORT environment variable
var port = process.env.PORT || 8080;

// Grab the blacklist from the command-line so that we can update the blacklist without deploying
// again. CORS Anywhere is open by design, and this blacklist is not used, except for countering
// immediate abuse (e.g. denial of service). If you want to block all origins except for some,
// use originWhitelist instead.
var originBlacklist = parseEnvList(process.env.CORSANYWHERE_BLACKLIST);
var originWhitelist = parseEnvList(process.env.CORSANYWHERE_WHITELIST);
function parseEnvList(env) {
  if (!env) {
    return [];
  }
  return env.split(',');
}

// Set up rate-limiting to avoid abuse of the public CORS Anywhere server.
// CORSANYWHERE_RATELIMIT limits requests per Origin (see lib/rate-limit.js for the format).
var checkRateLimit = require('./lib/rate-limit')(process.env.CORSANYWHERE_RATELIMIT);

// CORSANYWHERE_RATELIMIT_PER_IP limits requests per client IP, on top of the per-Origin limit.
// Format: "<max requests per period> <period in minutes>", e.g. "300 1".
// Origins listed as unlimited in CORSANYWHERE_RATELIMIT are exempt here too (plain hosts only,
// /regex/ entries are not matched here).
var checkIpRateLimit = createIpRateLimit(
  process.env.CORSANYWHERE_RATELIMIT_PER_IP,
  process.env.CORSANYWHERE_RATELIMIT
);
function createIpRateLimit(config, originConfig) {
  var match = /^(\d+) (\d+)\s*$/.exec(config || '');
  if (!match || parseInt(match[2], 10) === 0) {
    return null;
  }
  var maxRequests = parseInt(match[1], 10);
  var periodInMinutes = parseInt(match[2], 10);
  var exemptHosts = ((/^\d+ \d+\s+(.+)$/.exec(originConfig || '') || [])[1] || '')
    .toLowerCase().split(/\s+/).filter(Boolean);
  var counts = new Map();
  setInterval(function () {
    counts.clear();
  }, periodInMinutes * 60000).unref();

  // Used as handleInitialRequest: returning true means the request was handled (rejected).
  return function (req, res) {
    var originHost = (req.headers.origin || '').replace(/^[\w\-]+:\/\//, '').toLowerCase();
    if (originHost && exemptHosts.indexOf(originHost) !== -1) {
      return false;
    }
    // Traffic arrives via Cloudflare -> Traefik, so the real client IP is in CF-Connecting-IP.
    var ip = req.headers['cf-connecting-ip'] || req.headers['x-real-ip'] || req.socket.remoteAddress;
    var count = (counts.get(ip) || 0) + 1;
    counts.set(ip, count);
    if (count <= maxRequests) {
      return false;
    }
    res.writeHead(429, 'Too Many Requests', {
      'access-control-allow-origin': '*',
      'retry-after': String(periodInMinutes * 60),
      'content-type': 'text/plain; charset=utf-8',
    });
    res.end('Too many requests from ' + ip + '. The limit is ' + maxRequests +
      (periodInMinutes === 1 ? ' per minute.' : ' per ' + periodInMinutes + ' minutes.'));
    return true;
  };
}

// CORSANYWHERE_CACHE_TTL: seconds to keep successful GET responses (0 turns the cache off).
// CORSANYWHERE_CACHE_MAX_MB: memory cap for all cached responses.
var cacheTtlSeconds = parseInt(process.env.CORSANYWHERE_CACHE_TTL || '60', 10);
var withCache = cacheTtlSeconds > 0 ? require('./lib/response-cache')({
  ttlSeconds: cacheTtlSeconds,
  maxEntryBytes: 5 * 1024 * 1024,
  maxTotalBytes: parseInt(process.env.CORSANYWHERE_CACHE_MAX_MB || '100', 10) * 1024 * 1024,
}) : null;

var cors_proxy = require('./lib/cors-anywhere');
var server = cors_proxy.createServer({
  originBlacklist: originBlacklist,
  originWhitelist: originWhitelist,
  requireHeader: [],
  checkRateLimit: checkRateLimit,
  handleInitialRequest: checkIpRateLimit,
  removeHeaders: [
    'cookie',
    'cookie2',
    // Strip Heroku-specific headers
    'x-request-start',
    'x-request-id',
    'via',
    'connect-time',
    'total-route-time',
    // Headers added by Cloudflare and Traefik in front of this server (the
    // per-IP rate limit above reads them first). Forwarded as-is they tell the
    // target site a Cloudflare edge IP sent the request, which firewalls such
    // as 20i StackProtect read as spoofing.
    'x-forwarded-for',
    'x-forwarded-host',
    'x-forwarded-port',
    'x-forwarded-proto',
    'x-forwarded-server',
    'x-forwarded-ssl',
    'x-real-ip',
    'true-client-ip',
    'forwarded',
    'cdn-loop',
    'cf-connecting-ip',
    'cf-connecting-ipv6',
    'cf-ipcountry',
    'cf-ray',
    'cf-visitor',
    'cf-ew-via',
    'cf-worker',
    // Browser fingerprint headers: they contradict the user agent set below.
    'sec-ch-ua',
    'sec-ch-ua-mobile',
    'sec-ch-ua-platform',
    'sec-fetch-dest',
    'sec-fetch-mode',
    'sec-fetch-site',
  ],
  setHeaders: {
    // Requests leave from a server IP, so a browser user agent makes bot
    // firewalls (e.g. 20i StackProtect) answer 403. Send the user agent the
    // mobile app sends instead: every site the app works with accepts it.
    'user-agent': process.env.CORSANYWHERE_USER_AGENT || 'Dart/3.5 (dart:io)',
  },
  redirectSameOrigin: true,
  httpProxyOptions: {
    // Do not add X-Forwarded-For, etc. headers: the target only needs to see this server.
    xfwd: false,
    proxyTimeout: 15000,
    timeout: 15000
  },
});

if (withCache) {
  // Cache hits are answered before the rate limits run: they cost the target site nothing.
  var corsHandler = server.listeners('request')[0];
  server.removeAllListeners('request');
  server.on('request', withCache(corsHandler));
}

server.listen(port, host, function () {
  console.log('Running CORS Anywhere on ' + host + ':' + port +
    (withCache ? ' (cache ' + cacheTtlSeconds + 's)' : ''));
});
