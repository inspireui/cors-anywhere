'use strict';

// Short-lived in-memory cache for proxied GET responses.
//
// The web builder sends the same requests many times while a page loads and
// reloads (one session sent 286 requests for 47 URLs in three minutes). All of
// them leave from this server's one IP, so hosts with per-IP rate limits
// (e.g. 20i) answer 429. Serving repeats from memory for a short time keeps the
// load on each site close to one request per URL.
//
// Only successful (200) proxied GET responses without credentials are cached.
// Identical requests that arrive while the first one is still in flight wait
// for it instead of going to the site as well.

// Request headers that do not change the response. Every other header is part
// of the cache key, so requests carrying different tokens never share an entry.
var IGNORED_HEADERS = [
  'host', 'connection', 'keep-alive', 'user-agent', 'origin', 'referer',
  'accept-language', 'cache-control', 'pragma', 'priority', 'dnt', 'te',
  'cookie', 'cookie2', 'via', 'forwarded', 'true-client-ip', 'cdn-loop',
  'x-request-start', 'x-request-id', 'x-real-ip',
  'x-proxy-domain', // already part of the key as the target URL
  'upgrade-insecure-requests', 'if-none-match', 'if-modified-since',
];
var IGNORED_PREFIXES = ['x-forwarded-', 'cf-', 'sec-'];

// Response headers not replayed from the cache.
var HOP_HEADERS = ['connection', 'keep-alive', 'transfer-encoding', 'content-length'];

function isIgnoredHeader(name) {
  if (IGNORED_HEADERS.indexOf(name) !== -1) {
    return true;
  }
  return IGNORED_PREFIXES.some(function (prefix) {
    return name.lastIndexOf(prefix, 0) === 0;
  });
}

module.exports = function createResponseCache(options) {
  var ttlMs = options.ttlSeconds * 1000;
  var maxEntryBytes = options.maxEntryBytes;
  var maxTotalBytes = options.maxTotalBytes;

  var entries = new Map(); // key -> {expires, statusCode, headers, body}
  var totalBytes = 0;
  var inflight = new Map(); // key -> [{req, res}] waiting for the first request

  setInterval(function () {
    var now = Date.now();
    entries.forEach(function (entry, key) {
      if (entry.expires <= now) {
        remove(key);
      }
    });
  }, Math.max(ttlMs, 1000)).unref();

  function remove(key) {
    var entry = entries.get(key);
    if (entry) {
      totalBytes -= entry.body.length;
      entries.delete(key);
    }
  }

  function store(key, entry) {
    remove(key);
    entries.set(key, entry);
    totalBytes += entry.body.length;
    // Map keeps insertion order, so the first keys are the oldest.
    var it = entries.keys();
    while (totalBytes > maxTotalBytes && entries.size > 1) {
      remove(it.next().value);
    }
  }

  function cacheKey(req) {
    if (req.method !== 'GET') {
      return null;
    }
    var headers = req.headers;
    if (headers.authorization || headers['proxy-authorization']) {
      return null;
    }
    var target = headers['x-proxy-domain'] != null ? '/' + headers['x-proxy-domain'] : req.url;
    if (!target || target === '/' || target === '/favicon.ico' || target === '/iscorsneeded') {
      return null;
    }
    var keyHeaders = Object.keys(headers).filter(function (name) {
      return !isIgnoredHeader(name);
    }).sort().map(function (name) {
      return name + ':' + headers[name];
    });
    return target + '\n' + keyHeaders.join('\n');
  }

  function serveFromCache(entry, res) {
    var headers = Object.assign({}, entry.headers);
    headers['content-length'] = entry.body.length;
    headers['age'] = String(Math.floor((Date.now() - entry.storedAt) / 1000));
    headers['x-relay-cache'] = 'HIT';
    res.writeHead(entry.statusCode, headers);
    res.end(entry.body);
  }

  function isCacheable(res) {
    if (res.statusCode !== 200 || !res.getHeader('x-final-url')) {
      return false;
    }
    var cacheControl = String(res.getHeader('cache-control') || '').toLowerCase();
    return !/no-store|private/.test(cacheControl);
  }

  // Runs `handler` for a cache miss and records what it writes to `res`.
  // Calls `done()` once the response has finished or the client went away.
  function recordResponse(key, req, res, handler, done) {
    var chunks = [];
    var size = 0;
    var tooBig = false;

    function capture(chunk, encoding) {
      if (tooBig || chunk == null || typeof chunk === 'function') {
        return;
      }
      var buffer = Buffer.isBuffer(chunk) ? chunk :
        Buffer.from(chunk, typeof encoding === 'string' ? encoding : 'utf8');
      size += buffer.length;
      if (size > maxEntryBytes) {
        tooBig = true;
        chunks = [];
      } else {
        chunks.push(buffer);
      }
    }

    var originalWrite = res.write;
    var originalEnd = res.end;
    res.write = function (chunk, encoding) {
      capture(chunk, encoding);
      return originalWrite.apply(this, arguments);
    };
    res.end = function (chunk, encoding) {
      capture(chunk, encoding);
      return originalEnd.apply(this, arguments);
    };

    var finished = false;
    res.setHeader('x-relay-cache', 'MISS');
    res.on('finish', function () {
      finished = true;
      if (!tooBig && isCacheable(res)) {
        var headers = res.getHeaders();
        HOP_HEADERS.concat('x-relay-cache').forEach(function (name) {
          delete headers[name];
        });
        var now = Date.now();
        store(key, {
          storedAt: now,
          expires: now + ttlMs,
          statusCode: res.statusCode,
          headers: headers,
          body: Buffer.concat(chunks),
        });
      }
      done();
    });
    res.on('close', function () {
      if (!finished) {
        done();
      }
    });

    handler(req, res);
  }

  // Wraps the cors-anywhere request handler.
  return function withCache(handler) {
    return function (req, res) {
      var key = cacheKey(req);
      if (key === null) {
        return handler(req, res);
      }

      var entry = entries.get(key);
      if (entry && entry.expires > Date.now()) {
        return serveFromCache(entry, res);
      }

      var waiting = inflight.get(key);
      if (waiting) {
        waiting.push({ req: req, res: res });
        return;
      }

      inflight.set(key, []);
      var released = false;
      recordResponse(key, req, res, handler, function () {
        if (released) {
          return;
        }
        released = true;
        var waiters = inflight.get(key) || [];
        inflight.delete(key);
        var stored = entries.get(key);
        waiters.forEach(function (waiter) {
          if (stored) {
            serveFromCache(stored, waiter.res);
          } else {
            handler(waiter.req, waiter.res);
          }
        });
      });
    };
  };
};
