import http from "node:http";
import https from "node:https";
import { Transform } from "node:stream";

/*
|--------------------------------------------------------------------------
| CONFIGURATION
|--------------------------------------------------------------------------
*/

const PROXY_HOST = "127.0.0.1";
const PROXY_PORT = 6005;

const TARGET_HOSTNAME = "vamos.bet";
const TARGET_PORT = 443;

/*
|--------------------------------------------------------------------------
| CACHE CONFIG
|--------------------------------------------------------------------------
*/

const HTML_CACHE_TTL = 5 * 60 * 1000; // 5 minutes
const MAX_CACHE_SIZE = 10 * 1024 * 1024; // 10 MB

/*
|--------------------------------------------------------------------------
| REQUEST CONFIG
|--------------------------------------------------------------------------
*/

const UPSTREAM_TIMEOUT_MS = 30_000;
const CLIENT_TIMEOUT_MS = 120_000;

/*
|--------------------------------------------------------------------------
| HTML CACHE
|--------------------------------------------------------------------------
|
| key: request path + query string
| value: { body, headers, statusCode, createdAt }
|
|--------------------------------------------------------------------------
*/

const htmlCache = new Map();

/*
|--------------------------------------------------------------------------
| UPSTREAM HTTPS AGENT
|--------------------------------------------------------------------------
*/

const upstreamAgent = new https.Agent({
  keepAlive: true,
  keepAliveMsecs: 1_000,
  maxSockets: 300,
  maxFreeSockets: 100,
  timeout: 60_000
});

/*
|--------------------------------------------------------------------------
| HTML CACHE CLEANUP
|--------------------------------------------------------------------------
*/

const cacheCleanupTimer = setInterval(() => {
  const now = Date.now();

  for (const [key, entry] of htmlCache.entries()) {
    if (now - entry.createdAt > HTML_CACHE_TTL) {
      htmlCache.delete(key);
    }
  }
}, 30_000);

cacheCleanupTimer.unref();

/*
|--------------------------------------------------------------------------
| REMOVE HOP-BY-HOP HEADERS
|--------------------------------------------------------------------------
*/

function removeHopByHopHeaders(headers) {
  const result = { ...headers };

  const connection = result.connection;

  if (connection) {
    const connectionHeaders = connection
      .split(",")
      .map(v => v.trim().toLowerCase());

    for (const header of connectionHeaders) {
      delete result[header];
    }
  }

  delete result.connection;
  delete result["keep-alive"];
  delete result["proxy-authenticate"];
  delete result["proxy-authorization"];
  delete result.te;
  delete result.trailer;
  delete result.upgrade;
  delete result["transfer-encoding"];

  return result;
}

/*
|--------------------------------------------------------------------------
| BUILD UPSTREAM HEADERS
|--------------------------------------------------------------------------
*/

function buildUpstreamHeaders(clientReq) {
  const headers = {
    ...clientReq.headers,
    host: TARGET_HOSTNAME
  };

  delete headers.connection;
  delete headers["content-length"];

  const accept = String(clientReq.headers.accept || "").toLowerCase();

  const isHtmlRequest =
    clientReq.method === "GET" && accept.includes("text/html");

  if (isHtmlRequest) {
    headers["accept-encoding"] = "identity";
  }

  return headers;
}

/*
|--------------------------------------------------------------------------
| CACHE KEY
|--------------------------------------------------------------------------
*/

function getCacheKey(clientReq) {
  return clientReq.url;
}

/*
|--------------------------------------------------------------------------
| STREAMING HTML INJECTOR
|--------------------------------------------------------------------------
|
| Kept as a general-purpose hook in case you want to inject a real
| analytics/A-B-test snippet before </head>. Currently a no-op passthrough
| — set INJECTION_SNIPPET below if you want to use it.
|
|--------------------------------------------------------------------------
*/

const INJECTION_SNIPPET = ""; // e.g. '<script src="/analytics.js" defer></script>'

function createHtmlInjector() {
  if (!INJECTION_SNIPPET) {
    return new Transform({
      transform(chunk, encoding, callback) {
        callback(null, chunk);
      }
    });
  }

  const injection = Buffer.from(INJECTION_SNIPPET, "utf8");

  let foundHead = false;
  const KEEP_BYTES = 32;
  let carry = Buffer.alloc(0);

  return new Transform({
    transform(chunk, encoding, callback) {
      try {
        if (foundHead) {
          this.push(chunk);
          callback();
          return;
        }

        const data = carry.length > 0 ? Buffer.concat([carry, chunk]) : chunk;
        const searchable = data.toString("latin1").toLowerCase();
        const index = searchable.indexOf("</head>");

        if (index !== -1) {
          this.push(data.subarray(0, index));
          this.push(injection);
          this.push(data.subarray(index));
          foundHead = true;
          carry = Buffer.alloc(0);
          callback();
          return;
        }

        if (data.length > KEEP_BYTES) {
          const split = data.length - KEEP_BYTES;
          this.push(data.subarray(0, split));
          carry = data.subarray(split);
        } else {
          carry = data;
        }

        callback();
      } catch (error) {
        callback(error);
      }
    },

    flush(callback) {
      try {
        if (carry.length > 0) {
          this.push(carry);
        }
        callback();
      } catch (error) {
        callback(error);
      }
    }
  });
}

/*
|--------------------------------------------------------------------------
| STORE HTML CACHE
|--------------------------------------------------------------------------
*/

function storeHtmlCache(key, statusCode, headers, body) {
  if (body.length > MAX_CACHE_SIZE) {
    console.log(`⚠️ HTML too large to cache: ${body.length} bytes`);
    return;
  }

  // Don't cache pages with Set-Cookie — avoids caching session-specific HTML.
  if (headers["set-cookie"]) {
    console.log("⚠️ HTML contains Set-Cookie; not caching.");
    return;
  }

  const cleanHeaders = removeHopByHopHeaders(headers);
  delete cleanHeaders["transfer-encoding"];
  cleanHeaders["content-length"] = body.length;

  htmlCache.set(key, {
    body,
    headers: cleanHeaders,
    statusCode,
    createdAt: Date.now()
  });

  console.log(`💾 HTML cached: ${key} (${body.length} bytes)`);
}

/*
|--------------------------------------------------------------------------
| SERVE HTML CACHE
|--------------------------------------------------------------------------
*/

function serveHtmlCache(entry, clientRes, method) {
  const headers = { ...entry.headers };

  if (method === "HEAD") {
    clientRes.writeHead(entry.statusCode, headers);
    clientRes.end();
    return;
  }

  clientRes.writeHead(entry.statusCode, headers);
  clientRes.end(entry.body);
}

/*
|--------------------------------------------------------------------------
| HTML CACHE MISS / REFRESH
|--------------------------------------------------------------------------
*/

function fetchAndCacheHtml(clientReq, clientRes, cacheKey, method) {
  const headers = buildUpstreamHeaders(clientReq);
  headers["accept-encoding"] = "identity";
  delete headers["content-length"];

  const options = {
    hostname: TARGET_HOSTNAME,
    port: TARGET_PORT,
    method: "GET",
    path: clientReq.url,
    headers,
    agent: upstreamAgent,
    servername: TARGET_HOSTNAME,
    rejectUnauthorized: true
  };

  console.log(`→ CACHE MISS ${cacheKey}`);

  const upstreamReq = https.request(options, upstreamRes => {
    const statusCode = upstreamRes.statusCode || 200;
    const contentType = upstreamRes.headers["content-type"] || "";

    const cacheable =
      statusCode >= 200 &&
      statusCode < 300 &&
      contentType.toLowerCase().includes("text/html");

    if (!cacheable) {
      const responseHeaders = removeHopByHopHeaders(upstreamRes.headers);
      clientRes.writeHead(statusCode, responseHeaders);
      upstreamRes.pipe(clientRes);
      return;
    }

    if (method === "HEAD") {
      const responseHeaders = removeHopByHopHeaders(upstreamRes.headers);
      clientRes.writeHead(statusCode, responseHeaders);
      clientRes.end();
      return;
    }

    const chunks = [];
    let totalSize = 0;

    const injector = createHtmlInjector();

    injector.on("data", chunk => {
      totalSize += chunk.length;
      if (totalSize <= MAX_CACHE_SIZE) {
        chunks.push(Buffer.from(chunk));
      }
    });

    injector.on("error", error => {
      console.error("❌ HTML injector error:", error.message);
      clientRes.destroy();
    });

    injector.on("end", () => {
      const body = Buffer.concat(chunks);

      const responseHeaders = removeHopByHopHeaders(upstreamRes.headers);
      delete responseHeaders["content-length"];
      delete responseHeaders["content-encoding"];
      delete responseHeaders["transfer-encoding"];
      responseHeaders["content-length"] = body.length;

      storeHtmlCache(cacheKey, statusCode, responseHeaders, body);
    });

    const responseHeaders = removeHopByHopHeaders(upstreamRes.headers);
    delete responseHeaders["content-length"];
    delete responseHeaders["content-encoding"];
    delete responseHeaders["transfer-encoding"];

    clientRes.writeHead(statusCode, responseHeaders);

    injector.pipe(clientRes, { end: true });
    upstreamRes.pipe(injector);
  });

  upstreamReq.setTimeout(UPSTREAM_TIMEOUT_MS, () => {
    console.error(`❌ HTML upstream timeout after ${UPSTREAM_TIMEOUT_MS}ms`);
    upstreamReq.destroy(new Error("Upstream timeout"));
  });

  upstreamReq.on("error", error => {
    console.error("❌ HTML upstream error:", error.message);

    if (!clientRes.headersSent) {
      clientRes.writeHead(502, {
        "Content-Type": "text/plain; charset=utf-8",
        "Cache-Control": "no-store"
      });
      clientRes.end("Bad Gateway");
    } else {
      clientRes.destroy();
    }
  });

  upstreamReq.end();
}

/*
|--------------------------------------------------------------------------
| HANDLE HTML REQUEST
|--------------------------------------------------------------------------
*/

function handleHtmlRequest(clientReq, clientRes) {
  const cacheKey = getCacheKey(clientReq);
  const entry = htmlCache.get(cacheKey);
  const now = Date.now();

  if (entry && now - entry.createdAt < HTML_CACHE_TTL) {
    console.log(`✅ HTML CACHE HIT ${cacheKey}`);
    serveHtmlCache(entry, clientRes, clientReq.method);
    return;
  }

  if (entry) {
    console.log(`♻️ HTML CACHE EXPIRED ${cacheKey}`);
    htmlCache.delete(cacheKey);
  }

  fetchAndCacheHtml(clientReq, clientRes, cacheKey, clientReq.method);
}

/*
|--------------------------------------------------------------------------
| NORMAL FORWARD REQUEST
|--------------------------------------------------------------------------
*/

function forwardRequest(clientReq, clientRes) {
  // HTML GET/HEAD goes through cache.
  if (
    (clientReq.method === "GET" || clientReq.method === "HEAD") &&
    String(clientReq.headers.accept || "")
      .toLowerCase()
      .includes("text/html")
  ) {
    handleHtmlRequest(clientReq, clientRes);
    return;
  }

  // Normal API/static request — pass through unchanged.
  const headers = buildUpstreamHeaders(clientReq);

  const options = {
    hostname: TARGET_HOSTNAME,
    port: TARGET_PORT,
    method: clientReq.method,
    path: clientReq.url,
    headers,
    agent: upstreamAgent,
    servername: TARGET_HOSTNAME,
    rejectUnauthorized: true
  };

  console.log(
    `→ UPSTREAM ${clientReq.method} https://${TARGET_HOSTNAME}${clientReq.url}`
  );

  const upstreamReq = https.request(options, upstreamRes => {
    console.log(
      `← UPSTREAM ${upstreamRes.statusCode} ${clientReq.method} ${clientReq.url}`
    );

    const responseHeaders = removeHopByHopHeaders(upstreamRes.headers);

    clientRes.writeHead(upstreamRes.statusCode || 200, responseHeaders);

    upstreamRes.on("error", error => {
      console.error("❌ Upstream response error:", error.message);
      clientRes.destroy();
    });

    upstreamRes.pipe(clientRes);
  });

  upstreamReq.setTimeout(UPSTREAM_TIMEOUT_MS, () => {
    console.error("❌ Upstream timeout");
    upstreamReq.destroy(new Error("Upstream timeout"));
  });

  upstreamReq.on("error", error => {
    console.error("❌ Upstream error:", error.message);

    if (!clientRes.headersSent) {
      clientRes.writeHead(502, {
        "Content-Type": "text/plain; charset=utf-8"
      });
      clientRes.end("Bad Gateway");
    } else {
      clientRes.destroy();
    }
  });

  // Stream the client request body straight through, unmodified.
  clientReq.pipe(upstreamReq);
}

/*
|--------------------------------------------------------------------------
| MAIN SERVER
|--------------------------------------------------------------------------
*/

const server = http.createServer((clientReq, clientRes) => {
  clientReq.setTimeout(CLIENT_TIMEOUT_MS, () => {
    console.error("❌ Client request timeout");
    clientReq.destroy();
  });

  try {
    forwardRequest(clientReq, clientRes);
  } catch (error) {
    console.error("❌ Request handler error:", error);

    if (!clientRes.headersSent) {
      clientRes.writeHead(500, {
        "Content-Type": "text/plain; charset=utf-8"
      });
    }

    clientRes.end("Internal Server Error");
  }
});

/*
|--------------------------------------------------------------------------
| SERVER SETTINGS
|--------------------------------------------------------------------------
*/

server.requestTimeout = CLIENT_TIMEOUT_MS;
server.headersTimeout = 65_000;
server.keepAliveTimeout = 65_000;
server.maxRequestsPerSocket = 0;

/*
|--------------------------------------------------------------------------
| CLIENT / PROCESS ERRORS
|--------------------------------------------------------------------------
*/

server.on("clientError", (error, socket) => {
  console.error("❌ Client error:", error.message);

  if (socket.writable) {
    socket.end("HTTP/1.1 400 Bad Request\r\n\r\n");
  }
});

process.on("uncaughtException", error => {
  console.error("❌ uncaughtException:", error);
});

process.on("unhandledRejection", error => {
  console.error("❌ unhandledRejection:", error);
});

/*
|--------------------------------------------------------------------------
| START
|--------------------------------------------------------------------------
*/

server.listen(PROXY_PORT, PROXY_HOST, () => {
  console.log("");
  console.log("==========================================");
  console.log(" Reverse Proxy");
  console.log("==========================================");
  console.log(`Local:      http://${PROXY_HOST}:${PROXY_PORT}`);
  console.log(`Upstream:   https://${TARGET_HOSTNAME}`);
  console.log(`Cache TTL:  ${HTML_CACHE_TTL / 1000}s`);
  console.log("==========================================");
  console.log("");
});