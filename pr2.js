import http from "node:http";
import https from "node:https";
import crypto from "node:crypto";

const PROXY_HOST = "127.0.0.1";
const PROXY_PORT = 6005;

// Upstream
const TARGET_HOSTNAME = "vamos.com";
const TARGET_PORT = 443;

// Endpoint to watch
const REDIRECT_API_PATH = "/api/v2/test/redirect";

// Destination
const REDIRECT_BASE_URL =
  "https://test3.marziplus.com";

// Session lifetime
const REDIRECT_TTL_MS = 60_000;

// Maximum body we buffer for the trigger endpoint
const MAX_BODY_SIZE = 1 * 1024 * 1024;

// Timeouts
const UPSTREAM_TIMEOUT_MS = 30_000;
const CLIENT_TIMEOUT_MS = 120_000;

// Per-browser state
const clients = new Map();

/*
|--------------------------------------------------------------------------
| UPSTREAM HTTPS AGENT
|--------------------------------------------------------------------------
*/

const upstreamAgent = new https.Agent({
  keepAlive: true,
  keepAliveMsecs: 1_000,
  maxSockets: 200,
  maxFreeSockets: 50,
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
  let id = getClientId(req);

  if (!id) {
    id = createClientId();
  }

  let state = clients.get(id);

  if (!state) {
    state = {
      redirect: false,
      redirectUrl: null,
      createdAt: Date.now(),
      lastSeen: Date.now()
    };

    clients.set(id, state);
  } else {
    state.lastSeen = Date.now();
  }

  return id;
}

/*
|--------------------------------------------------------------------------
| CLEAN OLD CLIENT STATES
|--------------------------------------------------------------------------
*/

const cleanupTimer = setInterval(() => {
  const now = Date.now();

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
| REMOVE HOP-BY-HOP HEADERS
|--------------------------------------------------------------------------
|
| This fixes the Nginx 502 issue:
|
| "Content-Length and Transfer-Encoding headers at the same time"
|
*/

function removeHopByHopHeaders(headers) {
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

  // CRITICAL
  delete result["transfer-encoding"];

  return result;
}

/*
|--------------------------------------------------------------------------
| ADD PROXY SESSION COOKIE
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
    `proxy_client_id=${clientId}; Path=/; HttpOnly; SameSite=Lax`;

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
| BUILD UPSTREAM REQUEST HEADERS
|--------------------------------------------------------------------------
*/

function buildUpstreamHeaders(
  clientReq
) {
  const headers = {
    ...clientReq.headers,

    host: TARGET_HOSTNAME,

    /*
     * Don't let upstream compress responses.
     * This is useful because HTML may be modified.
     */
    "accept-encoding": "identity"
  };

  delete headers.connection;

  /*
   * Node will manage this.
   */
  delete headers["content-length"];

  return headers;
}

/*
|--------------------------------------------------------------------------
| REDIRECT STATUS ENDPOINT
|--------------------------------------------------------------------------
|
| Browser watcher polls this endpoint.
|
*/

function handleRedirectStatus(
  state,
  clientRes,
  clientId
) {
  const response =
    JSON.stringify({
      redirect:
        Boolean(
          state?.redirect
        ),

      url:
        state?.redirectUrl ||
        null
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
| REDIRECT SCRIPT
|--------------------------------------------------------------------------
*/

function sendRedirectScript(
  clientRes
) {
  const script = `
(function () {

  "use strict";

  async function checkRedirect() {

    try {

      const response = await fetch(
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

        console.log(
          "[Proxy] Redirecting to:",
          data.url
        );

        window.location.replace(
          data.url
        );
      }

    } catch (error) {

      /*
       * Ignore temporary failures.
       */

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
        Buffer.byteLength(script)
    }
  );

  clientRes.end(script);
}

/*
|--------------------------------------------------------------------------
| INJECT WATCHER INTO HTML
|--------------------------------------------------------------------------
*/

function injectWatcher(html) {
  const tag =
    '<script src="/__proxy_redirect.js"></script>';

  /*
   * Don't inject multiple times.
   */
  if (
    html.includes(
      "/__proxy_redirect.js"
    )
  ) {
    return html;
  }

  if (
    html.includes("</head>")
  ) {
    return html.replace(
      "</head>",
      `${tag}</head>`
    );
  }

  if (
    html.includes("</body>")
  ) {
    return html.replace(
      "</body>",
      `${tag}</body>`
    );
  }

  return tag + html;
}

/*
|--------------------------------------------------------------------------
| HTML RESPONSE
|--------------------------------------------------------------------------
*/

function handleHtmlResponse(
  upstreamRes,
  clientRes,
  clientId
) {
  const chunks = [];

  let totalSize = 0;

  upstreamRes.on(
    "data",
    chunk => {

      totalSize +=
        chunk.length;

      /*
       * Prevent excessive memory usage.
       */
      if (
        totalSize <=
        15 * 1024 * 1024
      ) {
        chunks.push(chunk);
      }
    }
  );

  upstreamRes.on(
    "end",
    () => {

      try {

        if (
          totalSize >
          15 * 1024 * 1024
        ) {

          clientRes.writeHead(
            502,
            {
              "Content-Type":
                "text/plain; charset=utf-8"
            }
          );

          clientRes.end(
            "HTML response too large"
          );

          return;
        }

        let body =
          Buffer.concat(chunks);

        let html =
          body.toString("utf8");

        /*
         * Inject watcher.
         */
        html =
          injectWatcher(html);

        body =
          Buffer.from(
            html,
            "utf8"
          );

        let headers =
          removeHopByHopHeaders(
            upstreamRes.headers
          );

        /*
         * Body changed.
         */
        delete headers[
          "content-length"
        ];

        delete headers[
          "content-encoding"
        ];

        delete headers[
          "transfer-encoding"
        ];

        headers[
          "content-length"
        ] =
          body.length;

        /*
         * Preserve proxy session.
         */
        headers =
          addProxyCookie(
            headers,
            clientId
          );

        clientRes.writeHead(
          upstreamRes.statusCode ||
            200,
          headers
        );

        clientRes.end(body);

      } catch (error) {

        console.error(
          "❌ HTML processing error:",
          error.message
        );

        if (
          !clientRes.headersSent
        ) {
          clientRes.writeHead(
            502
          );
        }

        clientRes.end(
          "Bad Gateway"
        );
      }
    }
  );

  upstreamRes.on(
    "error",
    error => {

      console.error(
        "❌ HTML response error:",
        error.message
      );

      if (
        !clientRes.headersSent
      ) {
        clientRes.writeHead(
          502
        );
      }

      clientRes.end(
        "Bad Gateway"
      );
    }
  );
}

/*
|--------------------------------------------------------------------------
| NORMAL RESPONSE
|--------------------------------------------------------------------------
*/

function handleNormalResponse(
  upstreamRes,
  clientRes,
  clientId
) {
  let headers =
    removeHopByHopHeaders(
      upstreamRes.headers
    );

  /*
   * Validate content-length.
   */
  if (
    headers["content-length"] !==
    undefined
  ) {

    const length =
      Number(
        headers["content-length"]
      );

    if (
      !Number.isFinite(length) ||
      length < 0
    ) {
      delete headers[
        "content-length"
      ];
    }
  }

  headers =
    addProxyCookie(
      headers,
      clientId
    );

  clientRes.writeHead(
    upstreamRes.statusCode ||
      200,
    headers
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

/*
|--------------------------------------------------------------------------
| FORWARD REQUEST
|--------------------------------------------------------------------------
*/

function forwardRequest(
  clientReq,
  clientRes,
  clientId,
  bufferedBody = null
) {
  const headers =
    buildUpstreamHeaders(
      clientReq
    );

  /*
   * Buffered request.
   */
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

        const contentType =
          upstreamRes.headers[
            "content-type"
          ] || "";

        /*
         * HTML
         */
        if (
          contentType
            .toLowerCase()
            .includes("text/html")
        ) {

          handleHtmlResponse(
            upstreamRes,
            clientRes,
            clientId
          );

          return;
        }

        /*
         * Everything else
         */
        handleNormalResponse(
          upstreamRes,
          clientRes,
          clientId
        );
      }
    );

  /*
   * Upstream timeout.
   */
  upstreamReq.setTimeout(
    UPSTREAM_TIMEOUT_MS,
    () => {

      console.error(
        `❌ Upstream timeout after ${UPSTREAM_TIMEOUT_MS}ms`
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
   * Buffered request body.
   */
  if (
    Buffer.isBuffer(
      bufferedBody
    )
  ) {

    upstreamReq.end(
      bufferedBody
    );

    return;
  }

  /*
   * Normal streaming.
   */
  clientReq.pipe(
    upstreamReq
  );
}

/*
|--------------------------------------------------------------------------
| REDIRECT TRIGGER
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

      chunks.push(chunk);
    }

  } catch (error) {

    console.error(
      "❌ Request body error:",
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
    Buffer.concat(chunks);

  /*
   * ========================================
   * NO BODY
   * ========================================
   *
   * IMPORTANT:
   * Forward the original request normally.
   */

  if (
    body.length === 0
  ) {

    console.log(
      "↪ Redirect endpoint has NO body"
    );

    console.log(
      "↪ Forwarding original request upstream"
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
   * Do NOT send this request upstream.
   */

  console.log("");
  console.log(
    "=========================================="
  );

  console.log(
    "🚨 REDIRECT TRIGGER"
  );

  console.log(
    `Endpoint: ${REDIRECT_API_PATH}`
  );

  console.log(
    `Body size: ${body.length} bytes`
  );

  /*
   * Log body as JSON when possible.
   */
  try {

    const json =
      JSON.parse(
        body.toString("utf8")
      );

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

  } catch {

    console.log(
      "Request body is not JSON."
    );

    console.log(
      "Raw body not displayed."
    );
  }

  /*
   * Set redirect state.
   */
  if (state) {

    state.redirect =
      true;

    state.redirectUrl =
      REDIRECT_BASE_URL;

    state.lastSeen =
      Date.now();
  }

  console.log(
    `➡ Browser redirect: ${REDIRECT_BASE_URL}`
  );

  /*
   * Return response to fetch/XHR.
   *
   * The original API request is NOT forwarded.
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
    "🛑 Original API request NOT forwarded."
  );

  console.log(
    "=========================================="
  );

  console.log("");
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

        /*
         * Get browser ID.
         */
        const clientId =
          getOrCreateClient(
            clientReq
          );

        const state =
          clients.get(
            clientId
          );

        console.log(
          `→ ${clientReq.method} ${clientReq.url}`
        );

        /*
         * ======================================
         * REDIRECT SCRIPT
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
         * ALL OTHER REQUESTS
         * ======================================
         *
         * IMPORTANT:
         *
         * We DO NOT stop proxying after the
         * redirect trigger.
         *
         * Only the trigger API itself is
         * intercepted.
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
| CLIENT ERROR
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
      `Local:    http://${PROXY_HOST}:${PROXY_PORT}`
    );

    console.log(
      `Upstream: https://${TARGET_HOSTNAME}`
    );

    console.log(
      `Trigger:  ${REDIRECT_API_PATH}`
    );

    console.log(
      `Redirect: ${REDIRECT_BASE_URL}`
    );

    console.log(
      "=========================================="
    );

    console.log("");
  }
);