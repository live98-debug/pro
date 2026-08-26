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
const PROXY_PUBLIC_DOMAIN = "proxytest.dash.bet";

const TARGET = {
  hostname: "dash.bet",
  protocol: "https:"
};

const REDIRECT_API_PATH = "/api/v2/test/redirect";
const REDIRECT_BASE_URL = "https://test3.dash.bet";
const REDIRECT_TTL_MS = 30_000;

// Path to your fixed curl-chrome binary wrapper
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

    const targetUrl = `${TARGET.protocol}//${TARGET.hostname}${clientReq.url}`;

    // Build execution flags for curl-impersonate
    const args = [
      "-s", "-i",
      "-X", clientReq.method,
      targetUrl,
      "-H", `Host: ${TARGET.hostname}`,
      "-H", `User-Agent: ${clientReq.headers["user-agent"] || "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36"}`,
      "-H", `Accept: ${clientReq.headers["accept"] || "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"}`,
      "-H", `Accept-Language: ${clientReq.headers["accept-language"] || "en-US,en;q=0.9"}`
    ];

    if (clientReq.headers.cookie) {
      args.push("-H", `Cookie: ${clientReq.headers.cookie}`);
    }

    if (finalBody.length > 0 && !["GET", "HEAD"].includes(clientReq.method)) {
      args.push("--data-binary", finalBody.toString("utf8"));
    }

    // Execute through Chrome BoringSSL impersonation binary
    const { stdout } = await execFileAsync(CURL_CHROME_BIN, args, {
      maxBuffer: 50 * 1024 * 1024
    });

    const headerEndIndex = stdout.indexOf("\r\n\r\n");
    if (headerEndIndex === -1) {
      throw new Error("Invalid HTTP response format received from upstream.");
    }

    const rawHeaders = stdout.substring(0, headerEndIndex);
    const bodyText = stdout.substring(headerEndIndex + 4);

    const headerLines = rawHeaders.split("\r\n");
    const statusLine = headerLines.shift();
    const statusCode = parseInt(statusLine.split(" ")[1], 10) || 200;

    const headers = {};
    for (const line of headerLines) {
      const [key, ...values] = line.split(":");
      if (key && values.length > 0) {
        headers[key.trim().toLowerCase()] = values.join(":").trim();
      }
    }

    delete headers["content-security-policy"];
    delete headers["content-security-policy-report-only"];
    delete headers["transfer-encoding"];

    if (headers.location) {
      headers.location = headers.location.replace(
        new RegExp(`https?://${TARGET.hostname}`, "gi"),
        `https://${PROXY_PUBLIC_DOMAIN}`
      );
    }

    const contentType = headers["content-type"] || "";

    if (contentType.includes("text/html") && bodyText) {
      const html = injectWatcher(bodyText);
      const newBody = Buffer.from(html, "utf8");

      delete headers["content-encoding"];
      headers["content-length"] = newBody.length;

      clientRes.writeHead(statusCode, headers);
      return clientRes.end(newBody);
    }

    clientRes.writeHead(statusCode, headers);
    clientRes.end(Buffer.from(bodyText));
  } catch (error) {
    console.error(`❌ Upstream Request Error (${TARGET.hostname}):`, error.message);
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

  console.log(`→ ${clientReq.method} ${clientReq.url}`);

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

      console.log(`🚨 Session ${clientId} triggered redirect to: ${finalUrl}`);
      return;
    } catch (err) {
      return forwardRequest(clientReq, clientRes, body);
    }
  }

  if (state?.redirected) {
    console.log(`🛑 Blocked traffic for redirected session: ${path}`);
    clientRes.writeHead(410, { "Content-Type": "text/plain; charset=utf-8" });
    return clientRes.end("Proxy session terminated");
  }

  await forwardRequest(clientReq, clientRes, null);
});

server.on("clientError", (error, socket) => {
  console.error("Client error:", error.message);
  socket.end("HTTP/1.1 400 Bad Request\r\n\r\n");
});

server.listen(PROXY_PORT, PROXY_HOST, () => {
  console.log("==========================================");
  console.log(` Proxy listening on http://${PROXY_HOST}:${PROXY_PORT}`);
  console.log(` Forwarding via curl-chrome to https://${TARGET.hostname}`);
  console.log("==========================================");
});