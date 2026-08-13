/**
 * Upload sink for WAN acceptance testing.
 *
 * Static hosting cannot accept a request body, so upstream internet
 * throughput cannot be measured against Cloudflare Pages. This Worker accepts
 * a POST, discards the body, and reports how many bytes it received.
 *
 * SECURITY: an open upload sink absorbs whatever is sent to it and bills you
 * for the privilege. SHARED_SECRET must be set as a Worker secret; requests
 * without a matching header are rejected. Consider additionally restricting
 * the route with Cloudflare Access or a WAF rule limiting it to your known
 * egress ranges.
 */

const MAX_BYTES = 512 * 1024 * 1024; // per-request ceiling

export default {
  async fetch(request, env) {
    if (request.method === "GET") {
      return new Response("acceptance upload sink\n", {
        headers: { "content-type": "text/plain", "cache-control": "no-store" },
      });
    }

    if (request.method !== "POST") {
      return new Response("method not allowed\n", {
        status: 405,
        headers: { allow: "GET, POST" },
      });
    }

    // Reject before reading the body, so an unauthorised caller cannot use
    // the endpoint as a bandwidth sink.
    if (!env.SHARED_SECRET) {
      return new Response("endpoint not configured: SHARED_SECRET is unset\n", {
        status: 503,
      });
    }
    if (request.headers.get("x-acceptance-key") !== env.SHARED_SECRET) {
      return new Response("forbidden\n", { status: 403 });
    }

    const declared = Number(request.headers.get("content-length") ?? "0");
    if (declared > MAX_BYTES) {
      return new Response(`payload too large (max ${MAX_BYTES} bytes)\n`, {
        status: 413,
      });
    }

    // Drain the body without buffering it: the point is to move bytes across
    // the circuit, not to keep them.
    let received = 0;
    if (request.body) {
      const reader = request.body.getReader();
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        received += value.byteLength;
        if (received > MAX_BYTES) {
          await reader.cancel();
          return new Response("payload too large\n", { status: 413 });
        }
      }
    }

    return new Response(JSON.stringify({ received_bytes: received }) + "\n", {
      headers: { "content-type": "application/json", "cache-control": "no-store" },
    });
  },
};
