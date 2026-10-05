// Hono app around the ported Val.town proxy handler.
import { Hono } from "hono";
import { createProxy } from "./proxy.js";

/**
 * @param {object} opts
 * @param {(name: string) => string | undefined} opts.env  reads configuration (process.env in production)
 * @param {object} opts.blob  key/value store with getJSON/setJSON/delete/list (see store.js)
 */
export function createApp({ env, blob }) {
  const handler = createProxy({ env, blob });
  const app = new Hono();

  app.onError((err, c) => {
    console.error(c.req.method, c.req.path, err);
    return new Response(JSON.stringify({ error: err.message || "Internal error" }), {
      status: 500,
      headers: { "content-type": "application/json", "access-control-allow-origin": "*" },
    });
  });

  // Unauthenticated liveness check for Railway (new; Val.town had no equivalent)
  app.get("/healthz", (c) => c.json({ ok: true }));

  // Every other path goes through the proxy handler unchanged
  app.all("*", (c) => handler(c.req.raw));

  return app;
}
