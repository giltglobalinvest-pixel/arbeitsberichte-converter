import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { createApp } from "../src/app.js";
import { createFileStore } from "../src/store.js";

const ENV = {
  AIRTABLE_BASE_ID: "appTEST",
  AIRTABLE_READ_KEY: "read-key-123456",
  AIRTABLE_WRITE_KEY: "write-key-123456",
  AUFZUG_API_KEY: "global-erp-key",
  AUFZUG_API_KEY_ASZENDIO: "aszendio-erp-key",
  AUFZUG_BASE_URL: "https://erp.test/v1",
  FRESHDESK_DOMAIN_AUFZUG: "aufzugdesk",
  FRESHDESK_API_KEY_AUFZUG: "fd-key",
  SYNC_SECRET: "sync-secret",
  ORDERDISPLAY_TOKEN: "od-token",
  ORDERDISPLAY_ACCOUNT_KEY_AUFZUG: "od-account",
  MAILCHIMP_API_KEY_AUFZUG: "mc-key-us5",
  MAILCHIMP_AUDIENCE_AUFZUG: "aud1",
  LIFTARO_PARTNER_KEY: "liftaro-global",
  LIFTARO_PARTNER_KEY_ASZENDIO: "liftaro-aszendio",
};

const USERS = {
  "admin-key": { id: "rec1", fields: { api_key: "admin-key", name: "Ada", role: "admin" } },
  "tech-key": { id: "rec2", fields: { api_key: "tech-key", name: "Tom", role: "techniker" } },
};

let dir, app, calls, upstream;
const realFetch = globalThis.fetch;

beforeEach(async () => {
  dir = await mkdtemp(path.join(tmpdir(), "esbx-"));
  app = createApp({ env: (k) => ENV[k], blob: createFileStore(dir) });
  calls = [];
  upstream = null;
  globalThis.fetch = async (input, init = {}) => {
    const url = String(input);
    calls.push({ url, init });
    if (url.startsWith("https://api.airtable.com/v0/appTEST/User?")) {
      const formula = new URL(url).searchParams.get("filterByFormula");
      const key = /\{api_key\}='([^']*)'/.exec(formula)[1];
      return Response.json({ records: USERS[key] ? [USERS[key]] : [] });
    }
    if (upstream) return upstream(url, init);
    throw new Error("unexpected fetch " + url);
  };
});

afterEach(async () => {
  globalThis.fetch = realFetch;
  await rm(dir, { recursive: true, force: true });
});

async function login(key = "admin-key", long_lived = false) {
  const res = await app.request("/auth", { method: "POST", body: JSON.stringify({ user_key: key, long_lived }) });
  return { res, body: await res.json() };
}
const bearer = (t) => ({ authorization: "Bearer " + t });

test("OPTIONS preflight returns CORS headers without auth", async () => {
  const res = await app.request("/aufzug/aufzug/api/auftraege", { method: "OPTIONS" });
  assert.equal(res.status, 204);
  assert.equal(res.headers.get("access-control-allow-origin"), "*");
  assert.match(res.headers.get("access-control-allow-headers"), /x-sync-secret/);
});

test("/auth issues a session token for an active user", async () => {
  const { res, body } = await login("admin-key", true);
  assert.equal(res.status, 200);
  assert.match(body.session_token, /^[0-9a-f]{64}$/);
  assert.equal(body.expires_in, 30 * 24 * 60 * 60);
  assert.deepEqual(body.user, { id: "rec1", api_key: "admin-key", name: "Ada", role: "admin", is_admin: true });
  assert.equal(res.headers.get("access-control-allow-origin"), "*");
});

test("/auth rejects missing and unknown keys", async () => {
  let res = await app.request("/auth", { method: "POST", body: "{}" });
  assert.equal(res.status, 400);
  assert.deepEqual(await res.json(), { error: "user_key fehlt" });
  res = (await login("nope")).res;
  assert.equal(res.status, 401);
});

test("protected routes need a token", async () => {
  let res = await app.request("/me");
  assert.equal(res.status, 401);
  assert.deepEqual(await res.json(), { error: "Missing Bearer token" });
  res = await app.request("/me", { headers: bearer("garbage") });
  assert.equal(res.status, 401);
  assert.deepEqual(await res.json(), { error: "Ungültiges Token" });
});

test("session token and direct user key both authenticate", async () => {
  const { body } = await login("tech-key");
  let res = await app.request("/me", { headers: bearer(body.session_token) });
  assert.equal((await res.json()).user.kind, "session");
  res = await app.request("/health", { headers: bearer("tech-key") });
  const health = await res.json();
  assert.equal(health.ok, true);
  assert.match(health.proxy_version, /^\d{4}-\d{2}-\d{2}/);
  assert.deepEqual(health.user, { name: "Tom", is_admin: false });
});

test("logout deletes the session", async () => {
  const { body } = await login();
  const res = await app.request("/logout", { method: "POST", headers: bearer(body.session_token) });
  assert.deepEqual(await res.json(), { ok: true });
  const after = await app.request("/me", { headers: bearer(body.session_token) });
  assert.equal(after.status, 401);
});

test("unknown paths return 404 after auth", async () => {
  const res = await app.request("/whatever", { headers: bearer("admin-key") });
  assert.equal(res.status, 404);
  assert.deepEqual(await res.json(), { error: "Not found", path: "whatever" });
});

test("/healthz is public", async () => {
  const res = await app.request("/healthz");
  assert.deepEqual(await res.json(), { ok: true });
});

test("/debug/env is admin-only and never returns full values", async () => {
  let res = await app.request("/debug/env", { headers: bearer("tech-key") });
  assert.equal(res.status, 403);
  res = await app.request("/debug/env", { headers: bearer("admin-key") });
  const body = await res.json();
  assert.deepEqual(body.env.AIRTABLE_READ_KEY, { set: true, length: 15, preview: "read...56" });
  assert.deepEqual(body.env.AUFZUG_API_KEY_AUFZUG, { set: false });
  assert.deepEqual(body.tenant_map, { aufzug: "1", aszendio: "4" });
});

test("/aufzug forwards with tenant fallback, per-firma key and query string", async () => {
  upstream = async () => new Response('[{"id":1}]', { status: 200, headers: { "content-type": "application/json" } });
  const res = await app.request("/aufzug/aszendio/api/auftraege?page=2", { headers: bearer("tech-key") });
  assert.equal(res.status, 200);
  assert.equal(await res.text(), '[{"id":1}]');
  assert.equal(res.headers.get("x-erp-target"), "https://erp.test/v1/api/auftraege?page=2");
  assert.equal(res.headers.get("x-erp-tenant"), "4");
  const call = calls.at(-1);
  assert.equal(call.url, "https://erp.test/v1/api/auftraege?page=2");
  assert.deepEqual(call.init.headers, { APIKEY: "aszendio-erp-key", TENANT: "4", Accept: "application/json" });
});

test("/aufzug uses X-ERP-Tenant and forwards JSON bodies", async () => {
  upstream = async () => new Response(null, { status: 204 });
  const res = await app.request("/aufzug/neu/api/auftraege/5", {
    method: "PATCH", headers: { ...bearer("tech-key"), "x-erp-tenant": "9" }, body: '{"a":1}',
  });
  assert.equal(res.status, 204);
  const call = calls.at(-1);
  assert.equal(call.init.method, "PATCH");
  assert.equal(call.init.body, '{"a":1}');
  assert.equal(call.init.headers.TENANT, "9");
  assert.equal(call.init.headers.APIKEY, "global-erp-key");
  assert.equal(call.init.headers["Content-Type"], "application/json");
});

test("/aufzug errors keep the Val.town diagnostic shape", async () => {
  let res = await app.request("/aufzug/unknown/x", { headers: bearer("tech-key") });
  assert.equal(res.status, 400);
  res = await app.request("/aufzug/aufzug", { headers: bearer("tech-key") });
  assert.equal(res.status, 400);
  upstream = async () => new Response("kaputt", { status: 422, headers: { "content-type": "text/plain" } });
  res = await app.request("/aufzug/aufzug/api/x", { method: "POST", headers: bearer("tech-key") });
  assert.equal(res.status, 422);
  const body = await res.json();
  assert.equal(body.error, "Upstream HTTP 422");
  assert.equal(body.tenant_source, "TENANT_MAP fallback");
  assert.equal(body.api_key_source, "AUFZUG_API_KEY");
  assert.equal(body.upstream_body_excerpt, "kaputt");
  upstream = async () => { throw new Error("ECONNREFUSED"); };
  res = await app.request("/aufzug/aufzug/api/x", { headers: bearer("tech-key") });
  assert.equal(res.status, 502);
});

test("/freshdesk forwards with basic auth and original content type", async () => {
  upstream = async () => Response.json({ id: 7 }, { status: 201 });
  const res = await app.request("/freshdesk/aufzug/api/v2/tickets?x=1", {
    method: "POST", headers: { ...bearer("tech-key"), "content-type": "application/json" }, body: '{"subject":"s"}',
  });
  assert.equal(res.status, 201);
  const call = calls.at(-1);
  assert.equal(call.url, "https://aufzugdesk.freshdesk.com/api/v2/tickets?x=1");
  assert.equal(call.init.headers.Authorization, "Basic " + btoa("fd-key:X"));
  assert.equal(call.init.headers["Content-Type"], "application/json");
  assert.equal(new TextDecoder().decode(call.init.body), '{"subject":"s"}');

  const missing = await app.request("/freshdesk/aszendio/api/v2/tickets", { headers: bearer("tech-key") });
  assert.equal(missing.status, 500);
  assert.deepEqual((await missing.json()).expected_env, ["FRESHDESK_DOMAIN_ASZENDIO", "FRESHDESK_API_KEY_ASZENDIO"]);
});

test("X-Sync-Secret authenticates cron calls; sync/run-all writes status", async () => {
  upstream = async (url, init) => {
    if (url.includes("/Firmen?")) return Response.json({ records: [{ id: "f1", fields: { slug: "aufzug", erp_tenant: "1" } }] });
    if (url.includes("/Auftraege?")) return Response.json({ records: [] });
    if (url === "https://erp.test/v1/api/auftraege") {
      return Response.json([{ id: 11, status: "In Bearbeitung", vorgangsnummer: "A-11", anlage: { name: "Haus" } }, { id: 12, status: "Storniert" }]);
    }
    if (url.endsWith("/Auftraege") && init.method === "POST") {
      assert.equal(init.headers.Authorization, "Bearer write-key-123456");
      return Response.json({ id: "recNew" });
    }
    throw new Error("unexpected " + url);
  };
  const wrong = await app.request("/sync/run-all", { method: "POST", headers: { "x-sync-secret": "nope" } });
  assert.equal(wrong.status, 401);

  const res = await app.request("/sync/run-all", { method: "POST", headers: { "x-sync-secret": "sync-secret" } });
  const body = await res.json();
  assert.equal(res.status, 200);
  assert.equal(body.ran, 1);
  assert.deepEqual(body.results[0], { firma: "aufzug", ok: true, created: 1, updated: 0, skipped: 0, errors: 0 });

  const status = await app.request("/sync/status", { headers: bearer("tech-key") });
  const s = (await status.json()).statuses;
  assert.equal(s.aufzug.created, 1);
  assert.equal(s.aufzug.triggered_by, "cron");
});

test("sync/run requires firma", async () => {
  const res = await app.request("/sync/run", { method: "POST", headers: bearer("tech-key"), body: "{}" });
  assert.equal(res.status, 400);
  assert.deepEqual(await res.json(), { error: "firma fehlt" });
});

test("/aufzug passes binary responses through untouched", async () => {
  const pdf = new Uint8Array([37, 80, 68, 70, 0, 255]);
  upstream = async () => new Response(pdf, { headers: { "content-type": "application/pdf", "content-disposition": "attachment; filename=a.pdf" } });
  const res = await app.request("/aufzug/aufzug/api/angebote/1/pdf", { headers: { ...bearer("tech-key"), accept: "application/pdf" } });
  assert.deepEqual(new Uint8Array(await res.arrayBuffer()), pdf);
  assert.equal(res.headers.get("content-disposition"), "attachment; filename=a.pdf");
  assert.equal(calls.at(-1).init.headers.Accept, "application/pdf");
});

test("/orderdisplay calls the MCP tool and unpacks an SSE answer", async () => {
  upstream = async (url, init) => {
    assert.equal(url, "https://mcp2.litelead.xyz/mcp");
    assert.equal(init.headers.Authorization, "Bearer od-token");
    assert.equal(init.headers["X-Litelead-Account-Key"], "od-account");
    const rpc = JSON.parse(init.body);
    assert.equal(rpc.method, "tools/call");
    assert.deepEqual(rpc.params, { name: "listOrders", arguments: { limit: 2 } });
    const payload = { jsonrpc: "2.0", id: 1, result: { content: [{ text: '{"orders":[1,2]}' }] } };
    return new Response("event: message\ndata: " + JSON.stringify(payload), { headers: { "content-type": "text/event-stream" } });
  };
  const res = await app.request("/orderdisplay/aufzug/tool", { method: "POST", headers: bearer("tech-key"), body: '{"name":"listOrders","arguments":{"limit":2}}' });
  const body = await res.json();
  assert.equal(body.ok, true);
  assert.deepEqual(body.result, { orders: [1, 2] });
  const get = await app.request("/orderdisplay/aufzug/tool", { headers: bearer("tech-key") });
  assert.equal(get.status, 405);
});

test("/mailchimp upsert uses the md5 subscriber hash and env fallback config", async () => {
  upstream = async (url, init) => {
    if (url.includes("/Firmen?")) return Response.json({ records: [] });
    return Response.json({ id: "m1", url, method: init.method });
  };
  const res = await app.request("/mailchimp/aufzug/upsert", { method: "POST", headers: bearer("tech-key"), body: '{"email_address":"Max@Example.de"}' });
  const body = await res.json();
  assert.equal(body.ok, true);
  assert.equal(calls.at(-1).url, "https://us5.api.mailchimp.com/3.0/lists/aud1/members/" + body.hash);
  const { createHash } = await import("node:crypto");
  assert.equal(body.hash, createHash("md5").update("max@example.de").digest("hex"));
});

test("/liftaro picks the per-firma partner key from X-Firma-Slug", async () => {
  upstream = async () => Response.json({ ok: 1 });
  await app.request("/liftaro/checks?status=open", { headers: { ...bearer("tech-key"), "x-firma-slug": "aszendio" } });
  assert.equal(calls.at(-1).init.headers["X-Partner-Key"], "liftaro-aszendio");
  assert.match(calls.at(-1).url, /\/api\/v2\/checks\?status=open$/);
  await app.request("/liftaro/me", { headers: bearer("tech-key") });
  assert.equal(calls.at(-1).init.headers["X-Partner-Key"], "liftaro-global");
});
