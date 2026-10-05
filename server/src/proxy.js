// Elevator Servicebox · ERP-Proxy, ported from the Val.town val (VALTOWN_PROXY_CODE in index.html).
// The handler is kept as close to the Val.town source as possible so changes there can be
// carried over line by line. Val.town specifics are injected instead of imported:
//   Deno.env.get(name)  -> env(name)
//   std/blob            -> blob (see store.js)
// Deliberate fixes: /logout deletes the session (the val threw on an out-of-scope variable),
// the sync error grouping regex matches digits again (/\d+/ had lost its backslash),
// Mailchimp subscriber hashes use a real md5 (the val's hand-written md5 was wrong),
// and LIFTARO_BASE_URL can override the Liftaro partner API address.

import { createHash } from "node:crypto";

export function createProxy({ env, blob }) {
  // Elevator Servicebox · ERP-Proxy
  // ENV: AIRTABLE_READ_KEY, AIRTABLE_BASE_ID, AUFZUG_API_KEY, ORDERDISPLAY_TOKEN, ORDERDISPLAY_ACCOUNT_KEY_<FIRMA>
  // PROXY_VERSION: 2026-08-13-b (+ Order-Display tools/list Schema-Discovery via __tools_list__)
  const PROXY_VERSION = "2026-08-12-a";

  const TENANT_MAP = { aufzug: "1", aszendio: "4" };
  const USER_CACHE = new Map();
  const CACHE_TTL_MS = 60000;
  const SESSION_SHORT = 8 * 60 * 60 * 1000;
  const SESSION_LONG  = 30 * 24 * 60 * 60 * 1000;
  const SESSION_PREFIX = "esbx_session_";

  async function setSession(t, d) { await blob.setJSON(SESSION_PREFIX+t, d); }
  async function getSession(t) {
    let d; try { d = await blob.getJSON(SESSION_PREFIX+t); } catch(_) { return null; }
    if (!d) return null;
    if (d.expires && d.expires < Date.now()) { try { await blob.delete(SESSION_PREFIX+t); } catch(_){} return null; }
    return d;
  }
  async function deleteSession(t) { try { await blob.delete(SESSION_PREFIX+t); } catch(_){} }
  function genToken() {
    const a = new Uint8Array(32); crypto.getRandomValues(a);
    return Array.from(a).map(b=>b.toString(16).padStart(2,"0")).join("");
  }
  async function lookupUser(userKey) {
    const c = USER_CACHE.get(userKey);
    if (c && c.expires > Date.now()) return c.user;
    const baseId  = env("AIRTABLE_BASE_ID");
    const readKey = env("AIRTABLE_READ_KEY");
    if (!baseId || !readKey) throw new Error("AIRTABLE_BASE_ID/AIRTABLE_READ_KEY env var fehlt");
    const formula = `AND({api_key}='${userKey.replace(/'/g,"\\'")}',{status}='aktiv')`;
    const url = `https://api.airtable.com/v0/${baseId}/User?filterByFormula=${encodeURIComponent(formula)}&maxRecords=1`;
    const res = await fetch(url, { headers: { Authorization: "Bearer "+readKey } });
    if (!res.ok) throw new Error("Airtable User-Lookup HTTP "+res.status);
    const data = await res.json();
    if (!data.records || !data.records.length) {
      USER_CACHE.set(userKey, { user: null, expires: Date.now()+CACHE_TTL_MS });
      return null;
    }
    const r = data.records[0];
    const u = { id:r.id, api_key:r.fields.api_key, name:r.fields.name, role:r.fields.role, is_admin:r.fields.role==="admin" };
    USER_CACHE.set(userKey, { user: u, expires: Date.now()+CACHE_TTL_MS });
    return u;
  }
  async function resolveAuth(token) {
    const s = await getSession(token);
    if (s) return { kind:"session", api_key:s.userApiKey, name:s.name, role:s.role, is_admin:s.isAdmin };
    try {
      const u = await lookupUser(token);
      if (u) return { kind:"direct", api_key:u.api_key, name:u.name, role:u.role, is_admin:u.is_admin };
    } catch(_) {}
    return null;
  }
  function json(d, s=200) {
    return new Response(JSON.stringify(d), { status:s, headers: { "content-type":"application/json", "access-control-allow-origin":"*" } });
  }

  async function handler(req) {
    if (req.method === "OPTIONS") return new Response(null, { status:204, headers: {
      "access-control-allow-origin":"*",
      "access-control-allow-headers":"authorization, content-type, x-erp-tenant, x-sync-secret, x-firma-slug",
      "access-control-allow-methods":"GET, POST, PATCH, PUT, DELETE, OPTIONS",
      "access-control-max-age":"86400"
    }});
    const url = new URL(req.url);
    const path = url.pathname.replace(/^\/+/,"");

    if (path === "auth" && req.method === "POST") {
      let b = {}; try { b = await req.json(); } catch(_){}
      const userKey = (b.user_key||"").toString().trim();
      if (!userKey) return json({ error:"user_key fehlt" }, 400);
      let user; try { user = await lookupUser(userKey); } catch(e) { return json({ error:e.message }, 500); }
      if (!user) return json({ error:"Ungültiger Login-Key oder Account inaktiv" }, 401);
      const t = genToken();
      const ttl = b.long_lived ? SESSION_LONG : SESSION_SHORT;
      await setSession(t, { userApiKey:user.api_key, name:user.name, role:user.role, isAdmin:user.is_admin, expires:Date.now()+ttl });
      return json({ session_token:t, expires_in:Math.floor(ttl/1000), user });
    }

    // Cron-Jobs authentifizieren sich via X-Sync-Secret Header statt Bearer-Token
    const syncSecret = (req.headers.get("x-sync-secret")||"").trim();
    const validSecret = env("SYNC_SECRET");
    const isCron = !!(syncSecret && validSecret && syncSecret === validSecret);

    let user, tok;
    if (isCron) {
      user = { kind:"cron", api_key:"cron", name:"Cron", role:"system", is_admin:true };
    } else {
      tok = (req.headers.get("authorization")||"").replace(/^Bearer\s+/i,"").trim();
      if (!tok) return json({ error:"Missing Bearer token" }, 401);
      user = await resolveAuth(tok);
      if (!user) return json({ error:"Ungültiges Token" }, 401);
    }

    if (path === "logout" && req.method === "POST") {
      if (user.kind === "session") await deleteSession(tok);
      return json({ ok:true });
    }
    if (path === "me")     return json({ user });
    if (path === "health") return json({ ok:true, proxy_version:PROXY_VERSION, user:{ name:user.name, is_admin:user.is_admin } });

    // ── Debug: welche Env-Vars sind gesetzt? (Werte nicht ausgegeben) ──
    if (path === "debug/env") {
      if (!user.is_admin) return json({ error:"Nur fuer Admins" }, 403);
      const keys = ["AIRTABLE_READ_KEY","AIRTABLE_BASE_ID","AUFZUG_API_KEY","AUFZUG_API_KEY_AUFZUG","AUFZUG_API_KEY_ASZENDIO","AUFZUG_BASE_URL","ORDERDISPLAY_TOKEN","ORDERDISPLAY_ACCOUNT_KEY_AUFZUG","ORDERDISPLAY_ACCOUNT_KEY_ASZENDIO"];
      const out = {};
      for (const k of keys) {
        const v = env(k);
        out[k] = v ? { set: true, length: v.length, preview: v.length>8 ? v.slice(0,4)+"..."+v.slice(-2) : "(short)" } : { set: false };
      }
      return json({ env: out, tenant_map: TENANT_MAP });
    }

    // ── Debug-Probe: beliebigen ERP-Pfad testen, raw upstream-response zurueckgeben ──
    if (path === "debug/probe" && req.method === "POST") {
      if (!user.is_admin) return json({ error:"Nur fuer Admins" }, 403);
      let b = {}; try { b = await req.json(); } catch(_){}
      const firma = (b.firma||"aufzug").toString();
      const probePath = (b.path||"").toString().replace(/^\/+/,"");
      // Tenant aus Body (Firmen-Verwaltung) > TENANT_MAP-Fallback
      const tenant = (b.tenant && String(b.tenant).trim()) || TENANT_MAP[firma];
      if (!tenant) return json({ error:"Kein Tenant fuer Firma "+firma+" (weder Body noch TENANT_MAP)" }, 400);
      const apiKey = env("AUFZUG_API_KEY_"+firma.toUpperCase()) || env("AUFZUG_API_KEY");
      if (!apiKey) return json({ error:"Kein API-Key fuer Firma "+firma+" gesetzt", expected_env:["AUFZUG_API_KEY_"+firma.toUpperCase(),"AUFZUG_API_KEY"] }, 500);
      const baseUrl = env("AUFZUG_BASE_URL") || "https://verwaltung.api.aufzugshandwerk.de/v1";
      const target  = baseUrl + "/" + probePath;
      const t0 = Date.now();
      let upstreamStatus = null, upstreamBody = "", upstreamErr = null;
      try {
        const r = await fetch(target, { method:"GET", headers: { APIKEY:apiKey, TENANT:tenant, Accept:"application/json" } });
        upstreamStatus = r.status;
        upstreamBody = await r.text();
      } catch(e) { upstreamErr = e.message; }
      return json({
        target,
        tenant,
        tenant_source: b.tenant ? "body" : "TENANT_MAP",
        api_key_source: env("AUFZUG_API_KEY_"+firma.toUpperCase()) ? "AUFZUG_API_KEY_"+firma.toUpperCase() : "AUFZUG_API_KEY",
        api_key_preview: apiKey.length>8 ? apiKey.slice(0,4)+"..."+apiKey.slice(-2) : "(short)",
        duration_ms: Date.now()-t0,
        status: upstreamStatus,
        err: upstreamErr,
        body_excerpt: upstreamBody ? upstreamBody.slice(0, 2000) : null
      });
    }

    if (path.startsWith("aufzug/")) {
      const rest = path.replace(/^aufzug\//,"");
      const i = rest.indexOf("/");
      if (i < 0) return json({ error:"Bad path. Erwartet: /aufzug/<firma>/<path>" }, 400);
      const firma = rest.slice(0, i);
      const up = rest.slice(i+1);
      // Tenant: X-ERP-Tenant Header (Firmen-Verwaltung) > TENANT_MAP-Fallback
      const tenantHeader = (req.headers.get("x-erp-tenant")||"").trim();
      const tenant = tenantHeader || TENANT_MAP[firma];
      if (!tenant) return json({ error:"Kein Tenant fuer Firma "+firma+" – setze ihn in der Firmen-Verwaltung", hint:"erlaubte Slugs im Fallback: "+Object.keys(TENANT_MAP).join(", ") }, 400);
      // Per-Firma API-Key zuerst, dann globalen Fallback
      const firmaEnvKey = "AUFZUG_API_KEY_"+firma.toUpperCase();
      const apiKey = env(firmaEnvKey) || env("AUFZUG_API_KEY");
      if (!apiKey) return json({ error:"Kein API-Key fuer Firma "+firma+" hinterlegt", expected_env:[firmaEnvKey,"AUFZUG_API_KEY"] }, 500);
      const baseUrl = env("AUFZUG_BASE_URL") || "https://verwaltung.api.aufzugshandwerk.de/v1";
      const target = baseUrl + "/" + up + url.search;
      const t0 = Date.now();
      // v7.58: Accept vom Client DURCHREICHEN (vorher hart application/json) — sonst liefern
      // Binaer-Endpunkte wie das Angebot-PDF (produces application/octet-stream) HTTP 406.
      // Fallback application/json fuer normale JSON-Reads.
      const clientAccept = (req.headers.get("accept") || "").trim();
      const init = { method:req.method, headers: { APIKEY:apiKey, TENANT:tenant, Accept: clientAccept || "application/json" } };
      if (req.method !== "GET" && req.method !== "HEAD") {
        const t = await req.text();
        if (t && t.length > 0) { init.body = t; init.headers["Content-Type"] = "application/json"; }
      }
      let up2;
      try {
        up2 = await fetch(target, init);
      } catch(e) {
        return json({ error:"Upstream-Verbindung fehlgeschlagen", target, tenant, message:e.message }, 502);
      }
      const noBody = up2.status===101||up2.status===204||up2.status===205||up2.status===304;
      const upCT = up2.headers.get("content-type") || "";
      const isTextual = upCT === "" || /json|text|xml|javascript|csv|html|urlencoded/i.test(upCT);
      // Bei Upstream-Fehler: strukturierte Fehlerantwort mit Diagnose (Body als Text lesen)
      if (up2.status >= 400) {
        const errText = noBody ? null : await up2.text();
        return json({
          error: "Upstream HTTP "+up2.status,
          target,
          tenant,
          tenant_source: tenantHeader ? "X-ERP-Tenant header" : "TENANT_MAP fallback",
          method: req.method,
          accept_sent: init.headers.Accept,
          api_key_source: env(firmaEnvKey) ? firmaEnvKey : "AUFZUG_API_KEY",
          duration_ms: Date.now()-t0,
          upstream_body_excerpt: errText ? errText.slice(0, 1500) : null,
          upstream_content_type: upCT || null
        }, up2.status);
      }
      const outHeaders = {
        "content-type": upCT || "application/json",
        "access-control-allow-origin": "*",
        "access-control-expose-headers": "x-erp-target,x-erp-tenant,x-erp-duration-ms,content-disposition",
        "x-erp-target": target,
        "x-erp-tenant": tenant,
        "x-erp-duration-ms": String(Date.now()-t0)
      };
      const cd = up2.headers.get("content-disposition"); if (cd) outHeaders["content-disposition"] = cd;
      if (noBody) return new Response(null, { status:up2.status, headers: outHeaders });
      // Textuelles als Text, Binaeres (PDF/octet-stream) 1:1 als ArrayBuffer durchreichen (KEIN .text()!)
      if (isTextual) return new Response(await up2.text(), { status:up2.status, headers: outHeaders });
      return new Response(await up2.arrayBuffer(), { status:up2.status, headers: outHeaders });
    }

    // ══════════ ORDER DISPLAY (LiteLead MCP) ══════════
    // Route: POST /orderdisplay/<firma>/tool  Body: { name, arguments }
    //   -> tools/call an mcp2.litelead.xyz/mcp (stateless, kein Session-Handshake noetig)
    // Auth: Bearer ORDERDISPLAY_TOKEN (global) + X-Litelead-Account-Key ORDERDISPLAY_ACCOUNT_KEY_<FIRMA>
    if (path.startsWith("orderdisplay/")) {
      if (req.method !== "POST") return json({ error:"Nur POST" }, 405);
      const rest = path.replace(/^orderdisplay\//, "");
      const i = rest.indexOf("/");
      const firma = (i < 0 ? rest : rest.slice(0, i)).toLowerCase();
      if (!firma) return json({ error:"Bad path. Erwartet: /orderdisplay/<firma>/tool" }, 400);
      const odUrl   = env("ORDERDISPLAY_MCP_URL") || "https://mcp2.litelead.xyz/mcp";
      const token   = env("ORDERDISPLAY_TOKEN");
      const acctKey = env("ORDERDISPLAY_ACCOUNT_KEY_"+firma.toUpperCase()) || env("ORDERDISPLAY_ACCOUNT_KEY");
      if (!token)   return json({ error:"ORDERDISPLAY_TOKEN fehlt (in val.town ENV setzen)" }, 500);
      if (!acctKey) return json({ error:"Kein Order-Display-Account-Key fuer Firma "+firma, expected_env:["ORDERDISPLAY_ACCOUNT_KEY_"+firma.toUpperCase(),"ORDERDISPLAY_ACCOUNT_KEY"] }, 500);
      let b = {}; try { b = await req.json(); } catch(_){}
      const toolName = (b.name||b.tool||"").toString();
      if (!toolName) return json({ error:"Body braucht { name, arguments }" }, 400);
      // v8.57: '__tools_list__' → MCP tools/list (Schema-Discovery für die createOrder-Feldnamen), sonst tools/call.
      const rpc = (toolName === "__tools_list__")
        ? { jsonrpc:"2.0", id: Date.now(), method:"tools/list", params:{} }
        : { jsonrpc:"2.0", id: Date.now(), method:"tools/call", params:{ name: toolName, arguments: b.arguments || {} } };
      const t0 = Date.now();
      let r;
      try {
        r = await fetch(odUrl, { method:"POST", headers: {
          "Authorization":"Bearer "+token,
          "X-Litelead-Account-Key": acctKey,
          "Content-Type":"application/json",
          "Accept":"application/json, text/event-stream"
        }, body: JSON.stringify(rpc) });
      } catch(e) {
        return json({ error:"Order-Display-Verbindung fehlgeschlagen", message:e.message }, 502);
      }
      const txt = await r.text();
      let payload = null;
      try { payload = JSON.parse(txt); } catch(_) {
        const idx = txt.indexOf("data:");
        if (idx >= 0) { const jb = txt.indexOf("{", idx); if (jb >= 0) { try { payload = JSON.parse(txt.slice(jb)); } catch(_){} } }
      }
      if (!payload) return json({ error:"Order-Display: unlesbare Antwort", http:r.status, excerpt: txt.slice(0,600) }, 502);
      if (payload.error) return json({ error:"Order-Display MCP-Fehler", mcp_error: payload.error, tool: toolName, duration_ms: Date.now()-t0 }, 400);
      let data = payload.result;
      let unpacked = null;
      try { if (data && data.content && data.content[0] && data.content[0].text) unpacked = JSON.parse(data.content[0].text); } catch(_){}
      return json({ ok:true, tool: toolName, result: unpacked, raw: data, duration_ms: Date.now()-t0 });
    }

    // ══════════ FRESHDESK PROXY ══════════
    // Routes: /freshdesk/<firma>/api/v2/... → https://<domain>.freshdesk.com/<api/v2/...>
    // Auth via FRESHDESK_API_KEY_<FIRMA> (Basic Auth, key:X)
    if (path.startsWith("freshdesk/")) {
      const rest = path.replace(/^freshdesk\//, "");
      const i = rest.indexOf("/");
      if (i < 0) return json({ error:"Bad path. Erwartet: /freshdesk/<firma>/<fd-path>" }, 400);
      const firma = rest.slice(0, i);
      const fdPath = rest.slice(i+1);
      const domainEnv = "FRESHDESK_DOMAIN_"+firma.toUpperCase();
      const keyEnv    = "FRESHDESK_API_KEY_"+firma.toUpperCase();
      const domain = env(domainEnv);
      const apiKey = env(keyEnv);
      if (!domain || !apiKey) return json({ error:"Freshdesk-Config fehlt für Firma "+firma, expected_env:[domainEnv, keyEnv] }, 500);
      const target = "https://" + domain + ".freshdesk.com/" + fdPath + url.search;
      const t0 = Date.now();
      const basic = btoa(apiKey + ":X");
      // Forward body as ArrayBuffer wenn vorhanden; Content-Type aus Request übernehmen (wichtig für multipart/form-data!)
      const upstreamHeaders = { "Authorization": "Basic " + basic };
      const originalCT = req.headers.get("content-type");
      if (originalCT) upstreamHeaders["Content-Type"] = originalCT;
      const fdInit = { method: req.method, headers: upstreamHeaders };
      if (req.method !== "GET" && req.method !== "HEAD") {
        fdInit.body = await req.arrayBuffer();
      }
      let r;
      try { r = await fetch(target, fdInit); }
      catch(e) { return json({ error:"Freshdesk-Verbindung fehlgeschlagen", target, message:e.message }, 502); }
      const noBody = r.status===101||r.status===204||r.status===205||r.status===304;
      const respText = noBody ? null : await r.text();
      if (r.status >= 400) {
        return json({
          error: "Freshdesk HTTP "+r.status,
          target,
          firma,
          method: req.method,
          duration_ms: Date.now()-t0,
          upstream_body_excerpt: respText ? respText.slice(0, 1500) : null,
        }, r.status);
      }
      return new Response(respText, { status: r.status, headers: {
        "content-type": r.headers.get("content-type") || "application/json",
        "access-control-allow-origin": "*",
        "x-fd-duration-ms": String(Date.now()-t0)
      }});
    }

    // ══════════ MAILCHIMP PROXY ══════════
    // Routes:
    //   POST /mailchimp/<firma>/ping            → Verbindungstest (zeigt Audience-Name)
    //   POST /mailchimp/<firma>/lists           → alle Audiences zurückgeben (für Dropdown-Picker)
    //                                             Body optional: { apiKey } → override für ungespeicherten Key
    //   POST /mailchimp/<firma>/upsert          → 1 Kontakt anlegen/aktualisieren (idempotent via md5(email))
    //   POST /mailchimp/<firma>/bulk            → mehrere Kontakte (Body: { members:[...] })
    // Config-Quelle (Reihenfolge):
    //   1) Airtable Firmen.mailchimp_api_key + .mailchimp_audience_id (über Firmen-Verwaltung in der App)
    //   2) Fallback Env-Vars MAILCHIMP_API_KEY_<FIRMA> / MAILCHIMP_AUDIENCE_<FIRMA>
    if (path.startsWith("mailchimp/")) {
      const rest = path.replace(/^mailchimp\//, "");
      const i = rest.indexOf("/");
      if (i < 0) return json({ error:"Bad path. Erwartet: /mailchimp/<firma>/<action>" }, 400);
      const firma  = rest.slice(0, i);
      const action = rest.slice(i+1).replace(/\/+$/,"");

      // SPECIAL CASE: "lists" braucht nur einen API-Key (Audience-ID egal)
      // und akzeptiert optional einen override im Body — für den Picker bevor User gespeichert hat
      if (action === "lists") {
        let overrideKey = null;
        if (req.method === "POST") {
          try { const b = await req.json(); if (b && b.apiKey) overrideKey = String(b.apiKey).trim(); } catch(_){}
        }
        let useKey = overrideKey;
        if (!useKey) {
          const cfgL = await lookupMailchimpConfig(firma);
          useKey = cfgL.apiKey;
        }
        if (!useKey) return json({
          error:"Kein Mailchimp-API-Key für Firma "+firma+" verfügbar",
          hint:"Trage den API-Key in Admin → Firmen-Verwaltung ein (oder schicke ihn im Body als { apiKey: '...' })."
        }, 400);
        const dashL = useKey.lastIndexOf("-");
        const serverL = dashL > 0 ? useKey.slice(dashL+1) : "";
        if (!serverL) return json({ error:"Mailchimp API-Key hat keinen Server-Suffix (z.B. -us12). Format prüfen." }, 400);
        const baseL = "https://"+serverL+".api.mailchimp.com/3.0";
        const basicL = btoa("anystring:"+useKey);
        const r = await fetch(baseL+"/lists?count=100&fields=lists.id,lists.name,lists.stats.member_count,total_items", {
          headers: { "Authorization":"Basic "+basicL, "Accept":"application/json" }
        });
        const txt = await r.text();
        if (!r.ok) {
          let detail = txt; try { const j = JSON.parse(txt); detail = j.detail || j.title || txt; } catch(_){}
          return json({ ok:false, status:r.status, error:"Mailchimp /lists HTTP "+r.status, detail:String(detail).slice(0,500) }, r.status);
        }
        let d; try { d = JSON.parse(txt); } catch(_) { d = {}; }
        const lists = (d.lists||[]).map(l => ({
          id: l.id,
          name: l.name,
          member_count: (l.stats && l.stats.member_count) || 0
        }));
        return json({ ok:true, lists, total: d.total_items || lists.length });
      }

      const cfg = await lookupMailchimpConfig(firma);
      const apiKey = cfg.apiKey, audId = cfg.audId;
      if (!apiKey || !audId) return json({
        error:"Mailchimp-Config fehlt für Firma "+firma,
        hint:"Trage API-Key und Audience-ID in Admin → Firmen-Verwaltung ein (oder als Env-Vars MAILCHIMP_API_KEY_"+firma.toUpperCase()+" / MAILCHIMP_AUDIENCE_"+firma.toUpperCase()+")."
      }, 500);
      // Server-Prefix aus dem Key extrahieren: "<token>-us12" → "us12"
      const dash = apiKey.lastIndexOf("-");
      const server = dash > 0 ? apiKey.slice(dash+1) : "";
      if (!server) return json({ error:"Mailchimp API-Key hat keinen Server-Suffix (z.B. -us12). Prüfe ob der Key korrekt aus Mailchimp kopiert wurde." }, 500);
      const mcBase = "https://"+server+".api.mailchimp.com/3.0";
      const basic = btoa("anystring:"+apiKey);
      const mcHeaders = { "Authorization":"Basic "+basic, "Content-Type":"application/json", "Accept":"application/json" };

      // Helper: md5 → Mailchimp subscriber_hash erwartet md5(lowercase(email))
      // The val shipped a hand-written md5 that returns wrong hashes (Deno lacks md5 in Web Crypto),
      // so Mailchimp got a subscriber_hash that did not match the email. Node has md5 built in.
      async function md5Hex(input) {
        return createHash("md5").update(input, "utf8").digest("hex");
      }

      async function mcUpsert(member) {
        const email = String(member.email_address||"").trim().toLowerCase();
        if (!email) return { ok:false, error:"Email fehlt" };
        const hash = await md5Hex(email);
        const mergeFields = {};
        if (member.merge_fields) Object.assign(mergeFields, member.merge_fields);
        const body = {
          email_address: email,
          status_if_new: "subscribed",
          merge_fields: mergeFields
        };
        const target = mcBase+"/lists/"+audId+"/members/"+hash;
        const r = await fetch(target, { method:"PUT", headers: mcHeaders, body: JSON.stringify(body) });
        const txt = await r.text();
        if (!r.ok) {
          let detail = txt; try { const j = JSON.parse(txt); detail = j.detail || j.title || txt; } catch(_){}
          return { ok:false, email, status:r.status, error: detail };
        }
        let memberData = null; try { memberData = JSON.parse(txt); } catch(_){}
        // Tags zusätzlich pushen (separater Endpoint)
        const tags = Array.isArray(member.tags) ? member.tags.filter(t => t && String(t).trim()) : [];
        if (tags.length) {
          const tagBody = { tags: tags.map(t => ({ name: String(t).trim(), status: "active" })) };
          const tr = await fetch(mcBase+"/lists/"+audId+"/members/"+hash+"/tags", {
            method:"POST", headers: mcHeaders, body: JSON.stringify(tagBody)
          });
          if (!tr.ok) {
            const tt = await tr.text();
            return { ok:true, email, hash, warn:"Member ok, Tags HTTP "+tr.status+": "+tt.slice(0,200), member: memberData };
          }
        }
        return { ok:true, email, hash, member: memberData };
      }

      if (action === "ping") {
        const r = await fetch(mcBase+"/lists/"+audId, { headers: mcHeaders });
        const txt = await r.text();
        if (!r.ok) return json({ ok:false, status:r.status, body: txt.slice(0,500) }, r.status);
        let d = null; try { d = JSON.parse(txt); } catch(_){}
        return json({ ok:true, audience: d ? { id:d.id, name:d.name, member_count:d.stats && d.stats.member_count } : null });
      }
      if (action === "upsert" && req.method === "POST") {
        let b = {}; try { b = await req.json(); } catch(_){}
        const result = await mcUpsert(b);
        return json(result, result.ok ? 200 : (result.status||500));
      }
      if (action === "bulk" && req.method === "POST") {
        let b = {}; try { b = await req.json(); } catch(_){}
        const members = Array.isArray(b.members) ? b.members : [];
        const results = [];
        let ok=0, fail=0, skip=0;
        for (const m of members) {
          if (!m || !m.email_address) { skip++; results.push({ ok:false, error:"keine Email", input:m && m.tags }); continue; }
          const r = await mcUpsert(m);
          if (r.ok) ok++; else fail++;
          results.push(r);
        }
        return json({ ok:true, total: members.length, success: ok, failed: fail, skipped: skip, results });
      }
      return json({ error:"Unbekannte Mailchimp-Action: "+action, available:["ping","upsert","bulk"] }, 404);
    }

    // ══════════ LIFTARO PARTNER API PROXY ══════════
    // Liftaro = neutrale Vergleichsplattform für Wartungsverträge.
    // Wir agieren als Subunternehmer-Partner und beantworten Anfragen.
    // Routes (X-Partner-Key wird serverseitig aus LIFTARO_PARTNER_KEY env-var gesetzt):
    //   GET  /liftaro/me                          → Self-Identify
    //   GET  /liftaro/checks?status=…             → Liste Anfragen
    //   GET  /liftaro/checks/<id>                 → Detail
    //   POST /liftaro/checks/<id>/offer           → Angebot abgeben
    //   POST /liftaro/checks/<id>/decline         → Ablehnen
    //   POST /liftaro/webhook-test                → Test-Webhook auslösen
    if (path === "liftaro" || path.startsWith("liftaro/")) {
      // Multi-Firma: bevorzugt LIFTARO_PARTNER_KEY_<SLUG>, Fallback LIFTARO_PARTNER_KEY
      const firmaSlugRaw = req.headers.get("X-Firma-Slug") || "";
      const firmaSlug = firmaSlugRaw.trim().toUpperCase().replace(/[^A-Z0-9_]/g, "");
      const envNameSpecific = firmaSlug ? ("LIFTARO_PARTNER_KEY_" + firmaSlug) : "";
      const liftaroKeyRawSpecific = firmaSlug ? (env(envNameSpecific) || "") : "";
      const liftaroKeyRawGlobal = env("LIFTARO_PARTNER_KEY") || "";
      const liftaroKeyRaw = liftaroKeyRawSpecific || liftaroKeyRawGlobal;
      const liftaroKey = liftaroKeyRaw.trim();
      const keySource = liftaroKeyRawSpecific ? envNameSpecific : "LIFTARO_PARTNER_KEY";
      const sub = path.replace(/^liftaro\/?/, "");

      // Debug-Endpoint: zeigt Key-Status OHNE den Wert zu leaken
      if (sub === "debug") {
        return json({
          firma_slug_header: firmaSlugRaw,
          key_source: keySource,
          env_var_specific_set: !!liftaroKeyRawSpecific,
          env_var_global_set: !!liftaroKeyRawGlobal,
          env_var_set: !!liftaroKeyRaw,
          raw_length: liftaroKeyRaw.length,
          trimmed_length: liftaroKey.length,
          had_whitespace: liftaroKeyRaw.length !== liftaroKey.length,
          preview: liftaroKey.length > 8 ? (liftaroKey.slice(0,4) + "..." + liftaroKey.slice(-4)) : "(zu kurz)",
          looks_like_hex_64: /^[0-9a-fA-F]{64}$/.test(liftaroKey),
        });
      }

      if (!liftaroKey) return json({
        error: firmaSlug
          ? ("Weder " + envNameSpecific + " noch LIFTARO_PARTNER_KEY env-var gesetzt")
          : "LIFTARO_PARTNER_KEY env-var nicht gesetzt (oder leer nach trim)",
        hint: firmaSlug
          ? ("Trage den Liftaro-Key für Firma '"+firmaSlugRaw+"' als " + envNameSpecific + " in val.town ein, oder global als LIFTARO_PARTNER_KEY.")
          : "Trage den Liftaro-Partner-Key in val.town Settings → Environment Variables ein.",
        key_source_attempted: keySource,
        firma_slug: firmaSlugRaw,
        raw_set: !!liftaroKeyRaw,
        raw_length: liftaroKeyRaw.length
      }, 500);
      const LIFTARO_BASE = env("LIFTARO_BASE_URL") || "https://giltglobalinvest--4c42aaf257b611f19fa0ee650bb23af1.web.val.run/api/v2";
      if (!sub) return json({ error:"Bad path. Erwartet: /liftaro/<endpoint>" }, 400);
      const target = LIFTARO_BASE + "/" + sub + url.search;
      const init = {
        method: req.method,
        headers: {
          "X-Partner-Key": liftaroKey,
          "Accept": "application/json",
        }
      };
      if (req.method !== "GET" && req.method !== "HEAD") {
        const ct = req.headers.get("content-type") || "application/json";
        init.headers["Content-Type"] = ct;
        try { init.body = await req.text(); } catch(_){}
      }
      const t0 = Date.now();
      let up, body;
      try {
        up = await fetch(target, init);
        body = await up.text();
      } catch(e) {
        return json({ error:"Liftaro-Verbindung fehlgeschlagen", target, message:e.message }, 502);
      }
      if (up.status >= 400) {
        let detail = body;
        try { const j = JSON.parse(body); detail = j.detail || j.error || j.message || body; } catch(_){}
        return json({
          error:"Liftaro HTTP "+up.status,
          target,
          status: up.status,
          detail: String(detail).slice(0, 1500),
          duration_ms: Date.now()-t0,
        }, up.status);
      }
      return new Response(body, {
        status: up.status,
        headers: {
          "content-type": up.headers.get("content-type") || "application/json",
          "access-control-allow-origin": "*",
          "x-liftaro-target": target,
          "x-liftaro-duration-ms": String(Date.now()-t0),
        }
      });
    }

    // ══════════ BACKGROUND-SYNC ENDPOINTS ══════════

    if (path === "sync/run" && req.method === "POST") {
      let b = {}; try { b = await req.json(); } catch(_){}
      const firma = (b.firma||"").toString();
      if (!firma) return json({ error:"firma fehlt" }, 400);
      try {
        const result = await runSyncForFirma(firma, user.api_key || "system");
        return json(result);
      } catch(e) {
        const errResult = { firma, error: e.message, finished: new Date().toISOString() };
        try { await blob.setJSON("sync_status_"+firma, errResult); } catch(_){}
        return json({ error: e.message, firma }, 500);
      }
    }

    if (path === "sync/status" && req.method === "GET") {
      let items = [];
      try { items = await blob.list("sync_status_") || []; } catch(_){}
      const statuses = {};
      for (const item of items) {
        const key = (item && item.key) ? item.key : item;
        try {
          const data = await blob.getJSON(key);
          const firma = String(key).replace("sync_status_","");
          statuses[firma] = data;
        } catch(_){}
      }
      return json({ statuses });
    }

    // Sync für ALLE aktiven Firmen (für Cron-Jobs)
    if (path === "sync/run-all" && req.method === "POST") {
      try {
        const firmen = await atReadAll("Firmen");
        const results = [];
        for (const f of firmen) {
          const slug = f.fields && f.fields.slug;
          const tenant = f.fields && f.fields.erp_tenant;
          const aktiv = (f.fields && f.fields.aktiv) !== false;
          if (!slug || !tenant || !aktiv) continue;
          try {
            const r = await runSyncForFirma(slug, user.api_key || "cron");
            results.push({ firma:slug, ok:true, created:r.created, updated:r.updated, skipped:r.skipped, errors:r.errors });
          } catch(e) {
            results.push({ firma:slug, ok:false, error: e.message });
            try { await blob.setJSON("sync_status_"+slug, { firma:slug, error:e.message, finished:new Date().toISOString(), triggered_by:user.api_key||"cron" }); } catch(_){}
            // v9.96: Totalausfall einer Firma ist IMMER wichtig → Hintergrund-Log
            try { await atCreate("Diagnose_Logs", {
              ts: new Date().toISOString(), firma: slug, reason: "sync_fatal",
              user_key: String(user.api_key || "cron"),
              log: JSON.stringify({ firma: slug, error: String((e && e.message) || e).slice(0, 2000) }, null, 1)
            }); } catch(_){}
          }
        }
        const summary = { ran: results.length, started: new Date().toISOString(), results };
        try { await blob.setJSON("cron_last_run", summary); } catch(_){}
        return json(summary);
      } catch(e) {
        return json({ error: e.message }, 500);
      }
    }

    return json({ error:"Not found", path }, 404);
  }

  // ══════════ SYNC HELPERS (server-side TS) ══════════

  const ACTIVE_STATUSES = ["Auftrag bestätigt", "In Bearbeitung", "Abgeschlossen"];

  // v9.99 BUGFIX: Diese Funktion FEHLTE im Val, wurde in runSyncForFirma aber aufgerufen.
  //   Folge: jeder Auftrag, der wirklich geschrieben werden musste, warf
  //   "_erpAuftragNumber is not defined" -> wurde vom catch als Fehler gezaehlt (die 86).
  //   Unveraenderte Auftraege liefen durch, weil sie gar nicht erst verarbeitet werden.
  function _erpAuftragNumber(a) {
    if (!a) return null;
    const candidates = [
      a.id,
      a.auftragsnummer, a.auftragsNummer, a.auftragsNr, a.auftragNr, a.auftragNum, a.auftragNumber,
      a.belegnummer,    a.belegNummer,    a.belegNr,    a.belegNum,
      a.referenznummer, a.referenzNummer, a.refNr,      a.referenz,
      a.bestellnummer,  a.bestellNummer,  a.bestellNr,
      a.nummer,         a.number,         a.no,
      a.angebot && a.angebot.auftragsnummer,
      a.angebot && a.angebot.nummer,
      a.auftragsbestaetigung && a.auftragsbestaetigung.nummer
    ];
    for (const v of candidates) {
      if (v != null && v !== "" && v !== 0) return v;
    }
    return null;
  }

  function normStatus(s) {
    const t = String(s||"").toLowerCase().trim();
    if (!t) return "offen";
    if (/abgerechnet/.test(t)) return "abgerechnet";
    if (/abgeschlossen/.test(t)) return "abgeschlossen";
    // Merged: 'In Bearbeitung' + 'Auftrag bestätigt' + legacy → 'offen'
    if (/bearbeit|best.tigt|^offen$|^in_bearbeitung$/.test(t)) return "offen";
    return t;
  }

  function buildKontakt(k) {
    const name  = [k.vorname, k.nachname].filter(Boolean).join(" ").trim();
    const phone = k.telefon || k.mobile || "";
    const parts = [];
    if (name) parts.push(name);
    if (phone) parts.push("Tel: "+phone);
    if (k.rolle) parts.push("Rolle: "+k.rolle);
    return parts.join("\n");
  }

  async function atReadAll(table, params) {
    const baseId  = env("AIRTABLE_BASE_ID");
    const readKey = env("AIRTABLE_READ_KEY");
    if (!baseId || !readKey) throw new Error("AIRTABLE_BASE_ID/AIRTABLE_READ_KEY env-var fehlt");
    let records = [];
    let offset = null;
    let safety = 0;
    do {
      let url = "https://api.airtable.com/v0/"+baseId+"/"+encodeURIComponent(table)+"?pageSize=100";
      if (params) url += "&"+params;
      if (offset) url += "&offset="+encodeURIComponent(offset);
      const r = await fetch(url, { headers: { Authorization: "Bearer "+readKey } });
      if (!r.ok) throw new Error("Airtable "+table+" GET "+r.status);
      const d = await r.json();
      records = records.concat(d.records || []);
      offset = d.offset || null;
      if (++safety > 50) break;
    } while (offset);
    return records;
  }

  async function atPatch(table, recId, fields) {
    const baseId   = env("AIRTABLE_BASE_ID");
    const writeKey = env("AIRTABLE_WRITE_KEY");
    if (!baseId || !writeKey) throw new Error("AIRTABLE_WRITE_KEY env-var fehlt (Setup neu durchlaufen)");
    const url = "https://api.airtable.com/v0/"+baseId+"/"+encodeURIComponent(table)+"/"+recId;
    const r = await fetch(url, {
      method: "PATCH",
      headers: { Authorization: "Bearer "+writeKey, "Content-Type": "application/json" },
      body: JSON.stringify({ fields })
    });
    const d = await r.json();
    if (!r.ok) throw new Error("Airtable PATCH "+r.status+": "+(d && d.error && d.error.message || ""));
    return d;
  }

  async function atCreate(table, fields) {
    const baseId   = env("AIRTABLE_BASE_ID");
    const writeKey = env("AIRTABLE_WRITE_KEY");
    if (!baseId || !writeKey) throw new Error("AIRTABLE_WRITE_KEY env-var fehlt (Setup neu durchlaufen)");
    const url = "https://api.airtable.com/v0/"+baseId+"/"+encodeURIComponent(table);
    const r = await fetch(url, {
      method: "POST",
      headers: { Authorization: "Bearer "+writeKey, "Content-Type": "application/json" },
      body: JSON.stringify({ fields })
    });
    const d = await r.json();
    if (!r.ok) throw new Error("Airtable POST "+r.status+": "+(d && d.error && d.error.message || ""));
    return d;
  }

  async function lookupTenant(firma) {
    try {
      const recs = await atReadAll("Firmen", "filterByFormula="+encodeURIComponent("{slug}='"+firma+"'")+"&maxRecords=1");
      const t = recs[0] && recs[0].fields && recs[0].fields.erp_tenant;
      if (t) return String(t).trim();
    } catch(_){}
    const LEGACY = { aufzug: "1", aszendio: "4" };
    return LEGACY[firma] || null;
  }

  // Mailchimp-Config pro Firma. Reihenfolge: Airtable-Felder (Firmen.mailchimp_api_key
  // + .mailchimp_audience_id) → Env-Vars MAILCHIMP_API_KEY_<FIRMA> / MAILCHIMP_AUDIENCE_<FIRMA>
  // → null. So kann der Admin alles in der App pflegen, ohne in val.town zu müssen.
  async function lookupMailchimpConfig(firma) {
    let apiKey = null, audId = null;
    try {
      const recs = await atReadAll("Firmen", "filterByFormula="+encodeURIComponent("{slug}='"+firma+"'")+"&maxRecords=1");
      const f = recs[0] && recs[0].fields;
      if (f) {
        const k = f.mailchimp_api_key, a = f.mailchimp_audience_id;
        if (k && String(k).trim()) apiKey = String(k).trim();
        if (a && String(a).trim()) audId  = String(a).trim();
      }
    } catch(_){}
    if (!apiKey) apiKey = env("MAILCHIMP_API_KEY_"+firma.toUpperCase()) || null;
    if (!audId)  audId  = env("MAILCHIMP_AUDIENCE_"+firma.toUpperCase()) || null;
    return { apiKey, audId };
  }

  async function erpGet(firma, tenant, apiKey, p) {
    const baseUrl = env("AUFZUG_BASE_URL") || "https://verwaltung.api.aufzugshandwerk.de/v1";
    const url = baseUrl+"/"+p;
    const r = await fetch(url, { headers: { APIKEY: apiKey, TENANT: tenant, Accept: "application/json" } });
    if (!r.ok) {
      const txt = await r.text().catch(()=>"");
      throw new Error("ERP "+p+" HTTP "+r.status+(txt?" – "+txt.slice(0,150):""));
    }
    return r.json();
  }

  async function runSyncForFirma(firma, userKey) {
    const t0 = Date.now();
    try { await blob.setJSON("sync_status_"+firma, { firma, running: true, started: new Date(t0).toISOString(), triggered_by: userKey }); } catch(_){}

    const tenant = await lookupTenant(firma);
    if (!tenant) throw new Error("Kein ERP-Tenant fuer Firma '"+firma+"' (Firmen-Verwaltung).");
    const apiKey = env("AUFZUG_API_KEY_"+firma.toUpperCase()) || env("AUFZUG_API_KEY");
    if (!apiKey) throw new Error("Kein API-Key fuer Firma '"+firma+"'.");

    const existing = await atReadAll("Auftraege");
    const byExt = new Map();
    for (const r of existing) {
      if (r.fields && r.fields.ext_id && (r.fields.firma||"") === firma) {
        byExt.set(String(r.fields.ext_id), r);
      }
    }

    let all;
    try { all = await erpGet(firma, tenant, apiKey, "api/auftraege"); }
    catch(_) { all = await erpGet(firma, tenant, apiKey, "auftraege"); }
    if (!Array.isArray(all)) all = (all && (all.content || all.items || all.data)) || [];
    const active = all.filter(a => ACTIVE_STATUSES.indexOf(a.status) >= 0);

    const toProcess = [];
    let skipped = 0;
    for (const a of active) {
      const ex = byExt.get(String(a.id));
      if (ex && a.lastmodifiedDate && ex.fields.ext_last_modified === a.lastmodifiedDate) {
        // ÜBERSPRINGEN — außer 'auftragswert_netto' fehlt noch (Migration nach v3.09)
        const needsValueBackfill = a.bestellform === "MITANGEBOT" && a.angebotid && (ex.fields.auftragswert_netto == null);
        if (!needsValueBackfill) {
          skipped++;
          continue;
        }
      }
      toProcess.push(a);
    }

    const angebotCache = new Map();
    const needsAngebot = [];
    for (const a of toProcess) {
      if (a.bestellform === "MITANGEBOT" && a.angebotid) {
        const ex = byExt.get(String(a.id));
        if (ex
            && String(ex.fields.angebot_id||"") === String(a.angebotid)
            && ex.fields.leistungsumfang
            && ex.fields.auftragswert_netto != null) {
          angebotCache.set(String(a.angebotid), {
            serviceDescription: ex.fields.leistungsumfang,
            offerExplanation:   ex.fields.erlaeuterungen,
            typ:                ex.fields.angebot_typ,
            netPrice:           ex.fields.auftragswert_netto
          });
        } else {
          needsAngebot.push(a);
        }
      }
    }
    if (needsAngebot.length > 0) {
      let idx = 0;
      const worker = async () => {
        while (idx < needsAngebot.length) {
          const a = needsAngebot[idx++];
          try {
            const ang = await erpGet(firma, tenant, apiKey, "api/angebote/"+a.angebotid);
            angebotCache.set(String(a.angebotid), ang);
          } catch(_) {}
        }
      };
      await Promise.all(Array.from({ length: Math.min(5, needsAngebot.length) }, () => worker()));
    }

    let created = 0, updated = 0, unchanged = 0, withAngebot = 0, errors = 0;
    const errorDetails = [];   // v9.96: Fehlerdetails sammeln (wurden vorher kommentarlos verworfen)
    const USER_MANAGED = ["techniker_keys","techniker_namen","priority","tmpl","notizen","bilder","subunternehmer_preis","bericht_id","bericht_num","completed_at","created","created_by"];

    for (const a of toProcess) {
      try {
        let ang = null;
        if (a.bestellform === "MITANGEBOT" && a.angebotid) {
          ang = angebotCache.get(String(a.angebotid)) || null;
          if (ang) withAngebot++;
        }
        const anlage = a.anlage || {};
        const ansp = anlage.ansprechpartner || {};
        const empf = a.empfaenger || {};
        const hasAnsp = !!(ansp.vorname || ansp.nachname || ansp.telefon || ansp.mobile);
        const kontaktText = hasAnsp ? buildKontakt(ansp) : buildKontakt(empf);
        const haystack = [a.bestellform, a.leistungsbeschreibung, a.notizen, ang && ang.typ, ang && ang.serviceDescription, ang && ang.title, anlage.objektTyp].filter(Boolean).join(" ").toLowerCase();
        const isWartung = /wartung/.test(haystack);
        const tmplKey = firma + (isWartung ? "-wartung" : "-arbeit");
        const leistungsumfang = ((ang && ang.serviceDescription) || a.leistungsbeschreibung || a.notizen || "").toString().trim();

        const fields = {
          firma,
          auftrag_num: _erpAuftragNumber(a),
          ext_id: a.id,
          ext_source: "aufzugshandwerk_v1",
          ext_vorgangsnummer: a.vorgangsnummer || null,
          ext_last_modified: a.lastmodifiedDate || "",
          standort: anlage.anzeigeAdresse || anlage.name || "",
          fabriknummer: anlage.fabriknummer || "",
          kontakt: kontaktText,
          // Leistungsbeschreibung bevorzugt aus Angebot (leistungsumfang), sonst aus Auftrag/Notizen
          leistungsbeschreibung: leistungsumfang || a.leistungsbeschreibung || a.notizen || "",
          status: normStatus(a.status),
          priority: "normal",
          due_date: (a.ausfuehrungstermin || "").slice(0, 10) || "",
          created: a.createdDate || new Date().toISOString(),
          created_by: userKey,
          tmpl: tmplKey,
          stundensatz: anlage.stundensatz || null,
          einsatzpauschale: anlage.einsatzPauschale || null,
          objekttyp: anlage.objektTyp || "",
          kunde_firmenname: (anlage.kunde && anlage.kunde.firmenname) || "",
          leistungsumfang: leistungsumfang,
          erlaeuterungen: (ang && ang.offerExplanation) || "",
          angebot_typ: (ang && ang.typ) || "",
          angebot_id: a.angebotid || null,
          bestellform: a.bestellform || "",
          auftragswert_netto: ang ? ((ang.netPrice != null ? +ang.netPrice : null) ?? (ang.gesamtpreis != null ? +ang.gesamtpreis : null) ?? (ang.annualPrice != null ? +ang.annualPrice : null)) : null
        };

        const ex = byExt.get(String(a.id));
        if (ex) {
          const patch = Object.assign({}, fields);
          for (const k of USER_MANAGED) {
            const v = ex.fields[k];
            const hasVal = v !== undefined && v !== null && v !== "" && !(Array.isArray(v) && v.length === 0);
            if (hasVal) delete patch[k];
          }
          // v7.98/v8.00: Maxise = Wahrheit — aktiver Maxise-Status reaktiviert lokal 'abgerechnet'
          //   (Status → offen). Das Ausblenden berechneter Aufträge macht die Checkbox „Mit Rechnung ausblenden".
          if (ex.fields.status === "abgerechnet" && normStatus(a.status) !== "offen") delete patch.status;
          if (ex.fields.needs_reinvoice && normStatus(a.status) === "abgerechnet") delete patch.status;   // v8.01: Bericht nach Rechnung hält offen
          const protectIfEmpty = ["kontakt","leistungsumfang","erlaeuterungen","standort","fabriknummer","due_date"];
          for (const k of protectIfEmpty) {
            if ((patch[k] === "" || patch[k] == null) && ex.fields[k]) delete patch[k];
          }
          const changed = {};
          for (const k of Object.keys(patch)) {
            const cur = ex.fields[k];
            const curN = (cur === null || cur === undefined) ? "" : cur;
            const newN = (patch[k] === null || patch[k] === undefined) ? "" : patch[k];
            if (String(curN) !== String(newN)) changed[k] = patch[k];
          }
          if (a.lastmodifiedDate && ex.fields.ext_last_modified !== a.lastmodifiedDate) {
            changed.ext_last_modified = a.lastmodifiedDate;
          }
          if (Object.keys(changed).length === 0) { unchanged++; continue; }
          await atPatch("Auftraege", ex.id, changed);
          updated++;
        } else {
          await atCreate("Auftraege", fields);
          created++;
        }
      } catch(e) {
        errors++;
        // v9.99: Der Fehler-Handler darf NIE selbst werfen, sonst bricht der ganze Sync ab
        //   (genau das passierte, weil hier _erpAuftragNumber aufgerufen wurde).
        try {
          if (errorDetails.length < 200) {
            errorDetails.push({
              auftrag: (a && (a.auftragsnummer || a.id)) || "?",
              ext_id: a && a.id,
              msg: String((e && e.message) || e).slice(0, 300)
            });
          }
        } catch(_) {}
      }
    }

    // v9.96: NUR WICHTIGE Fehler ins Hintergrund-Log (Airtable "Diagnose_Logs", reason='sync_error').
    //   Gruppiert nach Meldung (Zahlen normalisiert, damit gleiche Ursachen zusammenfallen).
    //   Transiente Netz-/Rate-Limit-Fehler nur, wenn sie sich haeufen (>=5) — sonst waere das Log Rauschen.
    let fehlerGruppen = [];
    try {
      const groups = new Map();
      for (const d of errorDetails) {
        const key = String(d.msg).replace(/\d+/g, "#").slice(0, 160);
        const g = groups.get(key) || { meldung: d.msg, anzahl: 0, beispiele: [] };
        g.anzahl++;
        if (g.beispiele.length < 5) g.beispiele.push(d.auftrag);
        groups.set(key, g);
      }
      const TRANSIENT = /rate.?limit|429|timeout|etimedout|econnreset|socket hang up|fetch failed|network/i;
      fehlerGruppen = Array.from(groups.values())
        .filter(g => !TRANSIENT.test(g.meldung) || g.anzahl >= 5)
        .sort((a, b) => b.anzahl - a.anzahl)
        .slice(0, 20);
      if (fehlerGruppen.length > 0) {
        await atCreate("Diagnose_Logs", {
          ts: new Date().toISOString(),
          firma: firma,
          reason: "sync_error",
          user_key: String(userKey || "cron"),
          log: JSON.stringify({
            firma: firma,
            finished: new Date().toISOString(),
            verarbeitet: toProcess.length,
            fehler_gesamt: errors,
            gruppen: fehlerGruppen
          }, null, 1).slice(0, 90000)
        });
      }
    } catch(_) {}

    const result = {
      firma, running: false,
      started: new Date(t0).toISOString(),
      finished: new Date().toISOString(),
      duration_ms: Date.now() - t0,
      total: active.length,
      toProcess: toProcess.length,
      skipped, created, updated, unchanged, withAngebot, errors,
      errors_wichtig: fehlerGruppen.reduce(function(n, g){ return n + (g.anzahl || 0); }, 0),   // v9.99: steuert das Banner
      triggered_by: userKey
    };
    try { await blob.setJSON("sync_status_"+firma, result); } catch(_){}
    return result;
  }

  return handler;
}
