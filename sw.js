// Service Worker für Elevator Servicebox
// Minimalistisch: leitet alle Requests durch (Network-First), cached aber
// das App-Shell für Offline-Fallback. Echte App-Logik macht der Loader im HTML.
const CACHE = 'esbox-shell-v1';
const SHELL = [
  './',
  './loader.html',
];

self.addEventListener('install', (e) => {
  self.skipWaiting();
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL).catch(()=>{})));
});

self.addEventListener('activate', (e) => {
  e.waitUntil((async () => {
    const keys = await caches.keys();
    for (const k of keys) if (k !== CACHE) await caches.delete(k);
    await self.clients.claim();
  })());
});

// Network-First für loader.html / index.html, Fallback auf Cache. API-Calls
// (airtable, anthropic, val.run, aufzugshandwerk) gehen IMMER über das Netz.
self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);
  // Externe API-Calls nicht cachen
  if (
    url.hostname.endsWith('airtable.com') ||
    url.hostname.endsWith('anthropic.com') ||
    url.hostname.endsWith('val.run') ||
    url.hostname.endsWith('aufzugshandwerk.de') ||
    url.hostname.endsWith('freshdesk.com')
  ) return;
  // Nur GET cachen
  if (e.request.method !== 'GET') return;

  e.respondWith((async () => {
    try {
      const res = await fetch(e.request);
      if (res && res.ok) {
        const cache = await caches.open(CACHE);
        cache.put(e.request, res.clone()).catch(()=>{});
      }
      return res;
    } catch (err) {
      const cached = await caches.match(e.request);
      if (cached) return cached;
      throw err;
    }
  })());
});
