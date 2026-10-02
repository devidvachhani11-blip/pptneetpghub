// PPTNEETPGHUB service worker.
// Network first. The cache is only a fallback so the app opens with no signal.
// It never touches /api (private PDFs, payments, Telegram), the admin page, Firebase, or any other site.
const CACHE = 'ppt-shell-v2';
const SHELL = ['/', '/manifest.webmanifest', '/icon-192.png', '/icon-512.png', '/apple-touch-icon.png'];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE).then((c) => Promise.all(SHELL.map((u) => c.add(new Request(u, { cache: 'reload' })).catch(() => {}))))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

function handled(url) {
  if (url.origin !== self.location.origin) return false;                 // Firebase, Google, fonts, CDNs
  const p = url.pathname;
  if (p === '/api' || p.indexOf('/api/') === 0) return false;           // never cache the API
  if (p === '/admin.html' || p === '/admin') return false;              // admin always live
  if (p === '/sw.js') return false;
  return true;
}

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (!handled(url)) return;

  const isPage = req.mode === 'navigate';
  event.respondWith((async () => {
    try {
      const res = await fetch(req);
      if (res && res.ok && res.type === 'basic') {
        const key = isPage ? '/' : req;
        // only the home page is kept as the offline page; other pages are not stored
        if (!isPage || url.pathname === '/' || url.pathname === '/index.html') {
          const copy = res.clone();
          caches.open(CACHE).then((c) => c.put(key, copy)).catch(() => {});
        }
      }
      return res;
    } catch (err) {
      const cache = await caches.open(CACHE);
      const hit = isPage ? await cache.match('/') : await cache.match(req);
      if (hit) return hit;
      if (isPage) return new Response('<!doctype html><meta name="viewport" content="width=device-width,initial-scale=1"><title>Offline</title><body style="font-family:sans-serif;padding:32px;text-align:center"><h2>You are offline</h2><p>Connect to the internet and try again.</p>', { status: 503, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
      return Response.error();
    }
  })());
});
