// Offline cache for the LAN inventory page. Only registers on HTTPS or localhost.
var CACHE = 'lan-inventory-sw-v4';

self.addEventListener('install', function (e) {
  e.waitUntil(caches.open(CACHE).then(function (c) { return c.addAll(['./', 'index.html', 'rig.css', 'panel.css', 'nav.css', 'rig-apps.js', 'bandwidth.js', 'fonts/BarlowSemiCondensed-400.woff2', 'fonts/BarlowSemiCondensed-600.woff2', 'fonts/JetBrainsMono.woff2']); }));
  self.skipWaiting();
});

self.addEventListener('activate', function (e) {
  e.waitUntil(caches.keys().then(function (keys) {
    return Promise.all(keys.filter(function (k) { return k !== CACHE; }).map(function (k) { return caches.delete(k); }));
  }));
  self.clients.claim();
});

// Network first, fall back to the last cached copy.
self.addEventListener('fetch', function (e) {
  if (e.request.method !== 'GET') return;
  e.respondWith(
    fetch(e.request).then(function (r) {
      var copy = r.clone();
      caches.open(CACHE).then(function (c) { c.put(e.request, copy); });
      return r;
    }).catch(function () { return caches.match(e.request, { ignoreSearch: true }); })
  );
});
