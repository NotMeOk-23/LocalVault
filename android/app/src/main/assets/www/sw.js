// LocalVault Mobile Service Worker - Offline Cache
const CACHE_NAME = "localvault-mobile-v2";
const ASSETS = [
  "/mobile/",
  "/mobile/index.html",
  "/mobile/manifest.json",
  "/mobile/icons/icon_128.png",
  "/mobile/icons/icon_192.png",
  "/mobile/icons/icon_256.png",
  "/mobile/icons/icon_512.png"
];

self.addEventListener("install", (e) => {
  e.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(ASSETS))
  );
  self.skipWaiting();
});

self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.map((k) => {
          if (k !== CACHE_NAME) return caches.delete(k);
        })
      );
    })
  );
  self.clients.claim();
});

self.addEventListener("fetch", (e) => {
  if (e.request.method === "GET" && e.request.url.includes("/mobile/")) {
    e.respondWith(
      caches.match(e.request).then((cached) => {
        return cached || fetch(e.request).catch(() => caches.match("/mobile/index.html"));
      })
    );
  }
});
