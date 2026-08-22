// homeOS service worker — shell offline básico, sem tocar em /api.
const CACHE = "homeos-v40";
const SHELL = [
  "/", "/index.html", "/manifest.webmanifest",
  "/icon-192.png", "/icon-512.png",
  "/icon-192-maskable.png", "/icon-512-maskable.png",
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (event) => {
  const req = event.request;
  const url = new URL(req.url);

  // Só lida com GET same-origin. API e métodos mutáveis passam direto (auth/dados vivos).
  // /apps/* são apps embutidos (ex.: Spotify) — deixa o navegador cuidar direto, pra não
  // poluir o cache do shell do homeOS nem interferir no fluxo deles.
  if (req.method !== "GET" || url.origin !== self.location.origin
      || url.pathname.startsWith("/api/") || url.pathname.startsWith("/apps/")) {
    return;
  }

  // Navegações: network-first, cai no shell em cache quando offline.
  if (req.mode === "navigate") {
    event.respondWith(
      fetch(req)
        .then((res) => {
          const copy = res.clone();
          caches.open(CACHE).then((c) => c.put("/", copy)).catch(() => {});
          return res;
        })
        .catch(() => caches.match("/").then((r) => r || caches.match("/index.html")))
    );
    return;
  }

  // Estáticos: stale-while-revalidate.
  event.respondWith(
    caches.match(req).then((cached) => {
      const network = fetch(req)
        .then((res) => {
          if (res && res.status === 200 && res.type === "basic") {
            const copy = res.clone();
            caches.open(CACHE).then((c) => c.put(req, copy)).catch(() => {});
          }
          return res;
        })
        .catch(() => cached);
      return cached || network;
    })
  );
});

// Notificações push (alertas do servidor: disco, temperatura, RAM, queda de luz).
self.addEventListener("push", (event) => {
  let data = {};
  try { data = event.data ? event.data.json() : {}; }
  catch { data = { body: event.data && event.data.text() }; }
  const title = data.title || "homeOS";
  event.waitUntil(self.registration.showNotification(title, {
    body: data.body || "",
    tag: data.tag || "homeos",
    renotify: true,
    icon: "/icon-192.png",
    badge: "/icon-192.png",
    data: { url: data.url || "/" },
  }));
});

// Clicar na notificação foca (ou abre) o homeOS na URL indicada.
self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const url = (event.notification.data && event.notification.data.url) || "/";
  event.waitUntil(
    self.clients.matchAll({ type: "window", includeUncontrolled: true }).then((clients) => {
      for (const c of clients) {
        if ("focus" in c) { try { c.navigate(url); } catch {} return c.focus(); }
      }
      if (self.clients.openWindow) return self.clients.openWindow(url);
    })
  );
});
