// Offline support + push notifications.
// The page itself is network-first (so updates show straight away); CDN libraries and fonts are cache-first.
// /api/ requests always go to the network and are never cached.
const CACHE = "quran-journal-v30";
const CORE = ["./", "index.html", "manifest.webmanifest", "icon-192.png", "icon-512.png", "icon-maskable-512.png", "apple-touch-icon.png", "splash-mark.png"];

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE).then((c) => c.addAll(CORE)).then(() => self.skipWaiting()));
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
  if (req.method !== "GET") return;
  const url = new URL(req.url);
  if (req.destination === "audio" || /\.mp3$/i.test(url.pathname)) return; // audio streams straight from the network

  if (url.origin === self.location.origin) {
    if (url.pathname.startsWith("/api/")) return;
    event.respondWith(
      fetch(req)
        .then((res) => {
          if (res.ok) { const copy = res.clone(); caches.open(CACHE).then((c) => c.put(req, copy)); }
          return res;
        })
        .catch(() => caches.match(req).then((hit) => hit || caches.match("index.html")))
    );
    return;
  }

  event.respondWith(
    caches.match(req).then((hit) => {
      if (hit) return hit;
      return fetch(req).then((res) => {
        if (res.ok || res.type === "opaque") { const copy = res.clone(); caches.open(CACHE).then((c) => c.put(req, copy)); }
        return res;
      });
    })
  );
});

self.addEventListener("push", (event) => {
  let data = {};
  try { data = event.data ? event.data.json() : {}; } catch (e) { data = { body: event.data ? event.data.text() : "" }; }
  event.waitUntil(
    self.registration.showNotification(data.title || "Quran Note", {
      body: data.body || "",
      icon: "icon-192.png",
      badge: "icon-192.png",
      tag: "daily-reminder",
      renotify: true,
      data: { url: data.url || "./" },
      actions: data.url && data.url.includes("action=log") ? [{ action: "log", title: "Catat bacaan" }] : [],
    })
  );
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const url = (event.notification.data && event.notification.data.url) || "./";
  const target = new URL(url, self.registration.scope);
  const action = target.searchParams.get("action");
  event.waitUntil(
    self.clients.matchAll({ type: "window", includeUncontrolled: true }).then((list) => {
      for (const c of list) {
        if (c.url.startsWith(self.registration.scope) && "focus" in c) {
          // The app is already open: bring it forward and tell it what to show.
          c.postMessage({ type: "qn-open", action, hash: target.hash ? target.hash.slice(1) : "" });
          return c.focus();
        }
      }
      return self.clients.openWindow(target.href);
    })
  );
});
