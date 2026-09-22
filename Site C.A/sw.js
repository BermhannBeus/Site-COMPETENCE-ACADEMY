const CACHE_NAME = 'competence-academy-v11';
const urlsToCache = [
  '/',
  '/Logo.png',
  '/icon-192.png',
  '/icon-512.png',
  '/privacy.html',
  '/style.css'
];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        return Promise.all(urlsToCache.map((url) => cache.add(url).catch((error) => {
          console.error(`Impossible de mettre en cache ${url}:`, error);
        })));
      })
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.map(cache => {
          if (cache !== CACHE_NAME) {
            return caches.delete(cache);
          }
        })
      );
    })
    .then(() => self.clients.claim())
  );
});

self.addEventListener('message', event => {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});

self.addEventListener('push', event => {
  const data = event.data ? event.data.json() : {};
  const title = data.title || 'Competence Academy';
  const options = {
    body: data.body || 'Une nouvelle mise à jour est disponible.',
    icon: '/icon-192.png',
    badge: '/icon-192.png',
    data: { url: data.url || '/' }
  };
  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener('notificationclick', event => {
  event.notification.close();
  const targetUrl = new URL(event.notification.data?.url || '/', self.location.origin).href;
  event.waitUntil(clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clientList) => {
    const existingClient = clientList.find((client) => 'focus' in client);
    if (existingClient) {
      existingClient.navigate(targetUrl);
      return existingClient.focus();
    }
    return clients.openWindow(targetUrl);
  }));
});

self.addEventListener('fetch', event => {
  const requestUrl = new URL(event.request.url);
  const isCoursePage = requestUrl.pathname.toLowerCase().includes('cours%20en%20ligne')
    || decodeURIComponent(requestUrl.pathname).toLowerCase().includes('cours en ligne');

  if (isCoursePage || event.request.mode === 'navigate') {
    event.respondWith(fetch(event.request));
    return;
  }

  event.respondWith(
    caches.match(event.request)
      .then(response => {
        return response || fetch(event.request);
      })
  );
});
