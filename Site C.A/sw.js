const CACHE_NAME = 'competence-academy-v3';
const urlsToCache = [
  '/',
  '/Logo.png',
  '/privacy.html',
  '/style.css'
];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        return cache.addAll(urlsToCache);
      })
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
  );
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
