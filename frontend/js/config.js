// Determine API base at runtime so the repo doesn't contain production URLs.
// - In production the site will use its origin (e.g. https://akili.fly.dev).
// - In local development we default to the local API at http://localhost:8001.
function detectApiBase() {
  try {
    // Allow an explicit runtime override (generated at deploy time, not committed):
    // window.AKILI_RUNTIME = { API_BASE: 'https://akili.fly.dev' }
    if (window && window.AKILI_RUNTIME && window.AKILI_RUNTIME.API_BASE) {
      return window.AKILI_RUNTIME.API_BASE.replace(/\/$/, '');
    }
    const host = (window && window.location && window.location.hostname) || '';
    if (host === 'localhost' || host === '127.0.0.1') return 'http://localhost:8001';
    // Use the page origin for deployment (same origin API)
    return (window.location && window.location.origin) || '';
  } catch (e) {
    return 'http://localhost:8001';
  }
}

window.AKILI_CONFIG = {
  API_BASE: detectApiBase(),
  // Public client ID is loaded from the server to avoid committing it in source
  GOOGLE_CLIENT_ID: null,
};

// Load public config (non-sensitive) from the API at runtime.
(async function loadPublicConfig() {
  try {
    const base = (window.AKILI_CONFIG.API_BASE || '').replace(/\/$/, '');
    const url = (base || '') + '/api/v1/public-config';
    const res = await fetch(url, { credentials: 'same-origin' });
    if (!res.ok) return;
    const data = await res.json();
    if (data && data.GOOGLE_CLIENT_ID) {
      window.AKILI_CONFIG.GOOGLE_CLIENT_ID = data.GOOGLE_CLIENT_ID;
    }
  } catch (e) {
    // ignore — fallback to null
  }
})();
