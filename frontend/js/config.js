window.AKILI_CONFIG = {
  API_BASE: 'http://localhost:5501',
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
