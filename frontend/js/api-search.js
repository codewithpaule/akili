(function () {
  const endpointEl = document.getElementById('endpoint');
  const methodEl = document.getElementById('method');
  const payloadEl = document.getElementById('payload');
  const tryBtn = document.getElementById('try-btn');
  const respEl = document.getElementById('response');
  const examplesBtn = document.getElementById('examples-btn');

  if (!endpointEl || !methodEl || !tryBtn) return;

  const base = (window.AKILI_CONFIG && AKILI_CONFIG.API_BASE) || (window.AKILI && AKILI.API && AKILI.API()) || 'https://akili.fly.dev';
  const examples = [
    { path: `${base.replace(/\/$/, '')}/api/v1/public/scan/link`, method: 'POST', payload: JSON.stringify({ url: base }, null, 2) },
    { path: `${base.replace(/\/$/, '')}/api/v1/public/scan/person`, method: 'POST', payload: JSON.stringify({ name: 'Jane Doe', keywords: '' }, null, 2) },
    { path: `${base.replace(/\/$/, '')}/api/v1/keys/generate`, method: 'POST', payload: JSON.stringify({ name: 'Integration key', sandbox: false }, null, 2) },
    { path: `${base.replace(/\/$/, '')}/api/v1/public/scan/api`, method: 'POST', payload: JSON.stringify({ url: `${base.replace(/\/$/, '')}/api/v1/data` }, null, 2) },
  ];

  let exIndex = 0;
  examplesBtn?.addEventListener('click', () => {
    const e = examples[exIndex++ % examples.length];
    endpointEl.value = e.path;
    methodEl.value = e.method;
    payloadEl.value = e.payload || '';
  });

  function showResponse(status, body, headers) {
    respEl.textContent = `HTTP ${status}\n\n` + (headers ? JSON.stringify(headers, null, 2) + '\n\n' : '') + (typeof body === 'string' ? body : JSON.stringify(body, null, 2));
  }

  tryBtn.addEventListener('click', async () => {
    const path = (endpointEl.value || '').trim();
    if (!path) { respEl.textContent = 'Enter a full URL to probe (e.g. https://example.com/api/v1/foo)'; return; }
    const method = (methodEl.value || 'GET').toUpperCase();
    let body = null;
    if (['POST', 'PUT', 'PATCH'].includes(method)) {
      try {
        body = payloadEl.value ? JSON.parse(payloadEl.value) : {};
      } catch (e) {
        respEl.textContent = 'Invalid JSON payload: ' + e.message;
        return;
      }
    }

    respEl.textContent = 'Loading…';
    // Build absolute URL: if not starting with http, assume https
    const url = path.startsWith('http') ? path : 'https://' + path;

    // Block probing our own backend or frontend hosts
    try {
      const parsed = new URL(url);
      const host = parsed.host;
      const internalHosts = [];
      if (window.location && window.location.host) internalHosts.push(window.location.host);
      if (window.AKILI_CONFIG && AKILI_CONFIG.API_BASE) {
        try { internalHosts.push(new URL(AKILI_CONFIG.API_BASE).host); } catch {}
      }
      // common local backends
      internalHosts.push('localhost:8001', '127.0.0.1:8001', 'localhost:5501');
      if (internalHosts.some(h => h && host.includes(h))) {
        respEl.textContent = 'Refusing to probe internal Akili endpoints. Enter an external URL instead.';
        return;
      }
    } catch (e) {
      respEl.textContent = 'Invalid URL: ' + e.message;
      return;
    }

    // Try OPTIONS first to detect allowed methods (best-effort)
    let headersObj = {};
    try {
      const optsResp = await fetch(url, { method: 'OPTIONS' });
      headersObj = {};
      optsResp.headers.forEach((v, k) => { headersObj[k] = v; });
      if (optsResp.status && optsResp.status !== 204 && optsResp.headers.get('content-type')?.includes('application/json')) {
        try { const j = await optsResp.json(); headersObj._options_body = j; } catch {}
      }
    } catch (e) {
      // ignore options failure
    }

    try {
      const res = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: body ? JSON.stringify(body) : undefined,
        mode: 'cors',
      });
      const ct = res.headers.get('content-type') || '';
      let data = await (ct.includes('application/json') ? res.json() : res.text());
      const hdrs = {};
      res.headers.forEach((v, k) => { hdrs[k] = v; });
      const mergedHeaders = Object.assign({}, headersObj, hdrs);
      showResponse(res.status, data, mergedHeaders);
    } catch (e) {
      respEl.textContent = 'Request failed: ' + (e.message || String(e)) + '\n\nNote: the remote server may block cross-origin requests (CORS).';
    }
  });
})();
