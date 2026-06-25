(function () {
  const TOKEN_KEY = 'akili_token';
  const USER_KEY = 'akili_user';

  function API() {
    return ((window.AKILI_CONFIG && AKILI_CONFIG.API_BASE) || 'http://localhost:8001').replace(/\/+$/, '');
  }

  function isRealSession() {
    const t = localStorage.getItem(TOKEN_KEY) || '';
    return Boolean(t && t !== 'sandbox_mock_token');
  }

  function getToken() {
    const t = localStorage.getItem(TOKEN_KEY) || '';
    if (t === 'sandbox_mock_token') return '';
    return t;
  }

  function getUser() {
    try {
      return JSON.parse(localStorage.getItem(USER_KEY) || 'null');
    } catch {
      return null;
    }
  }

  function setSession(token, user) {
    localStorage.setItem(TOKEN_KEY, token);
    localStorage.setItem(USER_KEY, JSON.stringify(user));
    if (typeof AKILI !== 'undefined' && AKILI.updateNavAuth) AKILI.updateNavAuth();
  }

  function clearSession() {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
    localStorage.removeItem('akili_api_key');
    if (typeof AKILI !== 'undefined' && AKILI.updateNavAuth) AKILI.updateNavAuth();
  }

  async function api(path, opts = {}) {
    const headers = { ...(opts.headers || {}) };
    if (opts.body && !headers['Content-Type']) headers['Content-Type'] = 'application/json';
    const token = getToken();
    if (token) headers['Authorization'] = `Bearer ${token}`;
    const res = await fetch(`${API()}${path}`, { ...opts, headers });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const msg = data.detail || data.message || res.statusText;
      throw new Error(typeof msg === 'string' ? msg : 'Request failed');
    }
    return data;
  }

  function requireAuth(redirectTo = 'login.html') {
    if (!isRealSession()) {
      if (localStorage.getItem(TOKEN_KEY) === 'sandbox_mock_token') {
        localStorage.removeItem(TOKEN_KEY);
        localStorage.removeItem(USER_KEY);
      }
      const next = location.pathname.split('/').pop() || 'developer.html';
      const feature = (window.AKILI_GATE && AKILI_GATE.featureForPage(next)) || next.replace(/\.html$/, '') || 'workspace';
      location.href = `access.html?feature=${encodeURIComponent(feature)}&next=${encodeURIComponent(next)}`;
      return false;
    }
    return true;
  }

  function goToDashboard() {
    location.href = 'dashboard.html';
  }

  async function renderGoogleButton(containerId, onSuccess) {
    if (window.AKILI_CONFIG_READY) {
      await window.AKILI_CONFIG_READY.catch(() => {});
    }
    const cid = ((window.AKILI_CONFIG && AKILI_CONFIG.GOOGLE_CLIENT_ID) || '').trim();
    const el = document.getElementById(containerId);
    if (!el) return;
    el.classList.add('google-btn-mount');
    if (!cid) {
      el.innerHTML = '<p class="label-sm" style="color:var(--slate)">Google sign-in is not configured on the server.</p>';
      return;
    }
    if (!window.google?.accounts?.id) {
      el.innerHTML = '<p class="label-sm">Loading Google sign-in…</p>';
      return;
    }
    el.innerHTML = '';
    google.accounts.id.initialize({
      client_id: cid,
      callback: async (resp) => {
        try {
          const data = await api('/api/v1/auth/google', {
            method: 'POST',
            body: JSON.stringify({ id_token: resp.credential }),
          });
          setSession(data.token, data.user);
          if (typeof AKILI !== 'undefined') AKILI.showToast('Signed in with Google', 'success');
          onSuccess(data);
        } catch (e) {
          if (typeof AKILI !== 'undefined') AKILI.showToast(e.message, 'error');
        }
      },
    });
    const width = Math.min(400, Math.max(280, el.clientWidth || el.parentElement?.clientWidth || 320));
    google.accounts.id.renderButton(el, {
      type: 'standard',
      theme: 'outline',
      size: 'large',
      text: 'continue_with',
      shape: 'rectangular',
      logo_alignment: 'left',
      width,
    });
  }

  async function waitForGoogleButton(containerId, onSuccess, attempts = 0) {
    if (window.AKILI_CONFIG_READY) {
      await window.AKILI_CONFIG_READY.catch(() => {});
    }
    if (window.google?.accounts?.id) {
      renderGoogleButton(containerId, onSuccess);
      return;
    }
    if (attempts > 20) { // 3 seconds timeout
      const el = document.getElementById(containerId);
      if (el) {
        el.innerHTML = `
          <button type="button" id="google-fallback-trigger" class="btn" style="display: flex; align-items: center; justify-content: center; gap: 0.75rem; width: 100%; max-width: 400px; padding: 0.65rem; background: var(--white); border: 1px solid var(--border-strong); border-radius: var(--radius); color: var(--navy); font-family: var(--font-body); font-size: 0.9rem; font-weight: 500; cursor: pointer; transition: background 0.2s, border-color 0.2s; box-shadow: var(--shadow-sm); margin: 0.5rem auto 0;">
            <svg style="width: 18px; height: 18px; flex-shrink: 0;" viewBox="0 0 24 24">
              <path fill="#EA4335" d="M12 5.04c1.66 0 3.2.57 4.38 1.69l3.27-3.27C17.67 1.54 15.01 1 12 1 7.35 1 3.4 3.65 1.57 7.5l3.86 3c.92-2.76 3.51-4.46 6.57-4.46z"/>
              <path fill="#4285F4" d="M23.49 12.27c0-.81-.07-1.59-.2-2.27H12v4.51h6.46c-.29 1.48-1.14 2.73-2.4 3.58l3.73 2.89c2.18-2 3.7-5.07 3.7-8.71z"/>
              <path fill="#FBBC05" d="M5.43 14.5c-.24-.72-.38-1.49-.38-2.3s.14-1.58.38-2.3L1.57 7.5C.8 9.15.36 11 .36 13s.44 3.85 1.21 5.5l3.86-3z"/>
              <path fill="#34A853" d="M12 23c3.24 0 5.97-1.07 7.96-2.91l-3.73-2.89c-1.1.74-2.52 1.18-4.23 1.18-3.06 0-5.65-1.7-6.57-4.46l-3.86 3C3.4 20.35 7.35 23 12 23z"/>
            </svg>
            Continue with Google (Sandbox)
          </button>
          <p class="label-sm" style="color:var(--amber); margin-top: 0.5rem; font-size: 0.75rem; text-align: center;">Google script blocked. Click above to bypass with local Sandbox Mode.</p>
        `;

        const btn = document.getElementById('google-fallback-trigger');
        if (btn) {
          btn.addEventListener('click', () => {
            if (typeof AKILI !== 'undefined' && AKILI.openModal) {
              AKILI.openModal(`
                <div class="auth-fallback-modal" style="text-align: center; padding: 0.5rem;">
                  <div style="font-size: 2.5rem; margin-bottom: 1rem;">🛡️</div>
                  <h3 style="font-family: var(--font-heading); font-size: 1.4rem; margin-bottom: 0.75rem; color: var(--navy);">Google Script Blocked</h3>
                  <p style="color: var(--slate); font-size: 0.9rem; line-height: 1.5; margin-bottom: 1.5rem;">
                    We detected that the official Google Sign-In script is blocked by your adblocker, tracking protection, or network connection.
                  </p>
                  <div style="background: var(--blue-light); border: 1px solid var(--blue-mid); border-radius: var(--radius); padding: 1rem; margin-bottom: 1.5rem; text-align: left;">
                    <h4 style="font-size: 0.9rem; margin-bottom: 0.35rem; color: var(--blue);">Offline Developer Sandbox</h4>
                    <p style="font-size: 0.8rem; color: var(--navy); margin: 0; line-height: 1.4;">
                      You can bypass the network block and sign in using a secure, local mock developer session to explore all platform features.
                    </p>
                  </div>
                  <div style="display: flex; flex-direction: column; gap: 0.5rem;">
                    <button type="button" class="btn btn-primary" id="fallback-sandbox-btn" style="width: 100%;">
                      Bypass with Sandbox Session
                    </button>
                    <button type="button" class="btn btn-outline" id="fallback-close-btn" style="width: 100%;">
                      Close & Use Email Sign-in
                    </button>
                  </div>
                </div>
              `, { title: 'Network Connection Notice' });

              const sandboxBtn = document.getElementById('fallback-sandbox-btn');
              const closeBtn = document.getElementById('fallback-close-btn');

              sandboxBtn?.addEventListener('click', () => {
                setSession('sandbox_mock_token', {
                  name: 'Sandbox Investigator',
                  email: 'sandbox@akili.com.ng'
                });
                if (typeof AKILI !== 'undefined') {
                  AKILI.showToast('Signed in as Sandbox Investigator', 'success');
                  AKILI.closeModal();
                }
                if (onSuccess) onSuccess();
              });

              closeBtn?.addEventListener('click', () => {
                if (typeof AKILI !== 'undefined') AKILI.closeModal();
              });
            } else {
              setSession('sandbox_mock_token', {
                name: 'Sandbox Investigator',
                email: 'sandbox@akili.com.ng'
              });
              if (onSuccess) onSuccess();
            }
          });
        }
      }
      return;
    }
    setTimeout(() => waitForGoogleButton(containerId, onSuccess, attempts + 1), 150);
  }

  window.AKILI_AUTH = {
    isRealSession,
    getToken,
    getUser,
    setSession,
    clearSession,
    api,
    requireAuth,
    goToDashboard,
    renderGoogleButton,
    waitForGoogleButton,
  };
})();
