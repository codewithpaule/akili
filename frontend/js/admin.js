(function () {
  const TOKEN_KEY = 'akili_admin_token';
  const USER_KEY = 'akili_admin_user';

  function API() {
    return (window.AKILI_CONFIG && AKILI_CONFIG.API_BASE) || 'http://localhost:8001';
  }

  function getToken() {
    return localStorage.getItem(TOKEN_KEY) || localStorage.getItem('akili_token') || '';
  }

  function getUser() {
    try {
      return JSON.parse(localStorage.getItem(USER_KEY) || localStorage.getItem('akili_user') || 'null');
    } catch {
      return null;
    }
  }

  function setSession(token, user) {
    localStorage.setItem(TOKEN_KEY, token);
    localStorage.setItem(USER_KEY, JSON.stringify(user));
    localStorage.setItem('akili_token', token);
    localStorage.setItem('akili_user', JSON.stringify(user));
  }

  function clearSession() {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
    localStorage.removeItem('akili_token');
    localStorage.removeItem('akili_user');
  }

  async function api(path, opts = {}) {
    const headers = { ...(opts.headers || {}) };
    if (opts.body && !headers['Content-Type']) headers['Content-Type'] = 'application/json';
    const token = getToken();
    if (token) headers.Authorization = `Bearer ${token}`;
    const res = await fetch(`${API()}${path}`, { ...opts, headers });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const msg = data.detail || data.message || res.statusText;
      throw new Error(typeof msg === 'string' ? msg : 'Request failed');
    }
    return data;
  }

  async function login(email, password) {
    const data = await api('/api/v1/admin/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
    if (!data.user?.is_admin) throw new Error('Not an administrator');
    setSession(data.token, data.user);
    return data;
  }

  function requireAdmin(redirectTo = 'admin-login.html') {
    const u = getUser();
    if (!getToken() || !u?.is_admin) {
      location.href = redirectTo;
      return false;
    }
    return true;
  }

  function logout() {
    clearSession();
    location.href = 'admin-login.html';
  }

  function fmtTime(ts) {
    if (!ts) return '—';
    return new Date(ts * 1000).toLocaleString();
  }

  function esc(s) {
    if (typeof AKILI !== 'undefined' && AKILI.escapeHtml) return AKILI.escapeHtml(String(s ?? ''));
    const d = document.createElement('div');
    d.textContent = String(s ?? '');
    return d.innerHTML;
  }

  window.AKILI_ADMIN = {
    api,
    login,
    logout,
    getToken,
    getUser,
    setSession,
    clearSession,
    requireAdmin,
    fmtTime,
    esc,
  };
})();
