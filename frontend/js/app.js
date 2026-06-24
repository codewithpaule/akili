(function () {
  const API = () => ((window.AKILI_CONFIG && AKILI_CONFIG.API_BASE) || 'http://localhost:8000').replace(/\/+$/, '');
  const ICONS = { success: '✓', error: '✕', warning: '⚠', info: 'ℹ' };

  window.AKILI = {
    API,
    showToast,
    openModal,
    closeModal,
    openImageModal,
    apiFetch,
    checkAccess,
    getApiKey,
    getToken,
    formatTime,
    relativeTime,
    escapeHtml,
    externalUrl,
    externalLink,
    copyText,
  };

  function getToken() {
    return localStorage.getItem('akili_token') || '';
  }

  function getApiKey() {
    return localStorage.getItem('akili_api_key') || '';
  }

  function showToast(message, type = 'info', duration = 4000) {
    let c = document.querySelector('.toast-container');
    if (!c) { c = document.createElement('div'); c.className = 'toast-container'; document.body.appendChild(c); }
    while (c.children.length >= 3) c.firstChild.remove();
    const t = document.createElement('div');
    t.className = `toast toast-${type}`;
    t.innerHTML = `<span>${ICONS[type] || 'ℹ'}</span><span>${escapeHtml(message)}</span>`;
    const close = () => { t.style.opacity = '0'; setTimeout(() => t.remove(), 300); };
    t.onclick = close;
    c.appendChild(t);
    setTimeout(close, duration);
  }

  function openModal(html, options = {}) {
    let bd = document.querySelector('.modal-backdrop');
    if (!bd) {
      bd = document.createElement('div');
      bd.className = 'modal-backdrop';
      bd.innerHTML = '<div class="modal-card"><button class="modal-close" aria-label="Close">&times;</button><div class="modal-body"></div></div>';
      document.body.appendChild(bd);
      bd.querySelector('.modal-close').onclick = closeModal;
      bd.onclick = (e) => { if (e.target === bd) closeModal(); };
    }
    bd.querySelector('.modal-body').innerHTML = html;
    bd.classList.add('open');
    document.body.style.overflow = 'hidden';
    if (options.title) bd.querySelector('.modal-card').insertAdjacentHTML('afterbegin', `<h3 style="margin-bottom:1rem">${escapeHtml(options.title)}</h3>`);
  }

  function closeModal() {
    const bd = document.querySelector('.modal-backdrop');
    if (bd) { bd.classList.remove('open'); document.body.style.overflow = ''; }
  }

  function openImageModal(images, index = 0) {
    if (!images || !images.length) return;
    let i = index;
    const render = () => {
      const img = images[i];
      openModal(`
        <div class="image-modal">
          <img src="${escapeHtml(img.url || '')}" alt="">
          <p style="margin-top:1rem;font-size:0.9rem"><strong>Source:</strong> ${externalLink(img.source, img.source || 'Unknown')}</p>
          <p><span class="badge badge-${img.verified ? 'low' : 'medium'}">${img.verified ? 'Verified' : 'Unverified'}</span> ${escapeHtml(img.label || '')}</p>
          <div style="margin-top:1rem;display:flex;gap:0.5rem">
            <button class="btn btn-outline btn-sm" id="img-prev">← Prev</button>
            <button class="btn btn-outline btn-sm" id="img-next">Next →</button>
            <a class="btn btn-outline btn-sm" href="${escapeHtml(externalUrl(img.url) || '')}" target="_blank" rel="noopener noreferrer" download>Download</a>
          </div>
        </div>
      `);
      document.getElementById('img-prev')?.addEventListener('click', () => { i = (i - 1 + images.length) % images.length; render(); });
      document.getElementById('img-next')?.addEventListener('click', () => { i = (i + 1) % images.length; render(); });
    };
    render();
  }

  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeModal(); });

  async function apiFetch(path, opts = {}) {
    const headers = { ...(opts.headers || {}) };
    if (opts.body && !headers['Content-Type']) headers['Content-Type'] = 'application/json';
    const key = getApiKey();
    if (key) headers['X-API-Key'] = key;
    const token = getToken();
    if (token) headers['Authorization'] = `Bearer ${token}`;
    const res = await fetch(`${API()}${path}`, { ...opts, headers });
    if (!res.ok) {
      let d = res.statusText;
      try { const j = await res.json(); d = j.detail || j.message || JSON.stringify(j); } catch (_) {}
      throw new Error(typeof d === 'string' ? d : 'Request failed');
    }
    return res;
  }

  async function checkAccess(module) {
    try {
      const res = await apiFetch('/api/v1/auth/check-access?module=' + encodeURIComponent(module));
      return await res.json();
    } catch (e) {
      return { allowed: false, message: e.message || 'Access check failed' };
    }
  }

  function escapeHtml(s) {
    const d = document.createElement('div');
    d.textContent = s == null ? '' : String(s);
    return d.innerHTML;
  }

  /** Ensure external links open real URLs, not localhost-relative paths. */
  function externalUrl(url) {
    if (url == null || url === '') return '';
    let u = String(url).trim();
    if (!u || u === '#') return '';
    if (/^(https?:|mailto:|tel:)/i.test(u)) return u;
    if (u.startsWith('//')) return `https:${u}`;
    return `https://${u.replace(/^\/+/, '')}`;
  }

  function externalLink(url, text, className = '') {
    const href = externalUrl(url);
    const label = text != null && text !== '' ? text : href;
    if (!href) return escapeHtml(label || '');
    const cls = className ? ` class="${className}"` : '';
    return `<a href="${escapeHtml(href)}" target="_blank" rel="noopener noreferrer"${cls}>${escapeHtml(label)}</a>`;
  }

  function copyText(text) {
    navigator.clipboard.writeText(text).then(() => showToast('Copied to clipboard', 'success')).catch(() => showToast('Copy failed', 'error'));
  }

  function formatTime(ts) {
    return new Date(ts * 1000).toLocaleString();
  }

  function relativeTime(ts) {
    const s = Math.floor(Date.now() / 1000 - ts);
    if (s < 60) return 'just now';
    if (s < 3600) return `${Math.floor(s / 60)} min ago`;
    if (s < 86400) return `${Math.floor(s / 3600)} hours ago`;
    return `${Math.floor(s / 86400)} days ago`;
  }

  function initNav() {
    const nav = document.querySelector('.navbar');
    if (nav) {
      window.addEventListener('scroll', () => nav.classList.toggle('scrolled', window.scrollY > 8));
    }

    const navInner = document.getElementById('nav-inner');
    const overlay  = document.getElementById('nav-overlay');
    const closeBtn = document.getElementById('nav-drawer-close');

    function openDrawer() {
      if (!navInner) return;
      navInner.classList.add('open');
      if (overlay) overlay.classList.add('open');
      document.body.style.overflow = 'hidden';
    }

    function closeDrawer() {
      if (!navInner) return;
      navInner.classList.remove('open');
      if (overlay) overlay.classList.remove('open');
      document.body.style.overflow = '';
    }

    document.querySelector('.hamburger')?.addEventListener('click', openDrawer);
    if (closeBtn) closeBtn.addEventListener('click', closeDrawer);
    if (overlay) overlay.addEventListener('click', closeDrawer);

    // Close drawer on Escape key
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && navInner?.classList.contains('open')) closeDrawer();
    });

    // Close drawer when a nav link inside the drawer is clicked
    navInner?.querySelectorAll('.nav-links a').forEach((a) => {
      a.addEventListener('click', closeDrawer);
    });

    // Wire up drawer logout button
    const drawerLogout = document.getElementById('nav-drawer-logout');
    if (drawerLogout && !drawerLogout.dataset.bound) {
      drawerLogout.dataset.bound = '1';
      drawerLogout.addEventListener('click', () => {
        localStorage.removeItem('akili_token');
        localStorage.removeItem('akili_user');
        localStorage.removeItem('akili_api_key');
        location.href = 'index.html';
      });
    }

    const path = location.pathname.split('/').pop() || 'index.html';
    document.querySelectorAll('.nav-links a[data-page]').forEach((a) => {
      if (a.getAttribute('data-page') === path) a.classList.add('active');
    });
    const apiDocs = document.getElementById('nav-api-docs');
    if (apiDocs) apiDocs.href = `${API()}/docs`;
  }

  const HEALTH_COLORS = { ok: '#22C55E', warn: '#F59E0B', err: '#EF4444', idle: '#94A3B8' };

  async function initHealth() {
    const el = document.getElementById('health-dot');
    const label = document.getElementById('health-label');
    if (!el) return;
    if (document.body.classList.contains('akili-scan-active')) return;
    el.style.background = HEALTH_COLORS.idle;
    if (label) label.textContent = '…';
    try {
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), 8000);
      const r = await fetch(`${API()}/api/v1/health`, { signal: ctrl.signal });
      clearTimeout(t);
      if (!r.ok) throw new Error('health failed');
      const d = await r.json();
      const apiLive = d.status === 'ok' || d.api === 'live';
      const engineOk = d.groq === 'connected';
      el.className = apiLive ? 'health-dot ok' : 'health-dot err';
      if (!apiLive) el.style.background = HEALTH_COLORS.err;
      else el.style.removeProperty('background');
      if (apiLive && engineOk) {
        el.title = 'AKILI API live — engine ready';
        if (label) label.textContent = 'LIVE';
      } else if (apiLive) {
        el.title = d.groq_detail || 'API live — engine reconnecting';
        if (label) label.textContent = 'LIVE';
      } else {
        el.title = 'API offline';
        if (label) label.textContent = 'OFFLINE';
      }
    } catch {
      el.className = 'health-dot err';
      el.style.background = HEALTH_COLORS.err;
      el.title = 'API offline — start: uvicorn main:app --port 8001';
      if (label) label.textContent = 'API OFFLINE';
    }
  }

  const CURSOR_SVG = {
    default: '<div class="cursor-eye"><svg viewBox="0 0 32 32"><circle class="eye-ring" cx="16" cy="16" r="13"/><g class="eye-pupil-group"><circle class="eye-core" cx="16" cy="16" r="5"/><circle class="eye-shine" cx="18" cy="14" r="1.5"/></g></svg></div>',
    link: `<div class="cursor-eye"><svg viewBox="0 0 32 32">
      <circle class="eye-ring" cx="16" cy="16" r="13" stroke-dasharray="4, 3"/>
      <path class="eye-crosshair" d="M16 2v4M16 26v4M2 16h4M26 16h4" />
      <g class="eye-pupil-group">
        <circle class="eye-core" cx="16" cy="16" r="7"/>
        <circle class="eye-shine" cx="19" cy="13" r="1.8"/>
      </g>
    </svg></div>`,
    text: '<div class="cursor-eye"><svg viewBox="0 0 32 32"><g class="eye-pupil-group"><path class="text-caret" d="M11 7h10M16 7v18M11 25h10" fill="none" stroke-width="2.5" stroke-linecap="round"/></g></svg></div>',
  };

  function initAkiliCursor() {
    if (window.matchMedia('(pointer: coarse)').matches) return;
    
    // Inject the class to hide native cursor globally
    document.body.classList.add('akili-cursor');

    let cur = document.getElementById('akili-cursor');
    if (!cur) {
      cur = document.createElement('div');
      cur.id = 'akili-cursor';
      cur.setAttribute('aria-hidden', 'true');
      cur.innerHTML = CURSOR_SVG.default;
      document.body.appendChild(cur);
    }
    
    const linkSel = 'a, button, .btn, [role="button"], .run-tpl, label[for], .module-card, .nav-links a, summary, .hamburger, .hero-mark-wrap';
    const textSel = 'input, textarea, select, [contenteditable="true"]';
    let mode = 'default';

    function setMode(next) {
      if (mode === next) return;
      mode = next;
      cur.classList.remove('on-link', 'on-text');
      if (next === 'link') {
        cur.classList.add('on-link');
        cur.innerHTML = CURSOR_SVG.link;
      } else if (next === 'text') {
        cur.classList.add('on-text');
        cur.innerHTML = CURSOR_SVG.text;
      } else {
        cur.innerHTML = CURSOR_SVG.default;
      }
    }

    let lastX = 0;
    let lastY = 0;
    let pupilTimeout = null;

    document.addEventListener('mousemove', (e) => {
      // Show cursor on first movement
      if (!cur.classList.contains('visible')) {
        cur.classList.add('visible');
      }
      cur.style.left = `${e.clientX}px`;
      cur.style.top = `${e.clientY}px`;
      
      // Target checks
      const target = e.target;
      if (target.closest(textSel)) {
        setMode('text');
      } else if (target.closest(linkSel)) {
        setMode('link');
      } else {
        setMode('default');
      }

      // Pupil dynamic lag / looking direction interaction
      const dx = e.clientX - lastX;
      const dy = e.clientY - lastY;
      lastX = e.clientX;
      lastY = e.clientY;

      const dist = Math.hypot(dx, dy);
      let tx = 0;
      let ty = 0;
      if (dist > 0) {
        const maxTranslate = 3.5;
        // Sensitivity factor for motion
        const factor = Math.min(maxTranslate, dist * 0.15);
        tx = (dx / dist) * factor;
        ty = (dy / dist) * factor;
      }

      const pupilGroup = cur.querySelector('.eye-pupil-group');
      if (pupilGroup) {
        pupilGroup.style.transform = `translate(${tx}px, ${ty}px)`;
      }

      // Smooth return to center when mouse slows down or stops
      clearTimeout(pupilTimeout);
      pupilTimeout = setTimeout(() => {
        const pg = cur.querySelector('.eye-pupil-group');
        if (pg) pg.style.transform = 'translate(0px, 0px)';
      }, 80);

    }, { passive: true });

    document.addEventListener('mouseleave', () => { cur.classList.remove('visible'); });
    document.addEventListener('mouseenter', () => { cur.classList.add('visible'); });

    // Interactive mouse squish / blink click effect
    document.addEventListener('mousedown', () => {
      const eye = cur.querySelector('.cursor-eye');
      if (eye) eye.classList.add('clicking');
    });

    document.addEventListener('mouseup', () => {
      const eye = cur.querySelector('.cursor-eye');
      if (eye) eye.classList.remove('clicking');
    });
  }

  function initBackgroundEyes() {
    let container = document.getElementById('akili-bg-eyes-container');
    if (!container) {
      container = document.createElement('div');
      container.id = 'akili-bg-eyes-container';
      container.setAttribute('aria-hidden', 'true');
      container.innerHTML = `
        <div class="bg-eye-shape shape-left">
          <svg viewBox="0 0 32 32" class="blinking-bubble-eye" fill="none">
            <circle cx="16" cy="16" r="14" stroke="#2563EB" stroke-width="2"/>
            <g class="bg-eye-pupil-group">
              <circle cx="16" cy="16" r="6" fill="#2563EB"/>
              <circle cx="18" cy="14" r="2" fill="#fff"/>
            </g>
          </svg>
        </div>
        <div class="bg-eye-shape shape-right">
          <svg viewBox="0 0 32 32" class="blinking-bubble-eye" fill="none">
            <circle cx="16" cy="16" r="14" stroke="#2563EB" stroke-width="2"/>
            <g class="bg-eye-pupil-group">
              <circle cx="16" cy="16" r="6" fill="#2563EB"/>
              <circle cx="18" cy="14" r="2" fill="#fff"/>
            </g>
          </svg>
        </div>
      `;
      document.body.appendChild(container);
    }

    const isCoarse = window.matchMedia('(pointer: coarse)').matches;
    const pupilGroups = container.querySelectorAll('.bg-eye-pupil-group');

    if (isCoarse) {
      pupilGroups.forEach(g => g.classList.add('idle-look'));
    } else {
      const eyeShapes = container.querySelectorAll('.bg-eye-shape');
      let mouseX = window.innerWidth / 2;
      let mouseY = window.innerHeight / 2;

      let currentX = mouseX;
      let currentY = mouseY;

      document.addEventListener('mousemove', (e) => {
        mouseX = e.clientX;
        mouseY = e.clientY;
      }, { passive: true });

      function updateGaze() {
        currentX += (mouseX - currentX) * 0.1;
        currentY += (mouseY - currentY) * 0.1;

        eyeShapes.forEach((shape) => {
          const rect = shape.getBoundingClientRect();
          const cx = rect.left + rect.width / 2;
          const cy = rect.top + rect.height / 2;

          const dx = currentX - cx;
          const dy = currentY - cy;
          const dist = Math.hypot(dx, dy);

          let tx = 0;
          let ty = 0;
          if (dist > 0) {
            const maxTranslate = 4.5;
            const factor = Math.min(maxTranslate, dist * 0.012);
            tx = (dx / dist) * factor;
            ty = (dy / dist) * factor;
          }

          const pg = shape.querySelector('.bg-eye-pupil-group');
          if (pg) {
            pg.style.transform = `translate(${tx}px, ${ty}px)`;
          }
        });

        requestAnimationFrame(updateGaze);
      }

      requestAnimationFrame(updateGaze);
    }

    // Sync global document clicks to background eye blinks
    document.addEventListener('mousedown', () => {
      container.querySelectorAll('.blinking-bubble-eye').forEach(eye => {
        eye.classList.add('clicking');
      });
    });

    document.addEventListener('mouseup', () => {
      container.querySelectorAll('.blinking-bubble-eye').forEach(eye => {
        eye.classList.remove('clicking');
      });
    });
  }

  async function loadNav() {
    const mount = document.getElementById('nav-mount');
    if (!mount) return;
    if (!mount.querySelector('#health-dot')) {
      try {
        const r = await fetch('partials/nav.html');
        mount.innerHTML = await r.text();
      } catch (_) { return; }
    }
    initNav();
    await initHealth();
    updateNavAuth();
    if (typeof lucide !== 'undefined') lucide.createIcons();
  }

  function watchNavMount() {
    const mount = document.getElementById('nav-mount');
    if (!mount) return;
    const onReady = () => {
      initNav();
      initHealth();
      updateNavAuth();
      if (typeof lucide !== 'undefined') lucide.createIcons();
    };
    if (mount.querySelector('#health-dot')) {
      onReady();
      return;
    }
    const obs = new MutationObserver(() => {
      if (mount.querySelector('#health-dot')) {
        obs.disconnect();
        onReady();
      }
    });
    obs.observe(mount, { childList: true, subtree: true });
  }

  window.AKILI.refreshHealth = initHealth;

  function updateNavAuth() {
    const token = getToken();
    const logo = document.getElementById('nav-logo') || document.querySelector('.navbar .logo');
    const navInner = document.querySelector('.nav-inner');
    const guestEls = document.querySelectorAll('.nav-guest-only');
    const authEls = document.querySelectorAll('.nav-auth-only');
    const logoutBtn = document.getElementById('nav-logout');
    if (token) {
      if (logo) logo.href = 'dashboard.html';
      if (navInner) {
        navInner.style.display = '';
        navInner.classList.add('nav-inner-auth-hide');
      }
      guestEls.forEach((el) => { el.style.display = 'none'; });
      authEls.forEach((el) => {
        el.style.display = el.classList.contains('btn') ? 'inline-flex' : '';
      });
      if (logoutBtn && !logoutBtn.dataset.bound) {
        logoutBtn.dataset.bound = '1';
        logoutBtn.addEventListener('click', () => {
          localStorage.removeItem('akili_token');
          localStorage.removeItem('akili_user');
          localStorage.removeItem('akili_api_key');
          location.href = 'index.html';
        });
      }
      // Fetch and update scan counter
      updateScanCounter();
    } else {
      if (logo) logo.href = 'index.html';
      if (navInner) {
        navInner.style.display = '';
        navInner.classList.remove('nav-inner-auth-hide');
      }
      guestEls.forEach((el) => { el.style.display = ''; });
      authEls.forEach((el) => { el.style.display = 'none'; });
    }
  }

  async function updateScanCounter() {
    const token = getToken();
    if (!token) return;
    
    const scanCounter = document.getElementById('nav-scan-counter');
    const scanUsed = document.getElementById('scan-used');
    const scanLimit = document.getElementById('scan-limit');
    const scanProgressBar = document.getElementById('scan-progress-bar');
    
    if (!scanCounter) return;
    
    try {
      const res = await fetch(`${API()}/api/v1/auth/scan-count`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        if (scanUsed) scanUsed.textContent = data.used;
        if (scanLimit) scanLimit.textContent = data.limit;
        if (scanProgressBar) {
          const percentage = (data.used / data.limit) * 100;
          scanProgressBar.style.width = `${percentage}%`;
          // Change color to red when at 4/5 or 5/5
          if (data.used >= 4) {
            scanProgressBar.style.background = '#EF4444';
          } else {
            scanProgressBar.style.background = '#10B981';
          }
        }
      }
    } catch (e) {
      console.error('Failed to fetch scan count:', e);
    }
  }

  function initSidebarLayout() {
    const path = location.pathname.split('/').pop() || 'index.html';
    const PUBLIC_PAGES = ['index.html', 'about.html', 'login.html', 'signup.html', 'privacy.html', 'terms.html', 'contact.html'];
    if (PUBLIC_PAGES.includes(path)) return;
    if (document.querySelector('.dashboard-layout') || document.querySelector('.admin-layout') || document.querySelector('.admin-topbar')) return;
    if (!localStorage.getItem('akili_token')) return;

    // Ensure pages.css is loaded
    if (!document.querySelector('link[href*="pages.css"]')) {
      const link = document.createElement('link');
      link.rel = 'stylesheet';
      link.href = 'css/pages.css';
      document.head.appendChild(link);
    }

    // Hide/remove nav-mount
    const oldNav = document.getElementById('nav-mount');
    if (oldNav) {
      oldNav.style.display = 'none';
    }

    // Select all direct children of body that form the main page content
    const container = document.querySelector('main.container') || document.querySelector('.container') || document.querySelector('main');
    if (!container) return;

    // Create the new layout elements
    const layout = document.createElement('div');
    layout.className = 'dashboard-layout';

    const SCAN_MODULES = [
      { href: 'scan-website.html', icon: 'globe', color: 'var(--mod-website)', name: 'Website Scan', desc: 'Headers, SSL, DNS, ports' },
      { href: 'scan-vulnerability.html', icon: 'bug', color: 'var(--mod-vuln)', name: 'Vulnerability', desc: 'CORS, CSRF, misconfigs' },
      { href: 'scan-subdomains.html', icon: 'git-branch', color: 'var(--mod-subdomain)', name: 'Subdomain Finder', desc: 'Scan a domain to find its subdomains (very effective!)' },
      { href: 'scan-ip.html', icon: 'network', color: 'var(--mod-ip)', name: 'IP Intelligence', desc: 'Geo, ports, reputation' },
      { href: 'scan-organization.html', icon: 'building-2', color: 'var(--mod-org)', name: 'Organization', desc: 'ASN and footprint' },
      { href: 'scan-auth.html', icon: 'lock', color: '#6366F1', name: 'Authenticated Scan', desc: 'Authorized login testing' },
    ];
    const INTEL_MODULES = [
        { href: 'person.html', icon: 'user-search', color: 'var(--mod-person)', name: 'Person Search', desc: 'Public OSINT due diligence' },
      { href: 'company.html', icon: 'briefcase', color: 'var(--mod-company)', name: 'Company Intel', desc: 'Domains, people, stack' },
      { href: 'email.html', icon: 'mail', color: 'var(--mod-email)', name: 'Email Investigator', desc: 'MX, breaches, validity' },
      { href: 'domain.html', icon: 'shield-check', color: 'var(--mod-domain)', name: 'Domain Reputation', desc: 'Age, typos, safe browsing' },
      // { href: 'breaches.html', icon: 'shield-alert', color: '#EF4444', name: 'Nigerian Breaches', desc: 'Nigerian compromised infrastructure data feed' },
      // Relationship Graph removed
    ];
    const TOOL_MODULES = [
      { href: 'api-search.html', icon: 'search', color: 'var(--navy)', name: 'API Search', desc: 'Search the API and docs' },
      { href: 'quick-scan.html', icon: 'zap', color: '#f59e0b', name: 'Quick Scan', desc: 'No login — light website or email check' },
      { href: 'developer.html', icon: 'terminal', color: 'var(--navy)', name: 'Developers', desc: 'Named API keys & limits' },
    ];

    function renderMenuHTML(items) {
      return items.map((m) => {
        const isActive = path === m.href ? ' active' : '';
        return `
          <li>
            <a href="${m.href}" class="sidebar-menu-item${isActive}${m.premium ? ' is-premium' : ''}" style="--accent:${m.color}" title="${escapeHtml(m.desc)}">
              <span class="sidebar-menu-icon" style="background:${m.color}15;color:${m.color}">
                <i data-lucide="${m.icon}"></i>
              </span>
              <span class="sidebar-menu-text">${m.name}</span>
              ${m.premium ? '<span class="sidebar-pro-badge">PRO</span>' : ''}
            </a>
          </li>
        `;
      }).join('');
    }

    const sidebarHtml = `
      <aside class="dash-sidebar" id="dash-sidebar">
        <div class="sidebar-header">
          <a href="dashboard.html" class="logo">
            <svg class="akili-mark" viewBox="0 0 32 32" fill="none" aria-hidden="true">
              <circle cx="16" cy="16" r="14" stroke="#2563EB" stroke-width="2"/>
              <circle cx="16" cy="16" r="6" fill="#2563EB"/>
              <circle cx="18" cy="14" r="2" fill="#fff"/>
            </svg>
            AKILI
          </a>
          <button class="sidebar-close" id="sidebar-close" aria-label="Close menu"><i data-lucide="x"></i></button>
        </div>
        
        <div class="sidebar-scroller">
          <nav class="sidebar-nav">
            <div class="sidebar-group">
              <span class="sidebar-group-title">Navigation</span>
              <ul class="sidebar-menu">
                <li>
                  <a href="dashboard.html" class="sidebar-menu-item${path === 'dashboard.html' ? ' active' : ''}" style="--accent:var(--blue)">
                    <span class="sidebar-menu-icon" style="background:var(--blue-light);color:var(--blue)">
                      <i data-lucide="layout-dashboard"></i>
                    </span>
                    <span class="sidebar-menu-text">Workspace Overview</span>
                  </a>
                </li>
              </ul>
            </div>

            <div class="sidebar-group">
              <span class="sidebar-group-title">Security Scans</span>
              <ul class="sidebar-menu">${renderMenuHTML(SCAN_MODULES)}</ul>
            </div>
            
            <div class="sidebar-group">
              <span class="sidebar-group-title">Intelligence</span>
              <ul class="sidebar-menu">${renderMenuHTML(INTEL_MODULES)}</ul>
            </div>
            
            <div class="sidebar-group">
              <span class="sidebar-group-title">Tools & Platform</span>
              <ul class="sidebar-menu">${renderMenuHTML(TOOL_MODULES)}</ul>
            </div>
            
            <div class="sidebar-group">
              <span class="sidebar-group-title">Account</span>
              <ul class="sidebar-menu">
                <li>
                  <a href="profile.html" class="sidebar-menu-item${path === 'profile.html' ? ' active' : ''}" style="--accent:var(--blue)">
                    <span class="sidebar-menu-icon" style="background:var(--blue-light);color:var(--blue)"><i data-lucide="user"></i></span>
                    <span class="sidebar-menu-text">Profile Details</span>
                  </a>
                </li>
                <li>
                  <a href="history.html" class="sidebar-menu-item${path === 'history.html' ? ' active' : ''}" style="--accent:var(--blue)">
                    <span class="sidebar-menu-icon" style="background:var(--blue-light);color:var(--blue)"><i data-lucide="clock"></i></span>
                    <span class="sidebar-menu-text">Scan History</span>
                  </a>
                </li>
                <li>
                  <a href="#" id="global-sidebar-api-docs" class="sidebar-menu-item" style="--accent:var(--blue)" target="_blank" rel="noopener">
                    <span class="sidebar-menu-icon" style="background:var(--blue-light);color:var(--blue)"><i data-lucide="book-open"></i></span>
                    <span class="sidebar-menu-text">API Docs</span>
                  </a>
                </li>
                <li>
                  <button type="button" class="sidebar-menu-item logout-btn" id="logout-sidebar-btn-global" style="--accent:var(--red);width:100%;text-align:left;border:none;background:transparent;cursor:pointer;">
                    <span class="sidebar-menu-icon" style="background:var(--red-light);color:var(--red)"><i data-lucide="log-out"></i></span>
                    <span class="sidebar-menu-text">Sign Out</span>
                  </button>
                </li>
              </ul>
            </div>
          </nav>
        </div>
      </aside>
      <div class="sidebar-overlay" id="sidebar-overlay"></div>
    `;

    // Create wrappers
    const sidebarContainer = document.createElement('div');
    sidebarContainer.innerHTML = sidebarHtml;

    const mainContent = document.createElement('div');
    mainContent.className = 'dash-main-content';

    const topbarHtml = `
      <header class="dash-topbar no-print">
        <button class="sidebar-toggle" id="sidebar-toggle-global" aria-label="Open menu"><i data-lucide="menu"></i></button>
        <div class="dash-topbar-brand">
          <svg class="akili-mark" viewBox="0 0 32 32" fill="none" aria-hidden="true" style="width:24px;height:24px;">
            <circle cx="16" cy="16" r="14" stroke="#2563EB" stroke-width="2"/>
            <circle cx="16" cy="16" r="6" fill="#2563EB"/>
            <circle cx="18" cy="14" r="2" fill="#fff"/>
          </svg>
          <span style="font-weight:700;color:var(--navy);font-size:1.15rem;margin-left:0.35rem;">AKILI</span>
        </div>
        <div class="dash-topbar-right">
          <span id="health-dot" class="health-dot" title="API status"></span>
          <span id="health-label" class="hide-mobile" style="font-size:0.7rem;color:#64748B;margin-left:4px">…</span>
        </div>
      </header>
    `;

    mainContent.innerHTML = topbarHtml;

    // Relocate original container
    container.parentNode.insertBefore(layout, container);
    
    while (sidebarContainer.firstChild) {
      layout.appendChild(sidebarContainer.firstChild);
    }
    layout.appendChild(mainContent);

    container.classList.add('dashboard-shell');
    container.style.padding = '';
    container.style.maxWidth = '';
    mainContent.appendChild(container);

    const sidebarEl = layout.querySelector('#dash-sidebar');
    const overlayEl = layout.querySelector('#sidebar-overlay');
    const toggleBtn = layout.querySelector('#sidebar-toggle-global');
    const closeBtn = layout.querySelector('#sidebar-close');

    function toggleSidebar() {
      sidebarEl.classList.toggle('open');
      overlayEl.classList.toggle('open');
    }

    if (toggleBtn) toggleBtn.addEventListener('click', toggleSidebar);
    // Support legacy pages that use id="sidebar-toggle"
    const legacyToggle = document.getElementById('sidebar-toggle');
    if (legacyToggle && legacyToggle !== toggleBtn) legacyToggle.addEventListener('click', toggleSidebar);
    if (closeBtn) closeBtn.addEventListener('click', toggleSidebar);
    if (overlayEl) overlayEl.addEventListener('click', toggleSidebar);

    const logoutBtn = layout.querySelector('#logout-sidebar-btn-global');
    if (logoutBtn) {
      logoutBtn.addEventListener('click', () => {
        localStorage.removeItem('akili_token');
        localStorage.removeItem('akili_user');
        localStorage.removeItem('akili_api_key');
        location.href = 'index.html';
      });
    }

    const globalDocs = layout.querySelector('#global-sidebar-api-docs');
    if (globalDocs) globalDocs.href = `${API().replace(/\/$/, '')}/docs`;

    if (typeof lucide !== 'undefined') {
      lucide.createIcons();
    }
    
    setTimeout(() => {
      initHealth();
    }, 100);
  }

  window.AKILI.updateNavAuth = updateNavAuth;

  document.addEventListener('DOMContentLoaded', () => {
    initSidebarLayout();
    initBackgroundEyes();
    initAkiliCursor();
    document.addEventListener('click', (e) => {
      const btn = e.target.closest('button, .btn');
      if (!btn || btn.disabled || btn.classList.contains('is-loading')) return;
      if (btn.closest('.scan-session-list')) return;
      btn.classList.add('is-loading');
      setTimeout(() => btn.classList.remove('is-loading'), 1200);
    }, true);
    loadNav();
    watchNavMount();
    setTimeout(updateNavAuth, 300);
    setInterval(() => {
      if (document.getElementById('health-dot')) initHealth();
    }, 60000);
  });
})();
