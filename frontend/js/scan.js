(function () {
  const cfg = window.AKILI_SCAN || {};
  const sandbox = cfg.sandbox || false;
  if (!cfg.public && !sandbox) {
    const token = localStorage.getItem('akili_token');
    if (!token) {
      location.href = 'signup.html';
      return;
    }
  }
  const SCAN_MODULE = cfg.module || 'scan';
  const endpoint = cfg.endpoint || '/api/v1/scan/website';
  const buildBody = cfg.buildBody || (() => ({}));

  let terminal = document.getElementById('terminal');
  let results = document.getElementById('results');
  const btn = document.getElementById('scan-btn');
  let statusBar = document.getElementById('scan-status');
  let resultsSpinner = document.getElementById('results-spinner');
  let scanAbort = null;
  let activeScanId = null;
  const sessionStore = new Map();

  const ACCURACY_HTML = `
    <div class="results-accuracy-disclaimer">
      <strong>Results may be inaccurate</strong>
      AKILI uses automated OSINT and security checks. Findings can be incomplete, outdated, or wrong — especially person matches and breach lists. Verify anything important before you act.
    </div>`;

  function scanHeaders() {
    const headers = { 'Content-Type': 'application/json' };
    const key = AKILI.getApiKey();
    if (key) headers['X-API-Key'] = key;
    const token = AKILI.getToken();
    if (token) headers['Authorization'] = `Bearer ${token}`;
    return headers;
  }

  function targetLabelFromBody(body) {
    return (
      body.url || body.email || body.name || body.domain || body.target
      || body.ip || JSON.stringify(body).slice(0, 48)
    );
  }

  function initScanWorkspace() {
    if (!terminal || !results || document.querySelector('.scan-workspace')) {
      resultsSpinner = document.getElementById('results-spinner');
      return;
    }
    const anchor = terminal;
    const parent = anchor.parentNode;
    const ws = document.createElement('div');
    ws.className = 'scan-workspace';

    const left = document.createElement('aside');
    left.className = 'scan-sessions-panel';
    left.innerHTML = `
      <p class="scan-panel-title">Scan sessions</p>
      <p class="label-sm" style="margin:0 0 0.5rem;color:var(--slate)">Live log for each run on this page.</p>
      <div id="scan-session-list" class="scan-session-list"></div>
    `;

    const right = document.createElement('section');
    right.className = 'scan-results-panel';
    right.innerHTML = ACCURACY_HTML;
    resultsSpinner = document.createElement('div');
    resultsSpinner.id = 'results-spinner';
    resultsSpinner.className = 'scan-results-spinner hidden';
    resultsSpinner.innerHTML = '<div class="spinner-ring" aria-hidden="true"></div><p>AKILI is analyzing your target…</p>';

    parent.insertBefore(ws, anchor);
    ws.appendChild(left);
    left.appendChild(terminal);
    ws.appendChild(right);
    right.appendChild(resultsSpinner);
    right.appendChild(results);

    terminal.classList.remove('hidden');
    results.classList.add('hidden');
  }

  function renderSessionList() {
    const list = document.getElementById('scan-session-list');
    if (!list) return;
    const items = [...sessionStore.values()].sort((a, b) => b.started - a.started);
    list.innerHTML = items.length
      ? items.map((s) => `
        <button type="button" class="scan-session-item ${s.id === activeScanId ? 'active' : ''} ${s.status}"
          data-id="${AKILI.escapeHtml(s.id)}">
          <span class="scan-session-target">${AKILI.escapeHtml(s.targetLabel)}</span>
          <span class="scan-session-state">${s.status === 'running' ? 'Running…' : 'Complete'}</span>
        </button>`).join('')
      : '<p class="label-sm" style="color:var(--slate)">No scans yet — run one above.</p>';
    list.querySelectorAll('.scan-session-item').forEach((el) => {
      el.onclick = () => selectSession(el.dataset.id);
    });
  }

  function selectSession(scanId) {
    const s = sessionStore.get(scanId);
    if (!s) return;
    activeScanId = scanId;
    renderSessionList();
    if (terminal) {
      terminal.innerHTML = '';
      ensureTerminalHeader();
      s.lines.forEach((line) => {
        const el = document.createElement('div');
        el.className = lineClass(line);
        el.textContent = line;
        terminal.appendChild(el);
      });
      terminal.scrollTop = terminal.scrollHeight;
    }
    if (s.status === 'running') {
      showResultsLoading(true);
    } else if (s.report) {
      showResultsLoading(false);
      renderResults(s.report, scanId);
    }
  }

  function showResultsLoading(loading) {
    if (resultsSpinner) resultsSpinner.classList.toggle('hidden', !loading);
    if (results) results.classList.toggle('hidden', loading);
  }

  function ensureStatusBar() {
    if (!terminal || statusBar) return statusBar;
    statusBar = document.createElement('div');
    statusBar.id = 'scan-status';
    statusBar.className = 'scan-status';
    statusBar.innerHTML = '<span class="pulse" aria-hidden="true"></span><span class="scan-status-text">Starting scan…</span>';
    const panel = terminal.closest('.scan-sessions-panel') || terminal.parentNode;
    panel.insertBefore(statusBar, terminal);
    return statusBar;
  }

  function ensureTerminalHeader() {
    if (!terminal || terminal.querySelector('.terminal-module-label')) return;
    const label = document.createElement('div');
    label.className = 'terminal-module-label';
    label.textContent = `${SCAN_MODULE} scan session`;
    terminal.prepend(label);
  }

  function lineClass(line) {
    if (line.startsWith('[THINK]')) return 'line-think';
    if (line.startsWith('[PLAN]')) return 'line-plan';
    if (line.startsWith('[PROGRESS]')) return 'line-progress';
    if (line.startsWith('[AKILI]')) return 'line-akili';
    if (line.startsWith('[TOOL]')) return 'line-tool';
    if (line.startsWith('[FOUND]')) return 'line-found';
    if (line.startsWith('[CRITICAL]')) return 'line-critical';
    if (line.startsWith('[OK]')) return 'line-ok';
    if (line.startsWith('[AI]')) return 'line-ai';
    if (line.startsWith('[DONE]')) return 'line-done';
    return 'line-akili';
  }

  function stripPrefix(line) {
    return line.replace(/^\[[A-Z]+\]\s*/, '').trim();
  }

  function updateLiveStatus(line) {
    const bar = ensureStatusBar();
    if (!bar) return;
    const el = bar.querySelector('.scan-status-text');
    if (el) el.textContent = stripPrefix(line);
    bar.classList.add('active');
    if (line.startsWith('[DONE]')) bar.classList.remove('active');
    document.body.classList.add('akili-scan-active');
  }

  function appendTerminal(text, scanId) {
    if (!terminal || scanId !== activeScanId) return;
    terminal.classList.remove('hidden');
    const session = sessionStore.get(scanId);
    text.split('\n').forEach((line) => {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('COMPLETE:')) return;
      if (session) session.lines.push(trimmed);
      const el = document.createElement('div');
      el.className = lineClass(trimmed);
      el.textContent = trimmed;
      terminal.appendChild(el);
      if (/^\[(THINK|PLAN|PROGRESS|TOOL|AI|AKILI)\]/.test(trimmed)) {
        updateLiveStatus(trimmed);
      }
    });
    terminal.scrollTop = terminal.scrollHeight;
  }

  function renderWebsite(report) {
    const grade = (report.grade || '—').toUpperCase();
    const gradeEl = document.getElementById('grade');
    if (gradeEl) gradeEl.innerHTML = `<div class="grade-lg grade-${grade}">${grade}</div>`;
    const sumEl = document.getElementById('summary');
    if (sumEl) sumEl.textContent = report.summary || report.ai_summary || '';
    const purposeEl = document.getElementById('site-purpose');
    if (purposeEl) {
      const bits = [
        report.site_purpose,
        report.page_h1 && `Heading: ${report.page_h1}`,
        report.page_title && `Title: ${report.page_title}`,
        report.page_description,
      ].filter(Boolean);
      purposeEl.textContent = bits.join('\n\n') || 'No description available from scan.';
      let eduNote = document.getElementById('site-edu-note');
      if (report.domain_profile === 'education') {
        if (!eduNote) {
          purposeEl.insertAdjacentHTML('afterend', '<p id="site-edu-note" class="label-sm" style="margin-top:0.5rem;color:var(--blue)">Educational / institutional site — scored with university-appropriate expectations.</p>');
        }
      } else if (eduNote) eduNote.remove();
    }
    const legitBadge = document.getElementById('legitimacy-badge');
    const legitNotes = document.getElementById('legitimacy-notes');
    const legit = (report.legitimacy || 'unclear').toLowerCase();
    if (legitBadge) {
      const cls = legit === 'likely_legit' ? 'badge-low' : legit === 'suspicious' ? 'badge-high' : 'badge-info';
      legitBadge.className = `badge ${cls}`;
      legitBadge.textContent = legit.replace(/_/g, ' ');
    }
    if (legitNotes) legitNotes.textContent = report.legitimacy_notes || '';
    const fg = document.getElementById('findings-grid');
    if (fg) {
      fg.innerHTML = (report.findings || []).map((f) => `
        <div class="card"><span class="badge badge-${(f.severity || 'info').toLowerCase()}">${f.severity}</span>
        <h4>${AKILI.escapeHtml(f.name || '')}</h4><p>${AKILI.escapeHtml(f.explanation || '')}</p>
        <p style="color:var(--blue)">${AKILI.escapeHtml(f.recommendation || '')}</p></div>
      `).join('');
    }
    fillTable('ports-table', report.ports, (p) => `<tr><td>${p.port}</td><td>${p.service || '—'}</td><td>${p.status || '—'}</td><td>${p.risk || '—'}</td></tr>`, 4);
    fillTable('dns-table', report.dns, (r) => `<tr><td>${AKILI.escapeHtml(r.type || '')}</td><td>${AKILI.escapeHtml(r.value || '')}</td></tr>`, 2);
    const stack = report.tech_stack || [];
    if (window.AKILI_CVE) {
      AKILI_CVE.renderTechStack(stack, 'tech-stack-cards', report.cve_data_source);
      AKILI_CVE.renderTechChanges(report.tech_changes, 'tech-changes');
      AKILI_CVE.renderScoreTimeline(report.score_history, 'score-timeline-section');
    }
    bindDomainVerify(report);
  }

  function bindDomainVerify(report) {
    const verifyBtn = document.getElementById('verify-domain-btn');
    const badge = document.getElementById('verify-badge');
    const instr = document.getElementById('verify-instructions');
    if (!verifyBtn) return;
    let domain = '';
    try {
      domain = new URL(AKILI.externalUrl(report.target || document.getElementById('url')?.value || '')).hostname;
    } catch {
      domain = (report.target || '').replace(/^https?:\/\//, '').split('/')[0];
    }
    if (!domain) return;

    async function refreshStatus() {
      try {
        const info = await AKILI.apiFetch(`/api/v1/verify/domain/${encodeURIComponent(domain)}`).then((r) => r.json());
        if (badge) {
          badge.textContent = info.verified ? 'Verified' : 'Unverified';
          badge.className = `badge ${info.verified ? 'badge-low' : 'badge-info'}`;
        }
        if (instr && info.txt_record && !info.verified) {
          instr.textContent = `Add TXT record at your DNS host: ${info.txt_record}`;
        }
      } catch {
        if (badge) badge.textContent = 'Unverified';
      }
    }

    verifyBtn.onclick = async () => {
      try {
        const data = await AKILI.apiFetch('/api/v1/verify/domain', {
          method: 'POST',
          body: JSON.stringify({ domain }),
        }).then((r) => r.json());
        if (instr) instr.textContent = data.instructions || `Add TXT: ${data.txt_record}`;
        AKILI.showToast('TXT record generated — add it at your DNS provider', 'success');
        await refreshStatus();
      } catch (e) {
        AKILI.showToast(e.message || 'Verification failed', 'error');
      }
    };
    refreshStatus();
  }

  function renderIp(report) {
    const sumEl = document.getElementById('summary');
    if (sumEl) sumEl.textContent = report.summary || report.hosted_websites_summary || '';
    const ws = document.getElementById('ip-websites-summary');
    if (ws) ws.textContent = report.hosted_websites_summary || '';
    const list = document.getElementById('ip-websites-list');
    const sites = report.hosted_websites || [];
    if (list) {
      list.innerHTML = sites.length
        ? sites.map((s) => `
          <li style="margin-bottom:0.65rem">
            ${AKILI.externalLink(s.url, s.hostname || s.url)}
            ${s.title ? ` — <em>${AKILI.escapeHtml(s.title)}</em>` : ''}
            ${s.status_code ? ` <span class="label-sm">HTTP ${s.status_code}</span>` : ''}
          </li>`).join('')
        : (report.reverse_dns
          ? `<li>${AKILI.externalLink(`https://${report.reverse_dns}`, report.reverse_dns)} (reverse DNS)</li>`
          : '<li>No public website hostname found for this IP.</li>');
    }
    const geo = document.getElementById('ip-geo');
    const g = report.geolocation || {};
    if (geo) {
      geo.textContent = [
        g.city && `City: ${g.city}`,
        g.country && `Country: ${g.country}`,
        g.isp && `ISP: ${g.isp}`,
        g.org && `Org: ${g.org}`,
        g.asn && `ASN: ${g.asn}`,
        report.reverse_dns && `Reverse DNS: ${report.reverse_dns}`,
      ].filter(Boolean).join(' · ') || 'No geolocation data';
    }
    fillTable('ip-ports-table', report.ports, (p) => `<tr><td>${p.port}</td><td>${p.status || p.service || 'open'}</td></tr>`, 2);
  }

  function renderEmail(report) {
    const sumEl = document.getElementById('summary');
    const breaches = report.breaches || [];
    const pwned = report.pwned || breaches.length > 0;
    const src = report.breach_source || 'breach databases';
    if (sumEl) {
      sumEl.innerHTML = `
        <div class="card" style="border-left:4px solid ${pwned ? 'var(--red)' : 'var(--green)'};margin-bottom:1rem">
          <p class="label-sm">${pwned ? 'Pwned' : 'No breaches found'}</p>
          <h2 style="margin:0.25rem 0">${AKILI.escapeHtml(report.email || report.target || '')}</h2>
          <p>${AKILI.escapeHtml(report.summary || report.ai_summary || '')}</p>
          <p class="label-sm" style="margin-top:0.5rem">Sources: ${AKILI.escapeHtml(src)}</p>
        </div>`;
    }
    const list = document.getElementById('breach-list');
    if (list) {
      list.innerHTML = breaches.length
        ? breaches.map((b) => `
          <li style="margin-bottom:0.5rem">
            <strong>${AKILI.escapeHtml(b.name || 'Unknown')}</strong>
            ${b.year ? ` <span class="label-sm">(${AKILI.escapeHtml(b.year)})</span>` : ''}
            ${b.link ? ` — ${AKILI.externalLink(b.link, 'View breach')}` : ''}
            ${(b.exposed_data || []).length ? `<br><span class="label-sm">Exposed: ${AKILI.escapeHtml((b.exposed_data || []).slice(0, 6).join(', '))}</span>` : ''}
          </li>`).join('')
        : '<li>No breaches in AKILI databases for this email.</li>';
    }
    const rec = document.getElementById('email-recommendations');
    if (rec) {
      const items = report.recommendations || [];
      rec.innerHTML = items.length
        ? `<ul>${items.map((r) => `<li>${AKILI.escapeHtml(r)}</li>`).join('')}</ul>`
        : '<p class="label-sm">Use unique passwords and MFA on all accounts.</p>';
    }
  }

  function renderPerson(report) {
    const PLATFORM_SVGS = {
      github: '<svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.22 2.2.82A7.6 7.6 0 018 4.6c.68.003 1.36.092 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.28.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.19 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/></svg>',
      twitter: '<svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path d="M22.46 6c-.77.35-1.6.58-2.46.69a4.3 4.3 0 001.88-2.37 8.59 8.59 0 01-2.72 1.04 4.28 4.28 0 00-7.29 3.9A12.14 12.14 0 013 4.79a4.28 4.28 0 001.32 5.72 4.25 4.25 0 01-1.94-.54v.05a4.28 4.28 0 003.43 4.2 4.3 4.3 0 01-1.93.07 4.29 4.29 0 004 2.97A8.6 8.6 0 012 19.54a12.13 12.13 0 006.56 1.92c7.88 0 12.2-6.53 12.2-12.2 0-.19-.01-.39-.02-.58A8.7 8.7 0 0022.46 6z"/></svg>',
      instagram: '<svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path d="M7 2C4.24 2 2 4.24 2 7v10c0 2.76 2.24 5 5 5h10c2.76 0 5-2.24 5-5V7c0-2.76-2.24-5-5-5H7zm5 5.5A3.5 3.5 0 0115.5 11 3.5 3.5 0 0112 14.5 3.5 3.5 0 018.5 11 3.5 3.5 0 0112 7.5zM18 6.5a.9.9 0 11-1.8 0 .9.9 0 011.8 0zM12 9.2a1.8 1.8 0 100 3.6 1.8 1.8 0 000-3.6z"/></svg>',
      linkedin: '<svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path d="M4.98 3.5C4.98 4.88 3.88 6 2.5 6S0 4.88 0 3.5 1.12 1 2.5 1 4.98 2.12 4.98 3.5zM0 8h5v14H0V8zm7.5 0H12v2.2h.1c.5-1 1.8-2.2 3.7-2.2 4 0 4.7 2.6 4.7 6V22h-5v-6.5c0-1.6 0-3.8-2.4-3.8-2.4 0-2.8 1.9-2.8 3.7V22h-5V8z"/></svg>',
    };
    const pn = document.getElementById('person-name');
    if (pn) pn.textContent = report.name || 'Subject';
    const conf = report.confidence ?? report.score ?? 0;
    const cv = document.getElementById('confidence-value');
    if (cv) cv.textContent = `${conf}%`;
    const cb = document.getElementById('confidence-breakdown');
    if (cb) {
      const bd = report.confidence_breakdown || {};
      const signals = bd.signals || report.trust_signals || [];
      const flags = bd.red_flags || report.red_flags || [];
      cb.innerHTML = [
        ...signals.map((s) => `<li style="color:var(--green)">+ ${AKILI.escapeHtml(s)}</li>`),
        ...flags.map((s) => `<li style="color:var(--red)">− ${AKILI.escapeHtml(s)}</li>`),
      ].join('') || '<li>Insufficient breakdown data</li>';
    }
    const platforms = report.platforms || {};
    const pb = document.getElementById('platforms-block');
    const pl = document.getElementById('platforms-list');
    if (pb && pl) {
      const entries = Object.entries(platforms).filter(([, v]) => v && v.found);
      if (entries.length) {
        pb.classList.remove('hidden');
        const extractHandle = (url, platform) => {
          if (!url) return '';
          try {
            if (platform === 'github') {
              const m = url.match(/github\.com\/([\w\-]+)/i); if (m) return '@' + m[1];
            } else if (platform === 'twitter' || platform === 'x') {
              const m = url.match(/(?:twitter|x)\.com\/(?:#!\/)?([\w_]+)/i); if (m) return '@' + m[1];
            } else if (platform === 'instagram') {
              const m = url.match(/instagram\.com\/([\w\.]+)/i); if (m) return '@' + m[1];
            } else if (platform === 'linkedin') {
              const m = url.match(/linkedin\.com\/(?:in|pub)\/([\w\-]+)/i); if (m) return m[1];
            }
          } catch (e) {}
          return '';
        };
        pl.innerHTML = entries.map(([k, v]) => {
          const handle = extractHandle(v.url, k);
          const label = handle ? `${k} · ${handle}` : k;
          const href = AKILI.externalUrl(v.url || '');
          const svg = PLATFORM_SVGS[k] || '';
          const linkHtml = href
            ? `<a href="${AKILI.escapeHtml(href)}" target="_blank" rel="noopener noreferrer" class="platform-pill">${svg}<span style="margin-left:6px">${AKILI.escapeHtml(label)}</span></a>`
            : AKILI.escapeHtml(label);
          return linkHtml;
        }).join('');
        // render social profile cards if available
        const scBlock = document.getElementById('social-cards-block');
        const scList = document.getElementById('social-cards-list');
        let cards = report.social_cards || [];
        // Fallback: if no social_cards from backend, infer from discovered URLs
        if ((!cards || cards.length === 0) && Array.isArray(report.all_urls) && report.all_urls.length) {
          const inferHandle = (url, platform) => {
            try {
              if (platform === 'github') { const m = url.match(/github\.com\/([\w\-]+)/i); if (m) return '@' + m[1]; }
              if (platform === 'twitter' || platform === 'x') { const m = url.match(/(?:twitter|x)\.com\/(?:#!\/)?([\w_]+)/i); if (m) return '@' + m[1]; }
              if (platform === 'instagram') { const m = url.match(/instagram\.com\/([\w\.]+)/i); if (m) return '@' + m[1]; }
              if (platform === 'linkedin') { const m = url.match(/linkedin\.com\/(?:in|pub)\/([\w\-]+)/i); if (m) return m[1]; }
            } catch (e) {}
            return '';
          };
          const inferred = [];
          report.all_urls.forEach((u) => {
            ['github','twitter','instagram','linkedin','x'].forEach((p) => {
              if (inferred.find(ic => (ic.profile_url || ic.url) === u)) return;
              const key = p === 'x' ? 'twitter' : p;
              const re = key === 'github' ? /github\.com\/[\w\-]+/i : key === 'twitter' ? /(?:twitter|x)\.com\/(?:#!\/)?[\w_]+/i : key === 'instagram' ? /instagram\.com\/[\w\.]+/i : key === 'linkedin' ? /linkedin\.com\/(?:in|pub)\/[\w\-]+/i : null;
              if (re && re.test(u)) {
                inferred.push({ platform: key, profile_url: u, url: u, handle: inferHandle(u, key) });
              }
            });
          });
          if (inferred.length) cards = inferred;
        }
        if (scBlock && scList) {
          if (cards.length) {
            scBlock.classList.remove('hidden');
            scList.innerHTML = cards.map((c) => {
              const p = (c.platform || 'profile').toLowerCase();
              const svg = PLATFORM_SVGS[p] || '';
              const h = c.handle ? `${AKILI.escapeHtml(c.handle)}` : '';
              const title = h ? `${p} · ${h}` : p;
              const bio = c.bio ? `<div class="label-sm" style="color:var(--slate);margin-top:0.25rem">${AKILI.escapeHtml(c.bio)}</div>` : '';
              const meta = (c.repo_count || c.followers) ? `<div class="label-sm" style="margin-top:0.25rem;color:var(--slate)">${c.repo_count ? c.repo_count + ' repos' : ''}${c.repo_count && c.followers ? ' · ' : ''}${c.followers ? c.followers + ' followers' : ''}</div>` : '';
              const href = AKILI.externalUrl(c.profile_url || c.url || '');
              const linkHtml = href
                ? `<a href="${AKILI.escapeHtml(href)}" target="_blank" rel="noopener noreferrer" class="platform-pill">${svg}<span style="margin-left:6px">${AKILI.escapeHtml(title)}</span></a>`
                : AKILI.escapeHtml(title);
              return `<div class="social-card">${linkHtml}${bio}${meta}</div>`;
            }).join('');
          } else {
            scBlock.classList.add('hidden');
            scList.innerHTML = '';
          }
        }
      } else pb.classList.add('hidden');
    }
    const breaches = report.breaches || [];
    const bb = document.getElementById('breaches-block');
    const bl = document.getElementById('breaches-list');
    if (bb && bl) {
      if (breaches.length) {
        bb.classList.remove('hidden');
        bl.innerHTML = breaches.slice(0, 8).map((b) =>
          `<li>${AKILI.escapeHtml(b.name || b.title || JSON.stringify(b))}</li>`
        ).join('');
      } else bb.classList.add('hidden');
    }
    const renderGrid = (id, imgs, verified) => {
      const grid = document.getElementById(id);
      if (!grid) return;
      const list = (imgs || []).map((img, i) => ({ ...img, verified: img.verified ?? verified }));
      grid.innerHTML = list.length
        ? list.slice(0, 12).map((img, i) =>
            `<button type="button" class="person-img-btn" data-idx="${i}" aria-label="View image">
              <img src="${AKILI.escapeHtml(AKILI.externalUrl(img.url) || '')}" alt="" loading="lazy" referrerpolicy="no-referrer" onerror="this.parentElement.style.display='none'">
            </button>`
          ).join('')
        : `<p class="label-sm" style="grid-column:1/-1">${verified ? 'No verified profile images found.' : 'No web images found.'}</p>`;
      grid.querySelectorAll('.person-img-btn').forEach((el) => {
        el.onclick = () => AKILI.openImageModal(list, +el.dataset.idx);
      });
    };
    renderGrid('verified-image-grid', report.verified_images, true);
    renderGrid('web-image-grid', report.web_images || report.images, false);
    const narrBlock = document.getElementById('profile-narrative-block');
    const narr = report.profile_narrative || '';
    const facts = [
      report.age_context && `Age / stage: ${report.age_context}`,
      report.role_hint && `Role: ${report.role_hint}`,
      report.location_hint && `Location: ${report.location_hint}`,
    ].filter(Boolean);
    if (narrBlock && (narr || facts.length)) {
      narrBlock.style.display = '';
      const ne = document.getElementById('profile-narrative');
      if (ne) ne.textContent = narr;
      const pf = document.getElementById('profile-facts');
      if (pf) pf.innerHTML = facts.map((f) => `<li>${AKILI.escapeHtml(f)}</li>`).join('');
    } else if (narrBlock) narrBlock.style.display = 'none';
    const ai = document.getElementById('ai-summary');
    if (ai) ai.textContent = report.ai_summary || report.summary || '';
    const oa = document.getElementById('overall-assessment');
    if (oa) oa.textContent = report.overall_assessment
      ? `Overall: ${report.overall_assessment.replace(/_/g, ' ')}`
      : '';
  }

  function fillTable(id, rows, rowFn, cols = 4) {
    const tbody = document.querySelector(`#${id} tbody`);
    if (!tbody) return;
    tbody.innerHTML = rows && rows.length ? rows.map(rowFn).join('') : `<tr><td colspan="${cols}">No data</td></tr>`;
  }

  function renderResults(report, scanId) {
    if (scanId !== activeScanId) return;
    const session = sessionStore.get(scanId);
    if (session) {
      session.status = 'done';
      session.report = report;
      renderSessionList();
    }
    showResultsLoading(false);
    if (cfg.module === 'person') renderPerson(report);
    else if (cfg.module === 'email') renderEmail(report);
    else if (cfg.module === 'ip') renderIp(report);
    else renderWebsite(report);
    AKILI.showToast('Scan complete', 'success');
    if (report.scan_id && !sandbox) {
      const view = document.createElement('p');
      view.className = 'scan-report-link no-print';
      view.style.marginTop = '1rem';
      view.innerHTML = `<a href="report.html?id=${encodeURIComponent(report.scan_id)}" class="btn btn-outline btn-sm">View full report</a>`;
      const resultsEl = document.getElementById('results');
      if (resultsEl && !resultsEl.querySelector('.scan-report-link')) {
        resultsEl.appendChild(view);
      }
    }
    document.body.classList.remove('akili-scan-active');
    if (typeof lucide !== 'undefined') lucide.createIcons();
    if (typeof AKILI.refreshHealth === 'function') AKILI.refreshHealth();
  }

  async function runScan() {
    const body = buildBody();
    if (cfg.validate && cfg.validate(body)) return;

    if (scanAbort) scanAbort.abort();
    scanAbort = new AbortController();
    activeScanId = typeof crypto !== 'undefined' && crypto.randomUUID
      ? crypto.randomUUID()
      : `scan-${Date.now()}`;
    const thisScanId = activeScanId;
    const label = targetLabelFromBody(body);

    sessionStore.set(thisScanId, {
      id: thisScanId,
      targetLabel: label,
      status: 'running',
      started: Date.now(),
      lines: [],
      report: null,
    });
    renderSessionList();

    btn.disabled = true;
    btn.textContent = 'Scanning...';
    if (terminal) {
      terminal.innerHTML = '';
      ensureTerminalHeader();
      terminal.dataset.scanModule = SCAN_MODULE;
      terminal.dataset.scanId = thisScanId;
      terminal.classList.remove('hidden');
    }
    if (statusBar) {
      statusBar.classList.add('active');
      const t = statusBar.querySelector('.scan-status-text');
      if (t) t.textContent = `Starting ${SCAN_MODULE} scan…`;
    }
    showResultsLoading(true);
    AKILI.showToast(`${SCAN_MODULE} scan started`, 'info');
    document.body.classList.add('akili-scan-active');

    const url = sandbox
      ? `${AKILI.API()}${endpoint.replace('/api/v1/', '/api/v1/sandbox/')}?scenario=${cfg.scenario || 'clean_scan'}`
      : `${AKILI.API()}${endpoint}`;

    try {
      const res = await fetch(url, {
        method: 'POST',
        headers: scanHeaders(),
        body: JSON.stringify(body),
        signal: scanAbort.signal,
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || err.message || res.statusText);
      }

      const reader = res.body.getReader();
      const dec = new TextDecoder();
      let buf = '';
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (thisScanId !== activeScanId) break;
        buf += dec.decode(value, { stream: true });
        const parts = buf.split('\n');
        buf = parts.pop() || '';
        for (const line of parts) {
          if (line.startsWith('COMPLETE:')) {
            try { renderResults(JSON.parse(line.slice(9)), thisScanId); } catch (_) {}
          } else {
            appendTerminal(line, thisScanId);
          }
        }
      }
      if (buf.startsWith('COMPLETE:') && thisScanId === activeScanId) {
        try { renderResults(JSON.parse(buf.slice(9)), thisScanId); } catch (_) {}
      }
    } catch (e) {
      if (e.name === 'AbortError') return;
      AKILI.showToast(e.message || 'Scan failed', 'error');
      appendTerminal('[CRITICAL] ' + (e.message || 'Error'), thisScanId);
      showResultsLoading(false);
      const session = sessionStore.get(thisScanId);
      if (session) {
        session.status = 'done';
        renderSessionList();
      }
      document.body.classList.remove('akili-scan-active');
    } finally {
      if (thisScanId === activeScanId) {
        btn.disabled = false;
        btn.textContent = cfg.buttonLabel || 'SCAN';
        if (statusBar) statusBar.classList.remove('active');
        document.body.classList.remove('akili-scan-active');
        if (typeof AKILI.refreshHealth === 'function') AKILI.refreshHealth();
      }
    }
  }

  initScanWorkspace();
  if (terminal) {
    terminal.innerHTML = '';
    ensureTerminalHeader();
  }

  btn?.addEventListener('click', runScan);
  document.getElementById('export-btn')?.addEventListener('click', () => window.print());
})();
