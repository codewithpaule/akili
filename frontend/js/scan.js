(function () {
  // Read initial config to decide whether to allow public access.
  const _initial_cfg = window.AKILI_SCAN || {};
  const sandbox = _initial_cfg.sandbox || false;
  const _needsAuth = !_initial_cfg.public && !sandbox;

  function currentCfg() { return window.AKILI_SCAN || {}; }
  function currentModule() { return currentCfg().module || 'scan'; }
  function currentEndpoint() { return currentCfg().endpoint || '/api/v1/scan/website'; }
  function currentBuildBody() { return currentCfg().buildBody || (() => ({})); }

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
      AKILI uses automated OSINT and security checks. Findings can be incomplete, outdated, or wrong especially person matches and breach lists. Verify anything important before you act.
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
      : '<p class="label-sm" style="color:var(--slate)">No scans yet run one above.</p>';
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
      startPollingScanLogs(scanId);
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
    if (!terminal) return;
    let label = terminal.querySelector('.terminal-module-label');
    if (!label) {
      label = document.createElement('div');
      label.className = 'terminal-module-label';
      terminal.prepend(label);
    }
    const mod = terminal.dataset.scanModule || currentModule();
    const moduleLabel = {
      website: 'Website security scan',
      vulnerability: 'Vulnerability assessment',
      subdomains: 'Subdomain discovery',
      ip: 'IP address investigation',
      person: 'Person search',
      email: 'Email investigation',
      domain: 'Domain reputation check',
      organization: 'Organisation scan',
      company: 'Company intelligence',
      api: 'API surface scan',
    }[mod] || 'Scan';
    label.textContent = moduleLabel;
    label.style.display = 'block';
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
    const human = humanizeTerminalLine(line);
    const m = human.match(/^\[[A-Z]+\]\s*(.*)$/);
    if (m) return m[1].trim();
    return human.replace(/^\[[A-Z]+\]\s*/, '').trim();
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
    if (currentModule() === 'person' && /\d+\s+results\b/i.test(text)) {
      return;
    }
    if (!terminal || scanId !== activeScanId) return;
    terminal.classList.remove('hidden');
    const session = sessionStore.get(scanId);
    text.split('\n').forEach((line) => {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('COMPLETE:')) return;
      if (currentModule() === 'person') {
        const body = trimmed.replace(/^\[[A-Z]+\]\s*/, '');
        if (/Port \d+/i.test(body) || /Detected tech/i.test(body) || /tech stack/i.test(body)) {
          return;
        }
      }
      const display = humanizeTerminalLine(trimmed);
      if (session) session.lines.push(display);
      const el = document.createElement('div');
      el.className = lineClass(trimmed);
      el.textContent = display;
      terminal.appendChild(el);
      if (/^\[(THINK|PLAN|PROGRESS|TOOL|AI|AKILI)\]/.test(trimmed)) {
        updateLiveStatus(trimmed);
      }
    });
    terminal.scrollTop = terminal.scrollHeight;
  }

  // Poll persisted scan logs from the API and merge into session store.
  const pollers = new Map();
  async function fetchScanLogsOnce(scanId, since) {
    try {
      const url = `${AKILI.API()}/api/v1/scan/${encodeURIComponent(scanId)}/logs` + (since ? `?since=${encodeURIComponent(String(since))}` : '');
      const res = await fetch(url, { headers: scanHeaders() });
      if (!res.ok) return null;
      return await res.json().catch(() => null);
    } catch (e) { return null; }
  }

  function startPollingScanLogs(scanId, intervalMs = 2000) {
    if (!scanId || pollers.has(scanId)) return;
    let stopped = false;
    let lastTs = 0;
    const tick = async () => {
      if (stopped) return;
      const data = await fetchScanLogsOnce(scanId, lastTs);
      if (!data || !Array.isArray(data.items)) return;
      const items = data.items || [];
      if (!items.length) return;
      const session = sessionStore.get(scanId) || {
        id: scanId,
        targetLabel: scanId,
        status: 'running',
        started: Date.now(),
        lines: [],
        report: null,
      };
      const existing = new Set(session.lines || []);
      let status = 'running';
      items.forEach((it) => {
        if (!it) return;
        lastTs = Math.max(lastTs || 0, it.timestamp || 0);
        const kind = (it.kind || '').toUpperCase() || '';
        const msg = (it.message || '') + '';
        const line = kind ? `[${kind}] ${msg}` : msg;
        if (!existing.has(line)) {
          session.lines.push(line);
          existing.add(line);
        }
        if (kind === 'DONE') status = 'done';
      });
      // If report present in latest item(s), try to parse JSON from COMPLETE: payload
      const lastItem = items[items.length - 1] || {};
      if (lastItem.message && typeof lastItem.message === 'string' && lastItem.message.startsWith('COMPLETE:')) {
        try { session.report = JSON.parse(lastItem.message.slice(9)); } catch (_) {}
        status = 'done';
      }
      session.status = status;
      sessionStore.set(scanId, session);
      renderSessionList();
      if (activeScanId === scanId) {
        terminal.innerHTML = '';
        ensureTerminalHeader();
        session.lines.forEach((line) => appendTerminal(line, scanId));
        if (session.status === 'done' && session.report) renderResults(session.report, scanId);
      }
      if (session.status !== 'running') stopPollingScanLogs(scanId);
    };
    const id = setInterval(tick, intervalMs);
    pollers.set(scanId, { id, stop: () => { stopped = true; clearInterval(id); } });
    // run immediately
    tick();
  }

  function stopPollingScanLogs(scanId) {
    const p = pollers.get(scanId);
    if (!p) return;
    try { p.stop(); } catch (_) {}
    pollers.delete(scanId);
  }

  function severityBorder(findings) {
    const severities = (findings || []).map((f) => (f.severity || '').toUpperCase());
    if (severities.includes('CRITICAL') || severities.includes('HIGH')) return 'var(--red)';
    if (severities.includes('MEDIUM')) return 'var(--amber)';
    return 'var(--green)';
  }

  function websiteVerdict(report, findings) {
    const grade = (report.grade || '').toUpperCase();
    if (grade === 'A' || grade === 'B') return 'This site looks well configured. Keep it that way.';
    if (grade === 'F' || grade === 'D') return 'This site has serious issues that need attention right away.';
    if (grade === 'C') return 'Usable, but there are visible security gaps worth fixing.';
    return findings.length ? 'Quick check found issues worth reviewing.' : 'Quick check completed.';
  }

  function gradeNote(grade) {
    const g = (grade || '').toUpperCase();
    if (g === 'F' || g === 'D') return 'This site has serious issues that need attention right away.';
    if (g === 'A' || g === 'B') return 'This site looks well configured. Keep it that way.';
    return '';
  }

  function findingLink(f) {
    return AKILI.externalUrl(f.url || f.reference_url || f.link || '');
  }

  function renderWebsite(report) {
    const grade = (report.grade || '—').toUpperCase();
    const gradeEl = document.getElementById('grade');
    const gradeNoteText = gradeNote(grade);
    if (gradeEl) gradeEl.innerHTML = `<div class="grade-lg grade-${grade}">${grade}</div>${gradeNoteText ? `<p style="margin-top:0.5rem;color:var(--slate)">${AKILI.escapeHtml(gradeNoteText)}</p>` : ''}`;
    const sumEl = document.getElementById('summary');
    if (sumEl) {
      const topFindings = report.top_findings || report.findings || [];
      sumEl.innerHTML = `
        <div class="card" style="border-left:4px solid ${severityBorder(topFindings)};margin-bottom:1rem">
          <p class="label-sm">Website quick scan</p>
          <h2 style="margin:0.25rem 0">${AKILI.escapeHtml(report.url || report.target || '')}</h2>
          <p style="font-size:1rem;margin:0.35rem 0">${AKILI.escapeHtml(websiteVerdict(report, topFindings))}</p>
          <p class="label-sm">Grade: <strong>${AKILI.escapeHtml(grade)}</strong> · SSL: ${report.ssl_valid === false ? 'problem detected' : 'valid'}${report.ssl_expiry ? ` · expires in ${AKILI.escapeHtml(String(report.ssl_expiry))} days` : ''}</p>
          ${report.summary || report.ai_summary ? `<p>${AKILI.escapeHtml(report.summary || report.ai_summary)}</p>` : ''}
        </div>
        ${topFindings.length ? `
          <div class="card">
            <h3 style="margin-top:0">Top findings</h3>
            <ul>${topFindings.map((f) => `
              <li style="margin-bottom:0.55rem">
                <strong>${AKILI.escapeHtml(f.severity || 'INFO')}:</strong>
                ${AKILI.escapeHtml(f.name || f.title || 'Finding')}
                ${findingLink(f) ? ` - ${AKILI.externalLink(findingLink(f), 'Open evidence')}` : ''}
                ${f.explanation ? `<br><span class="label-sm">${AKILI.escapeHtml(f.explanation)}</span>` : ''}
                ${f.recommendation ? `<br><span class="label-sm" style="color:var(--blue)">Fix: ${AKILI.escapeHtml(f.recommendation)}</span>` : ''}
              </li>
            `).join('')}</ul>
          </div>` : `
          <div class="card">
            <h3 style="margin-top:0">No major issues found</h3>
            <p class="label-sm">This guest scan checked SSL and visible headers. Sign in for the deeper AI scan, DNS, ports, history, and legitimacy checks.</p>
          </div>`}
        ${((report.exposed_files || []).filter((p) => p && p.accessible && Number(p.status) === 200)).length ? `
          <div class="card">
            <h3 style="margin-top:0">Confirmed exposed paths</h3>
            <ul>${(report.exposed_files || []).filter((p) => p && p.accessible && Number(p.status) === 200).slice(0, 12).map((p) => `
              <li><span class="label-sm">${AKILI.escapeHtml(p.risk || 'INFO')}</span> ${AKILI.escapeHtml(p.path || '')} - HTTP ${AKILI.escapeHtml(String(p.status || 0))}</li>
            `).join('')}</ul>
          </div>` : ''}
        ${(report.interesting_links || report.hidden_paths || []).length ? `
          <div class="card">
            <h3 style="margin-top:0">Discovered links</h3>
            <ul>${[
              ...(report.interesting_links || []).map((u) => ({ url: u, label: u })),
              ...(report.hidden_paths || []).map((p) => ({ url: p.url, label: `${p.path} (HTTP ${p.status_code})` })),
            ].slice(0, 12).map((l) => `<li>${AKILI.externalLink(l.url, l.label || l.url)}</li>`).join('')}</ul>
          </div>` : ''}
        ${report.cta ? `<p class="label-sm" style="margin-top:0.75rem">${AKILI.escapeHtml(report.cta)}</p>` : ''}
      `;
    }
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
          purposeEl.insertAdjacentHTML('afterend', '<p id="site-edu-note" class="label-sm" style="margin-top:0.5rem;color:var(--blue)">Educational / institutional site, scored with university appropriate expectations.</p>');
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
        ${findingLink(f) ? `<p>${AKILI.externalLink(findingLink(f), 'Open evidence')}</p>` : ''}
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
    const domainsList = document.getElementById('ip-domains-list');
    const domains = report.hosted_domains || [];
    if (domainsList) {
      domainsList.innerHTML = domains.length
        ? domains.map((d) => `<li>${AKILI.externalLink(`https://${d}`, d)}</li>`).join('')
        : '<li>No reverse DNS, Shodan hostname, or hosted-domain data found.</li>';
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
    fillTable('ip-ports-table', report.ports, (p) => {
      const info = p.info || {};
      const evidence = info.banner || info.server || info.powered_by || (info.status_code ? `HTTP ${info.status_code}` : '');
      return `<tr><td>${p.port}</td><td>${AKILI.escapeHtml(p.service || 'unknown')}</td><td>${AKILI.escapeHtml(p.status || 'open')}</td><td>${AKILI.escapeHtml(evidence || p.risk || '')}</td></tr>`;
    }, 4);
  }

  function renderSubdomains(report) {
    const all = report.subdomains || report.active_subdomains || [];
    const active = report.active_subdomains || all.filter((s) => s.status === 'resolved');
    const sumEl = document.getElementById('summary');
    if (sumEl) {
      sumEl.innerHTML = `<div class="card" style="border-left:4px solid var(--mod-subdomain);margin-bottom:1rem">
        <p class="label-sm">Subdomain discovery</p>
        <h2 style="margin:0.25rem 0">${AKILI.escapeHtml(report.target || '')}</h2>
        <p>${AKILI.escapeHtml(report.summary || `Found ${all.length} subdomains; ${active.length} resolved publicly.`)}</p>
      </div>`;
    }
    fillTable('subdomains-table', all, (s) => `
      <tr>
        <td>${s.subdomain ? AKILI.externalLink(`https://${s.subdomain}`, s.subdomain) : ''}</td>
        <td>${AKILI.escapeHtml(s.ip || '')}</td>
        <td>${AKILI.escapeHtml(s.status || '')}</td>
        <td>${AKILI.escapeHtml(s.http_status ? String(s.http_status) : '')}</td>
        <td>${AKILI.escapeHtml(s.title || '')}</td>
      </tr>`, 5);
    const fg = document.getElementById('findings-grid');
    if (fg) {
      fg.innerHTML = (report.findings || []).map((f) => `
        <div class="card"><span class="badge badge-${(f.severity || 'info').toLowerCase()}">${AKILI.escapeHtml(f.severity || 'INFO')}</span>
        <h4>${AKILI.escapeHtml(f.name || '')}</h4><p>${AKILI.escapeHtml(f.explanation || '')}</p>
        <p style="color:var(--blue)">${AKILI.escapeHtml(f.recommendation || '')}</p></div>
      `).join('');
    }
  }

  function breachDate(breach) {
    return breach.date || breach.BreachDate || breach.year || breach.breach_date || '';
  }

  function breachLink(breach) {
    return breach.link || breach.source_link || breach.url || '';
  }

  function breachExposedData(breach) {
    return breach.exposed_data || breach.data_exposed || breach.DataClasses || [];
  }

  function renderBreachItems(breaches) {
    return breaches.map((b) => {
      const date = breachDate(b);
      const link = breachLink(b);
      const exposed = breachExposedData(b);
      return `
        <li style="margin-bottom:0.75rem">
          <strong>${AKILI.escapeHtml(b.name || b.title || 'Unknown breach')}</strong>
          ${date ? ` <span class="label-sm">(${AKILI.escapeHtml(String(date))})</span>` : ''}
          ${link ? ` - ${AKILI.externalLink(link, 'View source')}` : ''}
          ${exposed.length ? `<br><span class="label-sm">Exposed: ${AKILI.escapeHtml(exposed.slice(0, 8).join(', '))}</span>` : ''}
        </li>`;
    }).join('');
  }

  function renderEmail(report) {
    const sumEl = document.getElementById('summary');
    const breaches = report.breaches || [];
    const pwned = report.pwned || report.breach_found || breaches.length > 0;
    const src = report.breach_source || 'breach databases';
    if (sumEl) {
      sumEl.innerHTML = `
        <div class="card" style="border-left:4px solid ${pwned ? 'var(--red)' : 'var(--green)'};margin-bottom:1rem">
          <p class="label-sm">${pwned ? 'Pwned' : 'No breaches found'}</p>
          <h2 style="margin:0.25rem 0">${AKILI.escapeHtml(report.email || report.target || '')}</h2>
          <p>${AKILI.escapeHtml(report.summary || report.ai_summary || (report.mx_valid === false ? 'No valid MX records were found for this domain.' : 'Basic email checks completed.'))}</p>
          <p class="label-sm">Format: ${report.valid_format === false ? 'invalid' : 'valid'} · MX: ${report.mx_valid === false ? 'not found' : 'found'}</p>
          <p class="label-sm" style="margin-top:0.5rem">Sources: ${AKILI.escapeHtml(src)}</p>
        </div>
        <div class="card">
          <h3 style="margin-top:0">${breaches.length ? 'Breach details' : 'No breach details found'}</h3>
          ${breaches.length
            ? `<ul style="padding-left:1.1rem;margin-bottom:0">${renderBreachItems(breaches)}</ul>`
            : '<p class="label-sm">No matching public breach records were returned for this quick check.</p>'}
        </div>`;
    }
    const list = document.getElementById('breach-list');
    if (list) {
      list.innerHTML = breaches.length
        ? renderBreachItems(breaches)
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
      x: '<svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path d="M18.9 2h3.3l-7.2 8.2L23.5 22h-6.6l-5.2-6.8L5.8 22H2.5l7.7-8.8L2 2h6.8l4.7 6.2L18.9 2zm-1.2 18h1.8L7.8 3.9H5.9L17.7 20z"/></svg>',
      instagram: '<svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path d="M7 2C4.24 2 2 4.24 2 7v10c0 2.76 2.24 5 5 5h10c2.76 0 5-2.24 5-5V7c0-2.76-2.24-5-5-5H7zm5 5.5A3.5 3.5 0 0115.5 11 3.5 3.5 0 0112 14.5 3.5 3.5 0 018.5 11 3.5 3.5 0 0112 7.5zM18 6.5a.9.9 0 11-1.8 0 .9.9 0 011.8 0zM12 9.2a1.8 1.8 0 100 3.6 1.8 1.8 0 000-3.6z"/></svg>',
      linkedin: '<svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path d="M4.98 3.5C4.98 4.88 3.88 6 2.5 6S0 4.88 0 3.5 1.12 1 2.5 1 4.98 2.12 4.98 3.5zM0 8h5v14H0V8zm7.5 0H12v2.2h.1c.5-1 1.8-2.2 3.7-2.2 4 0 4.7 2.6 4.7 6V22h-5v-6.5c0-1.6 0-3.8-2.4-3.8-2.4 0-2.8 1.9-2.8 3.7V22h-5V8z"/></svg>',
    };

    const banner = document.getElementById('best-match-banner');
    const matchConf = (report.best_match_confidence || '').toLowerCase();
    if (banner) {
      if (matchConf === 'high') {
        banner.className = 'card';
        banner.style.cssText = 'margin-bottom:1rem;border-left:4px solid var(--green);background:#f0fdf4';
        banner.textContent = 'We are confident this is the right person.';
      } else if (matchConf === 'medium') {
        banner.className = 'card';
        banner.style.cssText = 'margin-bottom:1rem;border-left:4px solid var(--amber);background:#fffbeb';
        banner.textContent = 'This is likely the right person but we recommend verifying.';
      } else {
        banner.className = 'card';
        banner.style.cssText = 'margin-bottom:1rem;border-left:4px solid var(--slate);background:#f8fafc';
        banner.textContent = 'We found limited public information for this name and keyword combination. Try adding more context.';
      }
    }

    const pn = document.getElementById('person-name');
    if (pn) pn.textContent = report.name || 'Subject';
    const overviewBlock = document.getElementById('person-overview-block');
    const overviewEl = document.getElementById('person-overview');
    const overview = report.person_overview || report.profile_narrative || '';
    if (overviewBlock && overviewEl) {
      if (overview) {
        overviewBlock.style.display = '';
        overviewEl.textContent = overview;
      } else {
        overviewBlock.style.display = 'none';
        overviewEl.textContent = '';
      }
    }
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

    const pw = report.personal_website;
    const pwb = document.getElementById('personal-website-block');
    const pwc = document.getElementById('personal-website-card');
    if (pwb && pwc) {
      const url = pw && (pw.url || (typeof pw === 'string' ? pw : ''));
      if (url) {
        pwb.classList.remove('hidden');
        const confText = (pw.confidence || '').toLowerCase() === 'high'
          ? 'We are fairly confident this is their site'
          : 'This may be their site';
        const href = AKILI.externalUrl(url);
        pwc.innerHTML = `<a href="${AKILI.escapeHtml(href)}" target="_blank" rel="noopener noreferrer" class="platform-pill">${AKILI.escapeHtml(url)}</a><p class="label-sm" style="margin-top:0.35rem;color:var(--slate)">${AKILI.escapeHtml(confText)}</p>`;
      } else {
        pwb.classList.add('hidden');
        pwc.innerHTML = '';
      }
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
          const displayName = k === 'twitter' ? 'x' : k;
          const label = handle ? `${displayName} · ${handle}` : displayName;
          const href = AKILI.externalUrl(v.url || '');
          const svg = PLATFORM_SVGS[displayName] || '';
          return href
            ? `<a href="${AKILI.escapeHtml(href)}" target="_blank" rel="noopener noreferrer" class="platform-pill">${svg}<span style="margin-left:6px">${AKILI.escapeHtml(label)}</span></a>`
            : AKILI.escapeHtml(label);
        }).join('');
      } else pb.classList.add('hidden');
    }

    const scBlock = document.getElementById('social-cards-block');
    const scList = document.getElementById('social-cards-list');
    const cards = report.social_cards || [];
    if (scBlock && scList) {
      if (cards.length) {
        scBlock.classList.remove('hidden');
        scList.innerHTML = cards.map((c) => {
          const p = (c.platform || 'profile').toLowerCase() === 'twitter' ? 'x' : (c.platform || 'profile').toLowerCase();
          const svg = PLATFORM_SVGS[p] || '';
          const h = c.handle ? `${AKILI.escapeHtml(c.handle)}` : '';
          const title = h ? `${p} · ${h}` : p;
          const job = c.job_title ? `<div class="label-sm" style="color:var(--slate)">${AKILI.escapeHtml(c.job_title)}</div>` : '';
          const loc = c.location ? `<div class="label-sm" style="margin-top:0.15rem">${AKILI.escapeHtml(c.location)}</div>` : '';
          const followers = c.follower_count ? `<div class="label-sm" style="color:var(--slate)">${AKILI.escapeHtml(String(c.follower_count))} followers</div>` : '';
          const bio = c.bio ? `<div class="label-sm" style="color:var(--slate);margin-top:0.25rem">${AKILI.escapeHtml(c.bio)}</div>` : '';
          const linked = c.linked_website ? `<div class="label-sm" style="margin-top:0.25rem"><a href="${AKILI.escapeHtml(AKILI.externalUrl(c.linked_website))}" target="_blank" rel="noopener noreferrer">${AKILI.escapeHtml(c.linked_website)}</a></div>` : '';
          const href = AKILI.externalUrl(c.profile_url || c.url || '');
          const linkHtml = href
            ? `<a href="${AKILI.escapeHtml(href)}" target="_blank" rel="noopener noreferrer" class="platform-pill">${svg}<span style="margin-left:6px">${AKILI.escapeHtml(title)}</span></a>`
            : AKILI.escapeHtml(title);
          return `<div class="social-card">${linkHtml}${job}${loc}${followers}${bio}${linked}</div>`;
        }).join('');
      } else {
        scBlock.classList.add('hidden');
        scList.innerHTML = '';
      }
    }

    const news = report.news_mentions || [];
    const nmb = document.getElementById('news-mentions-block');
    const nml = document.getElementById('news-mentions-list');
    if (nmb && nml) {
      if (news.length) {
        nmb.classList.remove('hidden');
        nml.innerHTML = news.map((n) => {
          const href = AKILI.externalUrl(n.url || '');
          return `<div class="social-card" style="margin-bottom:0.5rem">
            ${href ? `<a href="${AKILI.escapeHtml(href)}" target="_blank" rel="noopener noreferrer"><strong>${AKILI.escapeHtml(n.title || 'Article')}</strong></a>` : `<strong>${AKILI.escapeHtml(n.title || 'Article')}</strong>`}
            <p class="label-sm" style="margin:0.25rem 0 0;color:var(--slate)">${AKILI.escapeHtml(n.summary || '')}</p>
          </div>`;
        }).join('');
      } else {
        nmb.classList.add('hidden');
        nml.innerHTML = '';
      }
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

    const renderGrid = (id, imgs) => {
      const grid = document.getElementById(id);
      if (!grid) return [];
      const list = imgs || [];
      grid.innerHTML = list.length
        ? list.slice(0, 12).map((img, i) =>
            `<button type="button" class="person-img-btn" data-idx="${i}" aria-label="View image">
              <img src="${AKILI.escapeHtml(AKILI.externalUrl(img.url) || '')}" alt="" loading="lazy" referrerpolicy="no-referrer" onerror="this.parentElement.style.display='none'">
            </button>`
          ).join('')
        : `<p class="label-sm" style="grid-column:1/-1">No images found.</p>`;
      grid.querySelectorAll('.person-img-btn').forEach((el) => {
        el.onclick = () => AKILI.openImageModal(list, +el.dataset.idx);
      });
      return list;
    };

    const profileImgs = report.profile_images || [];
    const profilePanel = document.getElementById('profile-images-panel');
    if (profilePanel) {
      profilePanel.style.display = profileImgs.length ? '' : 'none';
    }
    renderGrid('profile-image-grid', profileImgs);
    renderGrid('web-image-grid', report.web_images || report.images || []);

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
    const mod_now = currentCfg().module || 'website';
    if (mod_now === 'person') renderPerson(report);
    else if (mod_now === 'email') renderEmail(report);
    else if (mod_now === 'ip') renderIp(report);
    else if (mod_now === 'subdomains') renderSubdomains(report);
    else renderWebsite(report);
    AKILI.showToast('Scan complete', 'success');
    if (!currentCfg().public && 'Notification' in window) {
      const notify = () => new Notification('AKILI scan ready', { body: `${currentModule()} scan finished for ${report.target || report.url || 'your target'}` });
      if (Notification.permission === 'granted') notify();
      else if (Notification.permission !== 'denied') Notification.requestPermission().then((p) => { if (p === 'granted') notify(); });
    }
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
    // If backend assigned a persistent scan_id, mirror local session lines into it
    try {
      if (report.scan_id && report.scan_id !== scanId) {
        const sid = report.scan_id;
        const existing = sessionStore.get(sid) || { id: sid, targetLabel: report.target || sid, status: 'done', started: Date.now(), lines: [], report: report };
        // copy current session lines into persisted session if missing
        if (session && Array.isArray(session.lines)) {
          const sset = new Set(existing.lines || []);
          session.lines.forEach((l) => { if (!sset.has(l)) existing.lines.push(l); });
        }
        existing.report = report;
        existing.status = 'done';
        sessionStore.set(sid, existing);
      }
    } catch (e) {}
    document.body.classList.remove('akili-scan-active');
    if (typeof lucide !== 'undefined') lucide.createIcons();
    if (typeof AKILI.refreshHealth === 'function') AKILI.refreshHealth();
  }

  const EMIT_LABELS = {
    THINK: 'Thinking through the findings...',
    TOOL: 'Running a check...',
    FOUND: 'Found something worth noting',
    CRITICAL: 'Found a serious issue',
    PLAN: 'Planning the next step',
    OK: 'Check complete',
    DONE: 'Wrapping up the report',
    AI: 'Analyzing with AI',
    PROGRESS: null,
    AKILI: null,
  };

  function humanizeTerminalLine(line) {
    const m = line.match(/^\[([A-Z]+)\]\s*(.*)$/);
    if (!m) return line;
    const label = EMIT_LABELS[m[1]];
    if (label === null) return line.replace(/^\[([A-Z]+)\]\s*/, '').trim() ? line : line;
    if (label) return label + (m[2] ? ': ' + m[2] : '');
    return line;
  }

  function scanErrorMessage(err, fallback = 'Scan failed') {
    const detail = err && (err.detail || err.message || err.error || err);
    if (typeof detail === 'string') {
      const d = detail.toLowerCase();
      if (d.includes('timeout') || d.includes('timed out')) return 'The scan took too long to respond. Try again in a moment.';
      if (d.includes('network') || d.includes('failed to fetch')) return 'Could not reach the AKILI server. Check your connection and try again.';
      if (d.includes('invalid') || d.includes('validation')) return 'That does not look right. Double-check the address and try again.';
      if (d.includes('rate limit') || d.includes('429') || d.includes('too many')) return 'You have run quite a few scans recently. Wait a minute and try again.';
      return detail;
    }
    if (detail && typeof detail.message === 'string') return detail.message;
    if (detail && typeof detail.detail === 'string') return detail.detail;
    if (detail && typeof detail.error === 'string') return detail.error;
    try {
      const text = JSON.stringify(detail);
      return text && text !== '{}' ? text : fallback;
    } catch (_) {
      return fallback;
    }
  }

  async function runScan() {
    if (_needsAuth && !localStorage.getItem('akili_token')) {
      if (window.AKILI) AKILI.showToast('Sign in to run a full scan', 'warning');
      return;
    }
    const body = currentBuildBody()();
    const cfg_now = currentCfg();
    if (cfg_now.validate && cfg_now.validate(body)) return;

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
      terminal.dataset.scanModule = currentModule();
      terminal.dataset.scanId = thisScanId;
      terminal.classList.remove('hidden');
    }
    if (statusBar) {
      statusBar.classList.add('active');
      const t = statusBar.querySelector('.scan-status-text');
      if (t) t.textContent = `Starting ${currentModule()} scan…`;
    }
    showResultsLoading(true);
    AKILI.showToast(`${currentModule()} scan started`, 'info');
    document.body.classList.add('akili-scan-active');
    if (cfg_now.public) {
      appendTerminal(`[AKILI] Starting guest ${currentModule()} quick scan`, thisScanId);
      appendTerminal(`[PROGRESS] Target: ${label}`, thisScanId);
      appendTerminal('[TOOL] Running lightweight public checks', thisScanId);
    }

    // If authenticated (not a public scan), check daily scan quota and warn if near limit.
    let reservationId = null;
    try {
      if (!cfg_now.public && typeof AKILI.apiFetch === 'function') {
        const quota = await AKILI.apiFetch('/api/v1/auth/scan-count').then((r) => r.json()).catch(() => null);
        if (quota && typeof quota.remaining === 'number') {
          // If only 1 remaining, prompt user before consuming the last allowed scan
          if (quota.remaining <= 1) {
            const ok = confirm(`You have ${quota.remaining}/${quota.limit} scans remaining today. Continue and consume one scan?`);
            if (!ok) {
              // user cancelled — cleanup state
              sessionStore.delete(thisScanId);
              renderSessionList();
              btn.disabled = false;
              btn.textContent = cfg_now.buttonLabel || 'Run scan';
              showResultsLoading(false);
              document.body.classList.remove('akili-scan-active');
              return;
            }
            // Reserve a slot (consumes one daily scan) — returns reservation id
            try {
              const r = await AKILI.apiFetch('/api/v1/scan/reserve', { method: 'POST' }).then((rr) => rr.json());
              if (r && r.reservation_id) {
                reservationId = r.reservation_id;
              }
            } catch (e) {
              // If reservation fails, abort scan start
              AKILI.showToast('Failed to reserve scan slot: ' + (e.message || ''), 'error');
              sessionStore.delete(thisScanId);
              renderSessionList();
              btn.disabled = false;
              btn.textContent = cfg_now.buttonLabel || 'Run scan';
              showResultsLoading(false);
              document.body.classList.remove('akili-scan-active');
              return;
            }
          }
        }
      }
    } catch (e) {
      // ignore quota check failures and proceed with scan
    }

    const ep = currentEndpoint();
    const cfg = currentCfg();
    const url = sandbox
      ? `${AKILI.API()}${ep.replace('/api/v1/', '/api/v1/sandbox/')}?scenario=${cfg.scenario || 'clean_scan'}`
      : `${AKILI.API()}${ep}`;

    try {
      const headers = scanHeaders();
      if (reservationId) headers['X-Scan-Reservation'] = reservationId;
      const res = await fetch(url, {
        method: 'POST',
        headers: headers,
        body: JSON.stringify(body),
        signal: scanAbort.signal,
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(scanErrorMessage(err, res.statusText));
      }

      const contentType = res.headers.get('content-type') || '';
      if (contentType.includes('application/json')) {
        const j = await res.json().catch(() => null);
        if (j && j.status === 'queued') {
          appendTerminal('[PROGRESS] Scan queued for background processing', thisScanId);
          // start polling persisted logs
          startPollingScanLogs(j.scan_id || thisScanId);
          return;
        }
        if (cfg_now.public) appendTerminal('[FOUND] Public scan returned structured results', thisScanId);
        const report = j;
        appendTerminal('[DONE] Quick scan complete', thisScanId);
        renderResults(report, thisScanId);
        return;
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
      const message = scanErrorMessage(e, 'Scan failed');
      AKILI.showToast(message, 'error');
      appendTerminal('[CRITICAL] ' + message, thisScanId);
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
          const cfg_end = currentCfg();
          btn.textContent = cfg_end.buttonLabel || 'SCAN';
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

  if (_needsAuth) {
    const mountGate = () => {
      if (window.AKILI_GATE) {
        AKILI_GATE.mountScanGate(currentModule());
      }
    };
    if (window.AKILI_GATE) mountGate();
    else {
      const s = document.createElement('script');
      s.src = 'js/gate.js';
      s.onload = mountGate;
      document.head.appendChild(s);
    }
  }

  btn?.addEventListener('click', runScan);
  document.getElementById('export-btn')?.addEventListener('click', () => window.print());
})();
