(function () {
  const TOKEN_KEY = 'akili_token';

  function isRealSession() {
    const t = localStorage.getItem(TOKEN_KEY) || '';
    return Boolean(t && t !== 'sandbox_mock_token');
  }

  const FEATURES = {
    workspace: {
      title: 'Your AKILI workspace',
      lead: 'Save scan history, track security scores over time, and run full-depth investigations from one dashboard.',
      bullets: [
        'Full agent depth — up to 10 planned tools per scan',
        'Confidence-driven follow-ups until evidence is solid',
        'Scan history and exportable reports',
        '5 free scans per day on every module',
      ],
      icon: 'layout-dashboard',
    },
    profile: {
      title: 'Profile & account',
      lead: 'Manage your account, API keys, and scan usage.',
      bullets: ['Update your profile', 'View daily scan limits', 'Secure account settings'],
      icon: 'user',
    },
    history: {
      title: 'Scan history',
      lead: 'Every investigation you run is saved here with grades, findings, and export options.',
      bullets: ['Re-open past reports', 'Compare scores over time', 'Export PDF-ready summaries'],
      icon: 'clock',
    },
    developer: {
      title: 'Developer API',
      lead: 'Create API keys and integrate AKILI into your apps with streaming scans.',
      bullets: ['Named API keys', 'REST + streaming responses', 'Public guest endpoints for quick checks'],
      icon: 'terminal',
    },
    website: {
      title: 'Website security scan',
      lead: 'AKILI hunts like an operator: exposed .env/git, hardcoded keys, CVEs on detected versions, phpMyAdmin, GraphQL, Spring actuators, DB ports — then maps attack paths.',
      bullets: [
        'Secret/credential pattern detection in page source',
        'Auto-chain: fingerprint → CVE lookup → exposed files',
        'Each finding includes attack path + CVSS where evidence supports it',
        'Live stream — watch the investigation unfold',
      ],
      icon: 'globe',
      accent: 'var(--mod-website)',
    },
    vulnerability: {
      title: 'Vulnerability scan',
      lead: 'Deep passive recon: cookie flaws, CORS abuse, SQL error leaks, debug traces, directory listing, admin panels, and known CVE chains on your stack.',
      bullets: ['12-path admin/API probe set', 'Hardcoded AWS/GitHub/Stripe key detection', 'CVE mapping on exact versions', 'Exploitability rating per finding'],
      icon: 'bug',
      accent: 'var(--mod-vuln)',
    },
    subdomains: {
      title: 'Subdomain discovery',
      lead: 'Map hidden hosts via certificate transparency, DNS, and agent follow-ups on interesting subdomains.',
      bullets: ['Certificate transparency + DNS', 'Active host probing', 'Attack surface summary'],
      icon: 'git-branch',
      accent: 'var(--mod-subdomain)',
    },
    ip: {
      title: 'IP intelligence',
      lead: 'See what services sit on a public IP — ports, banners, hosted sites, and ASN context.',
      bullets: ['Extended port scan with service hints', 'Reverse DNS and hosted domains', 'Risk-ranked findings for defenders'],
      icon: 'network',
      accent: 'var(--mod-ip)',
    },
    organization: {
      title: 'Organization footprint',
      lead: 'ASN, related infrastructure, and subdomain sprawl for an org or domain.',
      bullets: ['Org + ASN intelligence', 'Subdomain mapping', 'Web search for public context'],
      icon: 'building-2',
      accent: 'var(--mod-org)',
    },
    person: {
      title: 'Person search (OSINT)',
      lead: 'Public-profile investigation with verified matches — honest confidence scoring, not guesswork.',
      bullets: ['Profile verification before inclusion', 'Web search corroboration', 'Clear narrative for clients'],
      icon: 'user-search',
      accent: 'var(--mod-person)',
    },
    company: {
      title: 'Company intelligence',
      lead: 'Domains, infrastructure, and public context for a company name or domain.',
      bullets: ['Org footprint + WHOIS', 'Tech and subdomain hints', 'AI summary for decision-makers'],
      icon: 'briefcase',
      accent: 'var(--mod-company)',
    },
    email: {
      title: 'Email investigator',
      lead: 'Breach exposure, MX validation, and domain reputation for the email\'s domain.',
      bullets: ['Known breach databases', 'Disposable and MX checks', 'Domain reputation chaining'],
      icon: 'mail',
      accent: 'var(--mod-email)',
    },
    domain: {
      title: 'Domain reputation',
      lead: 'Age, DNS posture, blacklist signals, and subdomain exposure for a domain.',
      bullets: ['Reputation and blacklist checks', 'WHOIS + DNS depth', 'Subdomain attack surface'],
      icon: 'shield-check',
      accent: 'var(--mod-domain)',
    },
    auth: {
      title: 'Authenticated scan',
      lead: 'Authorized login testing for sites you own — form, basic, or token flows.',
      bullets: ['Permission-only testing', 'Session and cookie analysis', 'Clear pass/fail reporting'],
      icon: 'lock',
      accent: '#6366F1',
    },
  };

  const DISTINCT = [
    'Plans before it scans — not a fixed checklist',
    'Confidence loops add tools until evidence is enough',
    'Web search when on-tool data runs thin',
    'Streaming live investigation log',
  ];

  function escape(s) {
    if (window.AKILI && AKILI.escapeHtml) return AKILI.escapeHtml(s);
    const d = document.createElement('div');
    d.textContent = s == null ? '' : String(s);
    return d.innerHTML;
  }

  function buildGateHtml(featureKey, nextPage) {
    const f = FEATURES[featureKey] || FEATURES.workspace;
    const next = encodeURIComponent(nextPage || location.pathname.split('/').pop() || 'dashboard.html');
    const accent = f.accent || 'var(--blue)';
    const distinctHtml = DISTINCT.map((d) => `<li>${escape(d)}</li>`).join('');
    const bulletsHtml = (f.bullets || []).map((b) => `<li>${escape(b)}</li>`).join('');
    return `
      <div class="access-gate card" style="border-top: 4px solid ${accent}; margin-bottom: 1.5rem;">
        <div class="access-gate-head">
          <span class="access-gate-icon" style="background:${accent}18;color:${accent}">
            <i data-lucide="${f.icon || 'shield'}"></i>
          </span>
          <div>
            <h2 class="access-gate-title">${escape(f.title)}</h2>
            <p class="access-gate-lead">${escape(f.lead)}</p>
          </div>
        </div>
        <div class="access-gate-columns">
          <div>
            <p class="label-sm">What you get with a free account</p>
            <ul class="access-gate-list">${bulletsHtml}</ul>
          </div>
          <div>
            <p class="label-sm">What makes AKILI different</p>
            <ul class="access-gate-list access-gate-distinct">${distinctHtml}</ul>
          </div>
        </div>
        <div class="access-gate-actions">
          <a href="signup.html?next=${next}" class="btn btn-primary">Create free account</a>
          <a href="login.html?next=${next}" class="btn btn-outline">Sign in</a>
          <a href="quick-scan.html" class="btn btn-outline btn-sm">Try quick scan (no login)</a>
        </div>
        <p class="label-sm" style="margin-top:1rem;color:var(--slate)">Free tier: 5 scans per day. No card required.</p>
      </div>
    `;
  }

  function mountScanGate(moduleKey) {
    if (isRealSession()) return;
    const main = document.querySelector('main.container') || document.querySelector('main');
    if (!main || main.querySelector('.access-gate')) return;

    const formCard = main.querySelector('.card input, .card button#scan-btn')?.closest('.card');
    const disclaimer = main.querySelector('.disclaimer');
    const insertAfter = disclaimer || main.querySelector('.card.scan-accent') || main.firstElementChild;

    const wrap = document.createElement('div');
    wrap.innerHTML = buildGateHtml(moduleKey, location.pathname.split('/').pop());
    const gate = wrap.firstElementChild;
    if (insertAfter && insertAfter.nextSibling) {
      insertAfter.parentNode.insertBefore(gate, insertAfter.nextSibling);
    } else {
      main.insertBefore(gate, main.firstChild);
    }

    if (formCard) formCard.classList.add('access-gate-locked');
    const terminal = document.getElementById('terminal');
    const results = document.getElementById('results');
    if (terminal) terminal.classList.add('hidden');
    if (results) results.classList.add('hidden');

    const btn = document.getElementById('scan-btn');
    if (btn) {
      btn.disabled = true;
      btn.title = 'Sign in to run a full scan';
    }

    if (typeof lucide !== 'undefined') lucide.createIcons();
  }

  window.AKILI_GATE = {
    isRealSession,
    FEATURES,
    buildGateHtml,
    mountScanGate,
    featureForPage(page) {
      const p = (page || location.pathname.split('/').pop() || '').replace('.html', '');
      const map = {
        'scan-website': 'website',
        'scan-vulnerability': 'vulnerability',
        'scan-subdomains': 'subdomains',
        'scan-ip': 'ip',
        'scan-organization': 'organization',
        'scan-auth': 'auth',
        person: 'person',
        company: 'company',
        email: 'email',
        domain: 'domain',
        dashboard: 'workspace',
        profile: 'profile',
        history: 'history',
        developer: 'developer',
      };
      return map[p] || 'workspace';
    },
  };
})();
