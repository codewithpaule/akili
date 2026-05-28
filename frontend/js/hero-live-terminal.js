/**
 * Homepage akili — live terminal: endless random module scan demos.
 */
(function () {
  const el = document.getElementById('hero-terminal');
  if (!el) return;

  const TARGETS = {
    url: ['https://example-university.edu', 'https://example.com', 'https://api.stripe.com', 'https://wordpress.org'],
    ip: ['8.8.8.8', '1.1.1.1', '203.0.113.50', '102.89.12.4'],
    email: ['admin@example-university.edu', 'security@example.com', 'dev@startup.io'],
    name: ['Ada Okonkwo', 'John Smith', 'Jane Doe | Lagos developer'],
    domain: ['example-university.edu', 'example.com', 'safe-site.org'],
    org: ['Example University', 'Acme Corp', 'Ministry of Health NG'],
  };

  function pick(arr) {
    return arr[Math.floor(Math.random() * arr.length)];
  }

  function lineClass(line) {
    if (/^\[DONE\]/.test(line)) return 'ok';
    if (/^\[OK\]/.test(line)) return 'ok';
    if (/^\[CRITICAL\]/.test(line)) return 'bad';
    if (/^\[FOUND\]/.test(line)) return 'warn';
    if (/^\[PLAN\]/.test(line)) return 'warn';
    if (/^\[THINK\]/.test(line)) return 'think';
    if (/^\[PROGRESS\]/.test(line)) return 'progress';
    if (/^\[TOOL\]/.test(line)) return 'tool';
    if (/^\[AI\]/.test(line)) return 'ai';
    if (/^\[AKILI\]/.test(line)) return 'akili';
    return '';
  }

  const MODULES = [
    {
      name: 'Website Scan',
      lines: (t) => [
        `[AKILI] Website Scan → ${t}`,
        '[THINK] Loading baseline security checks…',
        '[PROGRESS] Step 1/5 — SSL certificate…',
        '[OK] SSL certificate complete',
        '[FOUND] Valid HTTPS — cert expires in 142 days',
        '[PROGRESS] Step 2/5 — HTTP security headers…',
        '[FOUND] Missing CSP header (common on older sites)',
        '[PROGRESS] Step 3/5 — technology fingerprint…',
        '[FOUND] Detected 6 technologies (4 versioned)',
        '[PROGRESS] Step 4/5 — WHOIS & DNS…',
        '[FOUND] 12 DNS records',
        '[PROGRESS] Step 5/5 — open ports…',
        '[AI] AKILI writing executive summary…',
        '[DONE] Report ready → Grade B · Score 74',
      ],
    },
    {
      name: 'Vulnerability Scan',
      lines: (t) => [
        `[AKILI] Vulnerability Scan → ${t}`,
        '[THINK] AKILI is thinking…',
        '[TOOL] Running vulnerability patterns…',
        '[FOUND] CORS policy allows broad origins',
        '[TOOL] Running HTTP security headers…',
        '[PROGRESS] Now checking exposed files…',
        '[OK] exposed files finished',
        '[DONE] Report ready → Grade C · Score 68',
      ],
    },
    {
      name: 'Subdomain Discovery',
      lines: (t) => [
        `[AKILI] Subdomain Scan → ${t}`,
        '[THINK] Querying certificate transparency logs…',
        '[TOOL] Running subdomain discovery…',
        '[FOUND] api.' + t.replace(/^https?:\/\//, '').split('/')[0],
        '[FOUND] mail.' + t.replace(/^https?:\/\//, '').split('/')[0],
        '[FOUND] www.' + t.replace(/^https?:\/\//, '').split('/')[0],
        '[DONE] 14 subdomains discovered',
      ],
    },
    {
      name: 'IP Intelligence',
      lines: (t) => [
        `[AKILI] IP Intelligence → ${t}`,
        '[TOOL] Running IP intelligence…',
        '[FOUND] IP located in Nigeria — ISP: regional provider',
        '[FOUND] Reverse DNS: hosted.example.net',
        '[FOUND] Website on IP: university portal (HTTP 200)',
        '[TOOL] Running open ports…',
        '[FOUND] Ports 80, 443 open',
        '[DONE] IP report ready',
      ],
    },
    {
      name: 'Organization Scan',
      lines: (t) => [
        `[AKILI] Organization Scan → ${t}`,
        '[TOOL] Running organization footprint…',
        '[FOUND] ASN mapped — 3 netblocks',
        '[TOOL] Running subdomain discovery…',
        '[FOUND] 8 related hostnames',
        '[AI] AKILI synthesizing org footprint…',
        '[DONE] Organization scan complete',
      ],
    },
    {
      name: 'Person Search',
      lines: (t) => [
        `[AKILI] Person Search → ${t}`,
        '[THINK] Searching public web & social signals…',
        '[TOOL] Running person OSINT (web search)…',
        '[FOUND] 9 public search results',
        '[FOUND] LinkedIn profile candidate',
        '[FOUND] 2 breach signals (public databases)',
        '[AI] AKILI writing trust assessment…',
        '[DONE] Confidence 72% · verify further',
      ],
    },
    {
      name: 'Company Intel',
      lines: (t) => [
        `[AKILI] Company Intel → ${t}`,
        '[TOOL] Running organization footprint…',
        '[FOUND] Primary domain resolved',
        '[TOOL] Running technology fingerprint…',
        '[FOUND] React, Cloudflare detected',
        '[DONE] Company intel report ready',
      ],
    },
    {
      name: 'Email Investigator',
      lines: (t) => [
        `[AKILI] Email Scan → ${t}`,
        '[TOOL] Running email reputation…',
        '[FOUND] MX records valid',
        '[FOUND] Pwned in 3 breach(es) — xposedornot.com (free)',
        '[AI] AKILI writing summary…',
        '[DONE] Risk level: high — rotate passwords',
      ],
    },
    {
      name: 'Domain Reputation',
      lines: (t) => [
        `[AKILI] Domain Reputation → ${t}`,
        '[TOOL] Running domain reputation…',
        '[FOUND] Domain age > 1 year',
        '[TOOL] Running WHOIS & DNS…',
        '[FOUND] 8 DNS records',
        '[DONE] Domain reputation: acceptable',
      ],
    },
    {
      name: 'Authenticated Scan',
      lines: (t) => [
        `[AKILI] Authenticated Scan → ${t}`,
        '[THINK] Session-aware checks (authorized)…',
        '[TOOL] Running HTTP security headers…',
        '[FOUND] Login form over HTTPS',
        '[DONE] Auth scan session complete',
      ],
    },
    {
      name: 'Scan Template',
      lines: (t) => [
        `[AKILI] Template: Quick Security Audit`,
        '[PLAN] Step 1/3 — website scan (' + t + ')',
        '[OK] website scan complete',
        '[PLAN] Step 2/3 — vulnerability scan',
        '[OK] vulnerability scan complete',
        '[PLAN] Step 3/3 — subdomain discovery',
        '[DONE] Template run finished · 3 modules',
      ],
    },
    // Relationship Graph demo removed
  ];

  function targetFor(mod) {
    const n = mod.name;
    if (n.includes('IP')) return pick(TARGETS.ip);
    if (n.includes('Email')) return pick(TARGETS.email);
    if (n.includes('Person')) return pick(TARGETS.name);
    if (n.includes('Domain') && !n.includes('Website')) return pick(TARGETS.domain);
    if (n.includes('Organization') || n.includes('Company')) return pick(TARGETS.org);
    return pick(TARGETS.url);
  }

  let running = true;

  function renderLineFromKind(kind, text) {
    const div = document.createElement('div');
    const cls = (function () {
      switch ((kind || '').toUpperCase()) {
        case 'DONE': return 'ok';
        case 'OK': return 'ok';
        case 'CRITICAL': return 'bad';
        case 'FOUND': return 'warn';
        case 'PLAN': return 'warn';
        case 'THINK': return 'think';
        case 'PROGRESS': return 'progress';
        case 'TOOL': return 'tool';
        case 'AI': return 'ai';
        case 'AKILI': return 'akili';
        default: return '';
      }
    })();
    if (cls) div.className = cls;
    if (cls === 'think') div.style.color = '#94A3B8';
    if (cls === 'progress') div.style.color = '#38BDF8';
    if (cls === 'tool') div.style.color = '#60A5FA';
    if (cls === 'ai') div.style.color = '#C4B5FD';
    div.textContent = text;
    el.appendChild(div);
    el.scrollTop = el.scrollHeight;
  }

  // Demo-only mode: do not poll production DB for live scan logs on the homepage.

  // Fallback demo mode when no live scan specified
  function runNext() {
    if (!running) return;
    const mod = pick(MODULES);
    const target = targetFor(mod);
    const lines = mod.lines(target);
    el.innerHTML = '';
    let i = 0;
    const step = () => {
      if (!running) return;
      if (i >= lines.length) {
        setTimeout(runNext, 600 + Math.random() * 900);
        return;
      }
      const line = lines[i++];
      const div = document.createElement('div');
      const cls = lineClass(line);
      if (cls) div.className = cls;
      if (cls === 'think') div.style.color = '#94A3B8';
      if (cls === 'progress') div.style.color = '#38BDF8';
      if (cls === 'tool') div.style.color = '#60A5FA';
      if (cls === 'ai') div.style.color = '#C4B5FD';
      div.textContent = line;
      el.appendChild(div);
      el.scrollTop = el.scrollHeight;
      setTimeout(step, 220 + Math.random() * 180);
    };
    step();
  }

  runNext();
})();
