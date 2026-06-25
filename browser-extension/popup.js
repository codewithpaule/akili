const API_BASE = 'https://api.akili.com.ng';

chrome.storage.local.get('apiKey').then(({ apiKey }) => {
  const input = document.getElementById('api-key-input');
  if (input && apiKey) input.value = apiKey;
  const badge = document.getElementById('mode-badge');
  if (badge) {
    badge.textContent = apiKey ? 'Deep scan' : 'Guest';
    if (apiKey) badge.classList.add('deep');
  }
});

document.getElementById('save-key-btn')?.addEventListener('click', async () => {
  const apiKey = document.getElementById('api-key-input').value.trim();
  if (apiKey) {
    await chrome.storage.local.set({ apiKey });
    const badge = document.getElementById('mode-badge');
    if (badge) {
      badge.textContent = 'Deep scan';
      badge.classList.add('deep');
    }
    location.reload();
  }
});

// On popup open get current tab URL
chrome.tabs.query({active: true, currentWindow: true}, async (tabs) => {
  if (!tabs[0]) return;
  
  const url = tabs[0].url;
  let domain = '';
  try {
    const parsed = new URL(url);
    if (!/^https?:$/.test(parsed.protocol)) {
      showError('Open a public http or https website before scanning.');
      return;
    }
    domain = parsed.hostname;
  } catch (error) {
    showError('This tab URL cannot be scanned.');
    return;
  }
  
  document.getElementById('current-domain').textContent = domain;
  
  // Check cache first (1 hour cache)
  const cached = await getCachedResult(domain);
  if (cached) {
    showResults(cached);
    return;
  }
  
  // Show eye loading animation
  showLoading();
  
  // Get stored API key
  const { apiKey } = await chrome.storage.local.get('apiKey');
  const loadingText = document.getElementById('loading-text');
  if (loadingText) {
    loadingText.textContent = apiKey
      ? 'Deep agent investigation (planning + tools)…'
      : 'Guest agent scan (planning first)…';
  }
  
  try {
    const pageSignals = await getPageSignals(tabs[0].id);
    const endpoint = apiKey ? '/api/v1/scan/website' : '/api/v1/public/scan/website';
    const headers = { 'Content-Type': 'application/json' };
    if (apiKey) headers['X-API-Key'] = apiKey;
    const result = await fetch(`${API_BASE}${endpoint}`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ 
        url,
        module: 'website',
        deep: Boolean(apiKey),
        page_title: pageSignals.title,
        page_description: pageSignals.description,
        page_h1: pageSignals.h1,
        page_text: pageSignals.text,
        page_links: pageSignals.links,
        page_forms: pageSignals.forms,
      })
    });
    
    if (!result.ok) {
      const data = await result.json().catch(() => ({}));
      throw new Error(data.detail || data.message || 'Scan failed');
    }

    const data = normalizeScanResult(await readScanResult(result, loadingText));
    if (!apiKey) {
      data.summary = data.summary || 'Guest scan complete. Add an API key below for full depth (10 tools + follow-ups).';
    }
    
    // Cache result for 1 hour
    await cacheResult(domain, data);
    
    // Show in popup
    showResults(data);
    
    // Inject corner badge
    chrome.tabs.sendMessage(tabs[0].id, {
      action: 'showBadge',
      grade: data.grade,
      score: data.score || 0
    }).catch(() => {
      // Content script not loaded, inject it
      chrome.scripting.executeScript({
        target: { tabId: tabs[0].id },
        files: ['content.js']
      }).then(() => {
        chrome.tabs.sendMessage(tabs[0].id, {
          action: 'showBadge',
          grade: data.grade,
          score: data.score || 0
        });
      });
    });
  } catch (error) {
    showError(error.message);
  }
});

async function getPageSignals(tabId) {
  const fallback = { title: '', description: '', h1: '', text: '', links: [], forms: [] };
  try {
    return await chrome.tabs.sendMessage(tabId, { action: 'extractPageSignals' }) || fallback;
  } catch (error) {
    try {
      await chrome.scripting.executeScript({ target: { tabId }, files: ['content.js'] });
      return await chrome.tabs.sendMessage(tabId, { action: 'extractPageSignals' }) || fallback;
    } catch (_) {
      return fallback;
    }
  }
}

async function readScanResult(response, loadingEl) {
  const contentType = response.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    return response.json();
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  let finalReport = null;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split('\n');
    buffer = lines.pop() || '';
    for (const line of lines) {
      if (line.startsWith('PLAN:') && loadingEl) {
        loadingEl.textContent = line.slice(5).trim().slice(0, 80) || 'Running planned checks…';
      }
      if (line.startsWith('TOOL:') && loadingEl) {
        loadingEl.textContent = line.slice(5).trim().slice(0, 80) || 'Running security tools…';
      }
      if (line.startsWith('COMPLETE:')) {
        finalReport = JSON.parse(line.slice(9));
      }
    }
  }

  if (!finalReport && buffer.startsWith('COMPLETE:')) {
    finalReport = JSON.parse(buffer.slice(9));
  }
  if (!finalReport) {
    throw new Error('Deep scan finished without a report.');
  }
  return finalReport;
}

function showLoading() {
  document.getElementById('loading').style.display = 'flex';
  document.getElementById('results').style.display = 'none';
  document.getElementById('error').style.display = 'none';
  document.getElementById('connect-prompt').style.display = 'none';
}

function showResults(data) {
  document.getElementById('loading').style.display = 'none';
  document.getElementById('results').style.display = 'block';
  document.getElementById('error').style.display = 'none';
  document.getElementById('connect-prompt').style.display = 'none';
  
  const score = Number.isFinite(Number(data.score)) ? Number(data.score) : scoreFromGrade(data.grade);
  const grade = data.grade || 'N/A';
  
  document.getElementById('score').textContent = score;
  
  const gradeEl = document.getElementById('grade');
  gradeEl.textContent = grade;
  gradeEl.className = 'score-grade grade-' + grade.toLowerCase();
  
  // Status banner
  const statusBanner = document.getElementById('status-banner');
  if (data.phishing_detected) {
    statusBanner.textContent = 'PHISHING DETECTED';
    statusBanner.className = 'status-banner status-phishing';
  } else if (data.malware_detected) {
    statusBanner.textContent = 'MALWARE DETECTED';
    statusBanner.className = 'status-banner status-malware';
  } else {
    statusBanner.textContent = 'NO THREATS DETECTED';
    statusBanner.className = 'status-banner status-clear';
  }
  
  // Findings
  const findingsEl = document.getElementById('findings');
  const findings = data.top_findings || data.findings || [];
  
  const summaryEl = document.getElementById('summary-text');
  if (summaryEl && data.summary) {
    summaryEl.textContent = data.summary;
    summaryEl.style.display = 'block';
  }
  findingsEl.innerHTML = findings.slice(0, 5).map(f => {
    const severity = f.severity || 'info';
    return `<div class="finding-pill finding-${severity.toLowerCase()}">
      <strong>${severity}:</strong> ${escapeHtml(f.name || f.title || 'Unknown issue')}
    </div>`;
  }).join('');
  
  if (findings.length === 0) {
    findingsEl.innerHTML = '<div class="finding-pill finding-low">No critical issues found</div>';
  }
  
  // Full report button
  document.getElementById('full-report-btn').onclick = () => {
    const id = data.scan_id || '';
    chrome.tabs.create({ url: id ? `https://akili.com.ng/report.html?id=${id}` : 'https://akili.com.ng/scan-website.html' });
  };
  
  // Rescan button
  document.getElementById('rescan-btn').onclick = () => {
    chrome.tabs.query({active: true, currentWindow: true}, (tabs) => {
      if (tabs[0]) {
        clearCache(new URL(tabs[0].url).hostname);
        location.reload();
      }
    });
  };
}

function showError(message) {
  document.getElementById('loading').style.display = 'none';
  document.getElementById('results').style.display = 'none';
  document.getElementById('error').style.display = 'block';
  document.getElementById('error').textContent = 'Error: ' + message;
  document.getElementById('connect-prompt').style.display = 'none';
}

function normalizeScanResult(data) {
  const out = data || {};
  if (!Number.isFinite(Number(out.score))) {
    out.score = scoreFromGrade(out.grade);
  }
  return out;
}

function scoreFromGrade(grade) {
  const g = String(grade || '').toUpperCase();
  if (g === 'A') return 95;
  if (g === 'B') return 82;
  if (g === 'C') return 72;
  if (g === 'D') return 62;
  if (g === 'F') return 45;
  return 0;
}

function showConnectPrompt() {
  showError('Add your API key in the bar below for deep scanning.');
}

async function getCachedResult(domain) {
  const cache = await chrome.storage.local.get('scanCache');
  if (cache.scanCache && cache.scanCache[domain]) {
    const cached = cache.scanCache[domain];
    const now = Date.now();
    if (now - cached.timestamp < 3600000) { // 1 hour cache
      return cached.data;
    }
  }
  return null;
}

async function cacheResult(domain, data) {
  const cache = await chrome.storage.local.get('scanCache') || {};
  if (!cache.scanCache) cache.scanCache = {};
  cache.scanCache[domain] = {
    data: data,
    timestamp: Date.now()
  };
  await chrome.storage.local.set(cache);
}

async function clearCache(domain) {
  const cache = await chrome.storage.local.get('scanCache');
  if (cache.scanCache && cache.scanCache[domain]) {
    delete cache.scanCache[domain];
    await chrome.storage.local.set(cache);
  }
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}
