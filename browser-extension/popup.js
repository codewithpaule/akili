const API_BASE = 'https://api.akili.com.ng';

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
  
  if (!apiKey) {
    showConnectPrompt();
    return;
  }
  
  try {
    // Use authenticated deep scan endpoint
    const result = await fetch(`${API_BASE}/api/v1/scan/website`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': apiKey
      },
      body: JSON.stringify({ 
        url,
        module: 'website',
        deep: true
      })
    });
    
    if (!result.ok) {
      const data = await result.json().catch(() => ({}));
      throw new Error(data.detail || data.message || 'Scan failed');
    }

    const data = await readScanResult(result);
    
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

async function readScanResult(response) {
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
  
  const score = data.score || 0;
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
  const findings = data.top_findings || [];
  findingsEl.innerHTML = findings.map(f => {
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
    chrome.tabs.create({ url: `https://akili.com.ng/report/${data.scan_id || ''}` });
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

function showConnectPrompt() {
  document.getElementById('loading').style.display = 'none';
  document.getElementById('results').style.display = 'none';
  document.getElementById('error').style.display = 'none';
  document.getElementById('connect-prompt').style.display = 'block';
  
  document.getElementById('save-key-btn').onclick = async () => {
    const apiKey = document.getElementById('api-key-input').value.trim();
    if (apiKey) {
      await chrome.storage.local.set({ apiKey });
      location.reload();
    }
  };
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
