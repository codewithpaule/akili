(function () {
  if (!localStorage.getItem('akili_token')) {
    location.href = 'signup.html';
    return;
  }
  const term = document.getElementById('terminal');
  const summary = document.getElementById('template-summary');
  let running = false;
  let tplAbort = null;
  let activeTplId = null;

  function lineClass(line) {
    if (line.startsWith('[THINK]')) return 'line-think';
    if (line.startsWith('[PLAN]')) return 'line-plan';
    if (line.startsWith('[PROGRESS]')) return 'line-progress';
    if (line.startsWith('[TOOL]')) return 'line-tool';
    if (line.startsWith('[FOUND]')) return 'line-found';
    if (line.startsWith('[CRITICAL]')) return 'line-critical';
    if (line.startsWith('[OK]')) return 'line-ok';
    if (line.startsWith('[AI]')) return 'line-ai';
    if (line.startsWith('[DONE]')) return 'line-done';
    return 'line-akili';
  }

  function appendLine(line, runId) {
    if (!term || !line.trim() || runId !== activeTplId) return;
    term.classList.remove('hidden');
    const el = document.createElement('div');
    el.className = lineClass(line.trim());
    el.textContent = line.trim();
    term.appendChild(el);
    term.scrollTop = term.scrollHeight;
  }

  function tplHeaders() {
    const headers = { 'Content-Type': 'application/json' };
    const key = AKILI.getApiKey();
    if (key) headers['X-API-Key'] = key;
    const token = AKILI.getToken();
    if (token) headers['Authorization'] = `Bearer ${token}`;
    return headers;
  }

  async function runTemplate(tpl, target) {
    if (running) {
      AKILI.showToast('A template is already running', 'warning');
      return;
    }
    if (!AKILI_AUTH?.getToken()) {
      AKILI.showToast('Sign in to run templates', 'warning');
      location.href = 'signup.html';
      return;
    }

    if (tplAbort) tplAbort.abort();
    tplAbort = new AbortController();
    activeTplId = `tpl-${Date.now()}`;
    const runId = activeTplId;

    running = true;
    document.querySelectorAll('.run-tpl').forEach((b) => { b.disabled = true; });
    if (term) {
      term.innerHTML = '';
      const hdr = document.createElement('div');
      hdr.className = 'terminal-module-label';
      hdr.textContent = `Template: ${tpl}`;
      term.appendChild(hdr);
    }
    if (summary) { summary.classList.add('hidden'); summary.innerHTML = ''; }
    AKILI.showToast('Template scan started', 'info');
    document.body.classList.add('akili-scan-active');

    try {
      const res = await fetch(`${AKILI.API()}/api/v1/scan/template`, {
        method: 'POST',
        headers: tplHeaders(),
        body: JSON.stringify({ template: tpl, target }),
        signal: tplAbort.signal,
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        const detail = err.detail || err.message || err.error || res.statusText;
        throw new Error(typeof detail === 'string' ? detail : (detail.message || JSON.stringify(detail)));
      }

      const reader = res.body.getReader();
      const dec = new TextDecoder();
      let buf = '';
      let finalReport = null;

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (runId !== activeTplId) break;
        buf += dec.decode(value, { stream: true });
        const parts = buf.split('\n');
        buf = parts.pop() || '';
        for (const line of parts) {
          if (line.startsWith('COMPLETE:')) {
            try { finalReport = JSON.parse(line.slice(9)); } catch (_) {}
            continue;
          }
          appendLine(line, runId);
        }
      }
      if (buf.startsWith('COMPLETE:') && runId === activeTplId) {
        try { finalReport = JSON.parse(buf.slice(9)); } catch (_) {}
      }

      if (finalReport && summary && runId === activeTplId) {
        summary.classList.remove('hidden');
        const mods = (finalReport.modules_run || []).join(', ');
        summary.innerHTML = `
          <h3>Template complete</h3>
          <p><strong>Modules:</strong> ${AKILI.escapeHtml(mods)}</p>
          <p>${AKILI.escapeHtml(finalReport.summary || '')}</p>
          <p class="label-sm">${(finalReport.findings || []).length} combined finding(s)</p>`;
      }
      AKILI.showToast('Template complete', 'success');
    } catch (e) {
      if (e.name !== 'AbortError') {
        AKILI.showToast(e.message || 'Template failed', 'error');
        appendLine('[CRITICAL] ' + (e.message || 'Error'), runId);
      }
    } finally {
      running = false;
      document.body.classList.remove('akili-scan-active');
      document.querySelectorAll('.run-tpl').forEach((b) => { b.disabled = false; });
      if (typeof AKILI.refreshHealth === 'function') AKILI.refreshHealth();
    }
  }

  document.querySelectorAll('.run-tpl').forEach((btn) => {
    btn.onclick = () => {
      const card = btn.closest('[data-tpl]');
      const tpl = card?.dataset.tpl;
      const target = prompt('Enter URL, domain, or name for this template:');
      if (!tpl || !target) return;
      runTemplate(tpl, target.trim());
    };
  });
})();
