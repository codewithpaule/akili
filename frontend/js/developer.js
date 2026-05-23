if (!window.AKILI_AUTH?.requireAuth('login.html')) {
  // redirecting
} else {
  initDeveloper();
}

function planBadgeClass(plan) {
  if (plan === 'premium') return 'plan-premium';
  if (plan === 'trial') return 'plan-trial';
  return 'plan-free';
}

function usageBar(used, cap) {
  const pct = cap ? Math.min(100, Math.round((used / cap) * 100)) : 0;
  return `<div class="usage-bar"><span style="width:${pct}%"></span></div>`;
}

function renderAccountUsage(account) {
  const el = document.getElementById('account-usage');
  if (!el || !account) return;
  const plan = account.plan || 'free';
  const planLabel = account.plan_label || plan;
  const mUsed = account.monthly_scans_used ?? 0;
  const mCap = account.monthly_total_limit ?? 50;
  const mRem = account.monthly_scans_remaining ?? Math.max(0, mCap - mUsed);
  el.innerHTML = `
    <div class="usage-account-head">
      <h3>Account usage</h3>
      <span class="dash-plan-badge ${planBadgeClass(plan)}">${AKILI.escapeHtml(planLabel)}</span>
    </div>
    <div class="usage-account-grid">
      <div class="usage-account-stat">
        <span class="label-sm">Scans this month</span>
        <p class="usage-account-value">${mUsed} <span class="usage-muted">/ ${mCap}</span></p>
        ${usageBar(mUsed, mCap)}
        <p class="label-sm">${mRem} remaining on account</p>
      </div>
      <div class="usage-account-stat">
        <span class="label-sm">Hourly API limit</span>
        <p class="usage-account-value">${account.hourly_limit ?? '—'}</p>
        <p class="label-sm">Per plan tier on API routes</p>
      </div>
      <div class="usage-account-stat">
        <span class="label-sm">API keys</span>
        <p class="usage-account-value">${account.active_api_keys ?? 0} <span class="usage-muted">/ ${account.max_api_keys ?? 1}</span></p>
        <p class="label-sm">Active named keys</p>
      </div>
    </div>
    <details class="usage-module-details" ${Object.keys(account.usage_this_month || {}).length ? 'open' : ''}>
      <summary>Module usage breakdown</summary>
      <div class="usage-module-list">
        ${Object.keys(account.module_caps || {}).sort().map((m) => {
          const cap = account.module_caps[m] || 10;
          const n = (account.usage_this_month || {})[m] || 0;
          return `<div class="dash-usage-row">
            <div class="dash-usage-label"><span>${m}</span><span>${n} / ${cap}</span></div>
            ${usageBar(n, cap)}
          </div>`;
        }).join('') || '<p class="label-sm">No module scans yet this month.</p>'}
      </div>
    </details>`;
}

function renderKeyCard(k) {
  const tierLabel = k.is_sandbox ? 'Sandbox' : (k.tier || 'free');
  const last = k.last_used_at ? AKILI.relativeTime(k.last_used_at) : 'Never';
  return `<article class="usage-key-card">
    <div class="usage-key-head">
      <div>
        <strong>${AKILI.escapeHtml(k.name || 'Unnamed')}</strong>
        <code class="usage-key-preview">${AKILI.escapeHtml(k.key_preview)}</code>
      </div>
      <div class="usage-key-actions">
        <span class="usage-key-tier">${tierLabel}</span>
        <button type="button" class="btn btn-sm btn-outline" data-id="${k.key_id}">Revoke</button>
      </div>
    </div>
    <div class="dash-usage-row">
      <div class="dash-usage-label"><span>API calls today</span><span>${k.api_calls_today || 0} / ${k.hourly_limit} hourly cap</span></div>
      ${usageBar(k.api_calls_today || 0, k.hourly_limit)}
    </div>
    <div class="dash-usage-row">
      <div class="dash-usage-label"><span>API calls this month</span><span>${k.api_calls_month || 0}</span></div>
    </div>
    <p class="label-sm">Hourly remaining (est.): <strong>${k.hourly_remaining ?? 0}</strong> · Last used ${last}</p>
  </article>`;
}

async function initDeveloper() {
  const banner = document.getElementById('dev-auth-banner');
  const user = AKILI_AUTH.getUser();
  if (banner && user) {
    const plan = user.effective_plan || user.plan || 'free';
    banner.textContent = `Signed in as ${user.email} · Plan: ${plan}. Keys inherit your account limits.`;
    banner.classList.remove('disclaimer');
    banner.classList.add('label-sm');
    banner.style.background = 'var(--blue-light)';
    banner.style.border = '1px solid var(--blue-mid)';
    banner.style.padding = '0.65rem 1rem';
    banner.style.borderRadius = 'var(--radius)';
  }
  await loadKeys();

  document.getElementById('gen-live')?.addEventListener('click', () => generate(false));
  document.getElementById('gen-test')?.addEventListener('click', () => generate(true));

  document.getElementById('save-agency')?.addEventListener('click', async () => {
    try {
      await AKILI.apiFetch('/api/v1/agency/profile', {
        method: 'POST',
        body: JSON.stringify({
          company_name: document.getElementById('agency-name').value,
          primary_color: document.getElementById('agency-color').value,
        }),
      });
      AKILI.showToast('Agency profile saved', 'success');
    } catch (e) {
      AKILI.showToast(e.message, e.message.includes('Pro') || e.message.includes('Premium') ? 'warning' : 'error');
    }
  });
}

async function loadKeys() {
  const list = document.getElementById('key-list');
  try {
    const data = await AKILI_AUTH.api('/api/v1/keys/list');
    if (data.account) renderAccountUsage(data.account);
    const keys = data.keys || [];
    list.innerHTML = keys.length
      ? keys.map(renderKeyCard).join('')
      : '<p class="label-sm">No keys yet — create one above.</p>';
    list.querySelectorAll('[data-id]').forEach((btn) => {
      btn.onclick = async () => {
        if (!confirm('Revoke this API key? Apps using it will stop working.')) return;
        await AKILI_AUTH.api('/api/v1/keys/' + btn.dataset.id, { method: 'DELETE' });
        AKILI.showToast('Key revoked', 'success');
        loadKeys();
      };
    });
  } catch (e) {
    list.innerHTML = `<p class="label-sm" style="color:var(--red)">${AKILI.escapeHtml(e.message)}</p>`;
  }
}

async function generate(sandbox) {
  const name = (document.getElementById('key-name')?.value || '').trim();
  if (!name) {
    AKILI.showToast('Enter a name for this API key', 'error');
    document.getElementById('key-name')?.focus();
    return;
  }
  try {
    const data = await AKILI_AUTH.api('/api/v1/keys/generate', {
      method: 'POST',
      body: JSON.stringify({ name, sandbox }),
    });
    localStorage.setItem('akili_api_key', data.api_key);
    AKILI.openModal(
      `<p><strong>Store this safely — shown once:</strong></p>
       <pre class="code-block" style="word-break:break-all">${AKILI.escapeHtml(data.api_key)}</pre>
       <button type="button" class="btn btn-primary" id="copy-key-btn">Copy</button>`,
      { title: (sandbox ? 'Sandbox' : 'Live') + ' key: ' + name }
    );
    document.getElementById('copy-key-btn')?.addEventListener('click', () => AKILI.copyText(data.api_key));
    loadKeys();
  } catch (e) {
    AKILI.showToast(e.message, 'error');
  }
}
