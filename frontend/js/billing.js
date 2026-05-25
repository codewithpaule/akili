(function () {
  function formatNgn(n) {
    if (!n) return 'Free';
    return '₦' + Number(n).toLocaleString('en-NG');
  }

  function apiBase() {
    return (window.AKILI_CONFIG && AKILI_CONFIG.API_BASE) || (window.AKILI && AKILI.API()) || 'http://localhost:8001';
  }

  async function fetchPricing() {
    const res = await fetch(`${apiBase()}/api/v1/billing/pricing`);
    if (!res.ok) throw new Error('Could not load plans');
    return res.json();
  }

  async function startCheckout(planId, returnPage) {
    if (!window.AKILI_AUTH?.getToken()) {
      const next = returnPage || 'dashboard.html';
      location.href = 'login.html?next=' + encodeURIComponent(next);
      return;
    }
    const page = returnPage || (location.pathname.split('/').pop() || 'dashboard.html');
    const data = await AKILI_AUTH.api('/api/v1/billing/checkout', {
      method: 'POST',
      body: JSON.stringify({ plan_id: planId, return_page: page }),
    });
    if (data.authorization_url) {
      window.location.href = data.authorization_url;
      return;
    }
    throw new Error('No payment URL returned from Paystack');
  }

  async function verifyReference(reference, opts = {}) {
    const data = await AKILI_AUTH.api('/api/v1/billing/verify?reference=' + encodeURIComponent(reference));
    if (typeof AKILI !== 'undefined') AKILI.showToast('Premium activated — thank you!', 'success');
    if (data.user && AKILI_AUTH) AKILI_AUTH.setSession(AKILI_AUTH.getToken(), data.user);
    const clean = opts.returnPage || location.pathname.split('/').pop() || 'dashboard.html';
    history.replaceState({}, '', clean);
    if (opts.reload) opts.reload();
    else if (opts.onSuccess) opts.onSuccess(data);
    return data;
  }

  function renderAlert(container, st) {
    if (!container) return;
    if (st && st.ready) {
      container.style.display = 'none';
      container.innerHTML = '';
      return;
    }
    container.style.display = '';
    container.className = 'billing-alert';
    container.innerHTML = `<strong>Paystack not ready.</strong> ${AKILI.escapeHtml(st?.message || '')}
      <span class="label-sm" style="display:block;margin-top:0.35rem">Update keys in backend/.env and restart the API.</span>`;
  }

  /**
   * Render plan picker into container. User picks a plan and pays without leaving the page (until Paystack).
   */
  function renderPicker(container, data, options = {}) {
    if (!container || !data) return;
    const plans = data.plans || {};
    const currentPlan = (options.currentPlan || 'free').toLowerCase();
    const paystackReady = data.paystack_enabled && data.paystack_status?.ready;
    const returnPage = options.returnPage || 'dashboard.html';
    const order = ['free', 'trial', 'premium_monthly'];

    container.innerHTML = order
      .filter((id) => plans[id])
      .map((id) => {
        const p = plans[id];
        const isPremium = id === 'premium_monthly';
        const isCurrent =
          (id === 'premium_monthly' && currentPlan === 'premium') ||
          (id === 'trial' && currentPlan === 'trial') ||
          (id === 'free' && currentPlan === 'free');
        const canPay = isPremium && paystackReady && currentPlan !== 'premium';
        return `<article class="billing-plan-card${isPremium ? ' featured' : ''}${isCurrent ? ' is-current' : ''}" data-plan-id="${id}">
          <div class="billing-plan-head">
            <h3>${AKILI.escapeHtml(p.name)}</h3>
            ${isCurrent ? '<span class="billing-current-badge">Current</span>' : ''}
          </div>
          <p class="billing-plan-price">${formatNgn(p.price_ngn)}${p.interval ? '<span>/month</span>' : ''}</p>
          <p class="label-sm">${AKILI.escapeHtml(p.description || '')}</p>
          <ul class="billing-plan-features">${(p.highlights || []).slice(0, 4).map((h) => `<li>${AKILI.escapeHtml(h)}</li>`).join('')}</ul>
          ${canPay
            ? `<button type="button" class="btn btn-primary btn-block" data-pay-plan="${id}">Pay ${formatNgn(p.price_ngn)} with Paystack</button>
               <p class="label-sm" style="margin-top:0.4rem">Card saved</p>`
            : isCurrent && isPremium
              ? '<p class="label-sm" style="color:var(--blue)">You are on Premium</p>'
              : isPremium && !paystackReady
                ? '<button type="button" class="btn btn-outline btn-block" disabled>Payment unavailable</button>'
                : '<p class="label-sm">Included with your account</p>'}
        </article>`;
      })
      .join('');

    if (data.plan_comparison && options.showComparison !== false) {
      container.insertAdjacentHTML(
        'beforeend',
        `<div class="billing-plan-compare" style="grid-column:1/-1;margin-top:1rem">
          <h3 class="label-sm" style="margin-bottom:0.75rem">Scan depth by tier</h3>
          <table class="data-table"><thead><tr><th>Tier</th><th>AI follow-ups</th><th>Website checks</th><th>Premium modules</th><th>Notes</th></tr></thead><tbody>
            ${data.plan_comparison.map((row) => `<tr>
              <td><strong>${AKILI.escapeHtml(row.name)}</strong></td>
              <td>${row.ai_followups}</td>
              <td>${row.website_checks}</td>
              <td>${row.premium_modules ? 'Yes' : 'No'}</td>
              <td class="label-sm">${AKILI.escapeHtml(row.description)}</td>
            </tr>`).join('')}
          </tbody></table>
          <p class="label-sm" style="margin-top:0.5rem"><a href="quick-scan.html">Quick scan (guest)</a> needs no account — shallow checks only.</p>
        </div>`
      );
    }

    if (data.module_addons && options.showModules !== false) {
      container.insertAdjacentHTML(
        'beforeend',
        `<details class="billing-module-ref" style="margin-top:1rem;grid-column:1/-1">
          <summary class="label-sm">Module reference prices (all included in Premium)</summary>
          <table class="data-table" style="margin-top:0.5rem"><tbody>
            ${data.module_addons.map((m) => `<tr><td>${AKILI.escapeHtml(m.name)}</td><td>${formatNgn(m.price_ngn)}/mo</td></tr>`).join('')}
          </tbody></table>
        </details>`
      );
    }

    container.querySelectorAll('[data-pay-plan]').forEach((btn) => {
      btn.addEventListener('click', async () => {
        const planId = btn.dataset.payPlan;
        btn.disabled = true;
        const label = btn.textContent;
        btn.textContent = 'Opening Paystack…';
        try {
          await startCheckout(planId, returnPage);
        } catch (e) {
          if (typeof AKILI !== 'undefined') AKILI.showToast(e.message, 'error');
          btn.disabled = false;
          btn.textContent = label;
        }
      });
    });
  }

  async function mountPicker(containerId, options = {}) {
    const container = typeof containerId === 'string' ? document.getElementById(containerId) : containerId;
    const alertEl = options.alertId ? document.getElementById(options.alertId) : null;
    const data = await fetchPricing();
    renderAlert(alertEl, data.paystack_status);
    renderPicker(container, data, options);
    return data;
  }

  function handlePageReturn(options = {}) {
    const params = new URLSearchParams(location.search);
    const ref = params.get('reference') || params.get('trxref');
    if (!ref) return Promise.resolve(null);
    if (!AKILI_AUTH?.getToken()) {
      const next = location.pathname.split('/').pop() + location.search;
      location.href = 'login.html?next=' + encodeURIComponent(next);
      return Promise.resolve(null);
    }
    return verifyReference(ref, options);
  }

  window.AKILI_BILLING = {
    formatNgn,
    fetchPricing,
    startCheckout,
    verifyReference,
    renderPicker,
    mountPicker,
    handlePageReturn,
  };

  // Standalone pricing.html page
  if (document.getElementById('pricing-grid')) {
    mountPicker('pricing-grid', { alertId: 'paystack-alert', returnPage: 'pricing.html', showModules: true })
      .then(() => handlePageReturn({ returnPage: 'pricing.html', onSuccess: () => { location.href = 'dashboard.html'; } }))
      .catch((e) => {
        const g = document.getElementById('pricing-grid');
        if (g) g.textContent = e.message;
      });
  }
})();
