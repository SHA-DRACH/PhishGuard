/* PhishGuard front-end (vanilla ES2022, no dependencies) */
const BASE = document.body.dataset.base || '';
const CSRF = document.querySelector('meta[name="csrf-token"]')?.content || '';
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const VERDICT = {
  safe:       { title: 'Looks safe',          color: 'var(--safe)',   msg: 'No significant phishing indicators were found. Still, only enter sensitive details on sites you reached by typing the address yourself.' },
  suspicious: { title: 'Proceed with caution', color: 'var(--warn)',   msg: 'Some warning signs were detected. Verify the address carefully and avoid entering passwords, PINs or mobile-money codes.' },
  phishing:   { title: 'Likely phishing',      color: 'var(--danger)', msg: 'Strong phishing indicators detected. Do NOT enter any personal information on this website.' },
};
const GROUPS = { reputation: 'Reputation', lexical: 'URL analysis', host: 'Host & certificate', content: 'Page content' };
const RISKY_WORDS = /(login|log-in|signin|sign-in|verify|verification|secure|account|update|confirm|banking|password|wallet|suspend|unlock|billing|invoice|recover|validate|bonus|reward|airtime|momo|kyc)/gi;

/* ------------------------------------------------------------ chrome */
$('.nav-toggle')?.addEventListener('click', (e) => {
  const btn = e.currentTarget;
  btn.setAttribute('aria-expanded', String(btn.getAttribute('aria-expanded') !== 'true'));
});

$('.theme-toggle')?.addEventListener('click', () => {
  const root = document.documentElement;
  const next = root.dataset.theme === 'light' ? 'dark' : 'light';
  root.dataset.theme = next;
  try { localStorage.setItem('pg-theme', next); } catch { /* storage unavailable */ }
});

document.addEventListener('click', (e) => {
  const menu = $('.user-menu[open]');
  if (menu && !menu.contains(e.target)) menu.removeAttribute('open');
});

document.addEventListener('submit', (e) => {
  const msg = e.target.dataset.confirm;
  if (msg && !confirm(msg)) e.preventDefault();
});

/* ------------------------------------------------------------ alert dialog */
const alertDialog = $('#phish-alert');
alertDialog?.addEventListener('click', (e) => {
  if (e.target.matches('[data-close]') || e.target === alertDialog) alertDialog.close();
  if (e.target.matches('[data-details]')) { alertDialog.close(); $('#result')?.scrollIntoView({ behavior: 'smooth' }); }
});
function raiseAlert(url) {
  if (!alertDialog) return;
  $('.phish-alert-url', alertDialog).textContent = url;
  alertDialog.showModal();
}

/* ------------------------------------------------------------ scanner */
const form = $('#scan-form');
if (form) {
  const input = $('#scan-url', form);
  const pulse = $('.pulse');
  const btn = $('button[type="submit"]', form);
  let timer, controller;

  input.addEventListener('input', () => {
    clearTimeout(timer);
    const value = input.value.trim();
    if (value.length < 4) { pulse.classList.remove('show'); return; }
    timer = setTimeout(async () => {
      controller?.abort();
      controller = new AbortController();
      try {
        const res = await fetch(`${BASE}/api/scan.php?quick=1&url=${encodeURIComponent(value)}`, { signal: controller.signal });
        const data = await res.json();
        if (!data.ok) { pulse.classList.remove('show'); return; }
        const v = VERDICT[data.verdict];
        $('.pulse-fill', pulse).style.width = Math.max(4, data.score) + '%';
        $('.pulse-fill', pulse).style.background = v.color;
        $('.pulse-label', pulse).innerHTML = `Live URL check: <b style="color:${v.color}">${data.score}/100 · ${esc(v.title)}</b>`;
        pulse.classList.add('show');
      } catch { /* aborted or offline */ }
    }, 350);
  });

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const url = input.value.trim();
    if (!url) { input.focus(); return; }
    form.classList.add('is-scanning');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Scanning';
    try {
      const body = new FormData(form);
      const res = await fetch(`${BASE}/api/scan.php`, { method: 'POST', body, headers: { 'X-CSRF-Token': CSRF } });
      const data = await res.json();
      if (!data.ok) throw new Error(data.error || 'Scan failed');
      renderResult(data.result, data.scan_id);
      if (data.result.verdict === 'phishing') raiseAlert(data.result.url);
    } catch (err) {
      const box = $('#result');
      box.innerHTML = `<div class="alert alert-error">${esc(err.message)}</div>`;
      box.classList.add('show');
    } finally {
      form.classList.remove('is-scanning');
      btn.disabled = false;
      btn.textContent = 'Scan';
    }
  });

  // Pre-fill from ?url=
  const pre = new URLSearchParams(location.search).get('url');
  if (pre) { input.value = pre; form.requestSubmit(); }
}

/* ------------------------------------------------------------ result rendering */
function gaugeSvg(score) {
  const r = 70, c = 2 * Math.PI * r;
  return `<div class="gauge"><svg viewBox="0 0 170 170" aria-hidden="true">
      <circle class="g-track" cx="85" cy="85" r="${r}" fill="none" stroke-width="12"/>
      <circle class="g-fill" cx="85" cy="85" r="${r}" fill="none" stroke-width="12"
        stroke-dasharray="${c}" stroke-dashoffset="${c}" data-target="${c * (1 - score / 100)}"/>
    </svg>
    <div class="g-label"><span class="g-score" data-count="${score}">0</span><span class="g-caption">Risk score</span></div></div>`;
}

function animateGauge(root) {
  const fill = $('.g-fill', root), num = $('.g-score', root);
  if (!fill) return;
  requestAnimationFrame(() => requestAnimationFrame(() => { fill.style.strokeDashoffset = fill.dataset.target; }));
  const target = +num.dataset.count, start = performance.now();
  const tick = (t) => {
    const p = Math.min(1, (t - start) / 1000);
    num.textContent = Math.round(target * (1 - Math.pow(1 - p, 3)));
    if (p < 1) requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
}

function xray(urlStr, domain) {
  let u;
  try { u = new URL(urlStr); } catch { return `<div class="xray">${esc(urlStr)}</div>`; }
  const host = u.hostname;
  const sub = domain && host.endsWith(domain) && host !== domain ? host.slice(0, -domain.length) : '';
  const dom = sub ? domain : host;
  const hl = (s) => esc(s).replace(RISKY_WORDS, '<mark>$1</mark>');
  const cred = u.username ? `<span class="x-cred" title="Credentials/@ trick">${esc(u.username)}${u.password ? ':' + esc(u.password) : ''}@</span>` : '';
  const insecure = u.protocol !== 'https:';
  return `<div class="xray" aria-label="URL breakdown">`
    + `<span class="x-scheme ${insecure ? 'insecure' : ''}" title="${insecure ? 'Not encrypted' : 'Encrypted'}">${esc(u.protocol)}//</span>`
    + cred
    + (sub ? `<span class="x-sub" title="Sub-domain">${hl(sub)}</span>` : '')
    + `<span class="x-domain" title="Real owner of this site">${esc(dom)}</span>`
    + (u.port ? `<span class="x-port">:${esc(u.port)}</span>` : '')
    + `<span class="x-path">${hl(decodeURIComponentSafe(u.pathname))}</span>`
    + (u.search ? `<span class="x-query">${hl(u.search)}</span>` : '')
    + `</div>
    <div class="xray-legend">
      <span><i style="background:color-mix(in srgb,var(--accent) 40%,transparent)"></i>Real domain (who owns the site)</span>
      <span><i style="background:var(--warn)"></i>Sub-domain</span>
      <span><i style="background:color-mix(in srgb,var(--danger) 40%,transparent)"></i>Risky pattern</span>
    </div>`;
}
function decodeURIComponentSafe(s) { try { return decodeURIComponent(s); } catch { return s; } }

function adviceFor(r) {
  const tips = {
    safe: ['Bookmark sites you use often and open them from your bookmarks.', 'Keep your browser and phone updated.'],
    suspicious: ['Type the official address yourself instead of clicking links.', 'Contact the organisation through a known phone number to confirm.', 'Do not enter passwords, PINs or mobile-money codes.'],
    phishing: ['Close this website immediately.', 'If you already entered a password, change it now and enable two-factor authentication.', 'If you shared card or mobile-money details, contact your bank or provider.', 'Report the site so LTC ICT can block it for everyone.'],
  };
  return tips[r.verdict];
}

function renderResult(r, scanId) {
  const box = $('#result');
  if (!box) return;
  const v = VERDICT[r.verdict];
  const flagged = r.features.filter((f) => f.risk > 0).length;

  const groups = {};
  for (const f of r.features) (groups[f.group] ||= []).push(f);
  const board = Object.entries(GROUPS).filter(([k]) => groups[k]).map(([k, label]) => {
    const items = groups[k];
    const pts = items.reduce((a, f) => a + f.risk, 0);
    return `<section class="signal-group"><h4>${label}<b>+${pts}</b></h4><ul>${items.map((f) => `
      <li class="signal" data-status="${esc(f.status)}"><span><strong>${esc(f.label)}</strong><small>${esc(f.result)}</small></span><em>${f.risk ? '+' + f.risk : f.status === 'info' ? 'info' : 'ok'}</em></li>`).join('')}</ul></section>`;
  }).join('');

  const reportLink = r.verdict !== 'safe'
    ? `<a class="btn btn-sm btn-outline" href="${BASE}/report.php?url=${encodeURIComponent(r.url)}">Report this site</a>` : '';
  const detailLink = scanId ? `<a class="btn btn-sm btn-ghost" href="${BASE}/result.php?id=${scanId}">Permalink</a>` : '';

  box.innerHTML = `
    <div class="card verdict-panel" data-verdict="${r.verdict}">
      ${gaugeSvg(r.score)}
      <div>
        <span class="badge badge-${r.verdict}">${r.verdict}</span>
        <div class="verdict-title">${v.title}</div>
        <p class="verdict-msg">${v.msg}</p>
        <div class="meta">
          <span>host: ${esc(r.host)}</span>
          <span>${flagged} of ${r.features.length} signals flagged</span>
          <span>${r.network ? 'deep scan' : 'URL-only scan'} · ${r.duration_ms} ms</span>
          ${r.list_match ? `<span>list: ${esc(r.list_match)}</span>` : ''}
        </div>
        <div style="display:flex;gap:8px;margin-top:14px;flex-wrap:wrap">${reportLink}${detailLink}</div>
      </div>
    </div>

    <div class="grid grid-2" style="margin-top:20px">
      <div class="card"><h3>URL X-ray</h3>${xray(r.url, r.domain)}
        ${r.final_url && r.final_url !== r.url ? `<p class="small muted" style="margin-top:12px">Final destination after redirects: <code>${esc(r.final_url)}</code></p>` : ''}
      </div>
      <div class="card"><h3>What you should do</h3><ul class="advice">${adviceFor(r).map((t) => `<li>${esc(t)}</li>`).join('')}</ul></div>
    </div>

    <div class="card" style="margin-top:20px">
      <div class="card-head"><h3>Detection signals</h3>
        <label class="check"><input type="checkbox" id="hide-ok"> Show only flagged signals</label></div>
      <div class="signal-board" id="signal-board">${board}</div>
    </div>`;
  box.classList.add('show');
  animateGauge(box);
  $('#hide-ok', box).addEventListener('change', (e) => $('#signal-board').classList.toggle('filter-safe', e.target.checked));
  box.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// Saved result page
const saved = $('#scan-data');
if (saved) {
  const data = JSON.parse(saved.textContent);
  renderResult(data, null);
  if (data.verdict === 'phishing' && data.alert) raiseAlert(data.url);
}

/* ------------------------------------------------------------ charts */
function barChart(el) {
  const data = JSON.parse(el.dataset.series); // [{label, safe, suspicious, phishing}]
  const W = 640, H = 220, pad = { l: 34, r: 8, t: 10, b: 26 };
  const max = Math.max(4, ...data.map((d) => d.safe + d.suspicious + d.phishing));
  const bw = (W - pad.l - pad.r) / data.length;
  const y = (v) => H - pad.b - (v / max) * (H - pad.t - pad.b);
  let svg = '';
  for (let i = 0; i <= 4; i++) {
    const val = Math.round((max / 4) * i), yy = y(val);
    svg += `<line class="grid-line" x1="${pad.l}" x2="${W - pad.r}" y1="${yy}" y2="${yy}"/><text x="${pad.l - 6}" y="${yy + 4}" text-anchor="end">${val}</text>`;
  }
  data.forEach((d, i) => {
    const x = pad.l + i * bw + bw * 0.22, w = bw * 0.56;
    let base = 0;
    for (const [k, c] of [['safe', 'var(--safe)'], ['suspicious', 'var(--warn)'], ['phishing', 'var(--danger)']]) {
      if (!d[k]) continue;
      const y1 = y(base + d[k]), y0 = y(base);
      svg += `<rect x="${x}" y="${y1}" width="${w}" height="${Math.max(0, y0 - y1)}" rx="3" fill="${c}"><title>${d.label}: ${d[k]} ${k}</title></rect>`;
      base += d[k];
    }
    svg += `<text x="${x + w / 2}" y="${H - 8}" text-anchor="middle">${esc(d.label)}</text>`;
  });
  el.innerHTML = `<svg class="chart" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" role="img" aria-label="Scans per day">${svg}</svg>`;
}

function donut(el) {
  const parts = JSON.parse(el.dataset.parts); // [{label, value, color}]
  const total = parts.reduce((a, p) => a + p.value, 0);
  const r = 58, c = 2 * Math.PI * r;
  let offset = 0, arcs = '';
  for (const p of parts) {
    const len = total ? (p.value / total) * c : 0;
    arcs += `<circle cx="80" cy="80" r="${r}" fill="none" stroke="${p.color}" stroke-width="20" stroke-dasharray="${len} ${c - len}" stroke-dashoffset="${-offset}"><title>${p.label}: ${p.value}</title></circle>`;
    offset += len;
  }
  el.innerHTML = `<div class="donut-wrap">
    <svg viewBox="0 0 160 160" width="160" height="160" style="transform:rotate(-90deg)"><circle cx="80" cy="80" r="${r}" fill="none" stroke="var(--line)" stroke-width="20"/>${arcs}</svg>
    <ul class="legend">${parts.map((p) => `<li><i style="background:${p.color}"></i>${esc(p.label)}<b>${p.value}${total ? ` · ${Math.round(p.value / total * 100)}%` : ''}</b></li>`).join('')}</ul></div>`;
}

$$('[data-chart="bars"]').forEach(barChart);
$$('[data-chart="donut"]').forEach(donut);

/* ------------------------------------------------------------ awareness quiz */
$$('.quiz-item').forEach((item) => {
  item.addEventListener('click', (e) => {
    const b = e.target.closest('button[data-answer]');
    if (!b || item.classList.contains('answered')) return;
    const right = b.dataset.answer === item.dataset.truth;
    item.classList.add('answered', right ? 'correct' : 'wrong');
    $('.quiz-feedback', item).innerHTML = `<b style="color:${right ? 'var(--safe)' : 'var(--danger)'}">${right ? 'Correct!' : 'Not quite.'}</b> ${esc(item.dataset.explain)}`;
    const done = $$('.quiz-item.answered').length, score = $$('.quiz-item.correct').length;
    const out = $('#quiz-score');
    if (out) out.textContent = `${score} / ${done} correct`;
  });
});
