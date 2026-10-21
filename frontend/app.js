/**
 * PhishGuard — app.js (v2)
 * Handles: URL scan, Message analysis, Bulk scan, Stats, History
 */

const API = 'http://localhost:8000';

/* ─── Helpers ─────────────────────────────────────────────────── */
const $ = id => document.getElementById(id);

function toast(msg, type = 'info', ms = 3600) {
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.textContent = msg;
  $('toasts').appendChild(el);
  setTimeout(() => {
    el.style.animation = 'slideRight .28s ease reverse';
    setTimeout(() => el.remove(), 290);
  }, ms);
}

function fmtDate(iso) {
  try {
    return new Intl.DateTimeFormat('en-US', {
      month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit', hour12: false,
    }).format(new Date(iso));
  } catch { return iso; }
}

/* ─── API Status ───────────────────────────────────────────────── */
async function checkApi() {
  try {
    const r = await fetch(`${API}/health`, { signal: AbortSignal.timeout(4000) });
    const ok = r.ok;
    $('status-dot').className = `status-dot ${ok ? 'online' : 'offline'}`;
    $('status-text').textContent = ok ? 'API Online' : 'API Offline';
    return ok;
  } catch {
    $('status-dot').className = 'status-dot offline';
    $('status-text').textContent = 'API Offline';
    return false;
  }
}

/* ─── Tab switching ────────────────────────────────────────────── */
const tabUrl = $('tab-url');
const tabMsg = $('tab-msg');
const panelUrl = $('panel-url');
const panelMsg = $('panel-msg');

function switchTab(which) {
  const isUrl = which === 'url';
  tabUrl.classList.toggle('active', isUrl);
  tabMsg.classList.toggle('active', !isUrl);
  tabUrl.setAttribute('aria-selected', isUrl);
  tabMsg.setAttribute('aria-selected', !isUrl);
  panelUrl.classList.toggle('hidden', !isUrl);
  panelMsg.classList.toggle('hidden', isUrl);
  // Hide result when switching tabs
  $('result-area').classList.add('hidden');
}

tabUrl.addEventListener('click', () => switchTab('url'));
tabMsg.addEventListener('click', () => switchTab('msg'));

/* ─── URL Input helpers ────────────────────────────────────────── */
const urlInput = $('url-input');
const urlClearBtn = $('url-clear-btn');

urlInput.addEventListener('input', () => {
  urlClearBtn.hidden = !urlInput.value.trim();
});
urlClearBtn.addEventListener('click', () => {
  urlInput.value = '';
  urlClearBtn.hidden = true;
  urlInput.focus();
  $('result-area').classList.add('hidden');
});

// Demo URL chips
document.querySelectorAll('#url-demos .chip').forEach(chip => {
  chip.addEventListener('click', () => {
    urlInput.value = chip.dataset.url;
    urlInput.dispatchEvent(new Event('input'));
    urlInput.focus();
  });
});

// Demo message chips
document.querySelectorAll('#msg-demos .chip').forEach(chip => {
  chip.addEventListener('click', () => {
    $('msg-input').value = chip.dataset.msg;
    updateMsgCount();
    $('msg-input').focus();
  });
});

/* ─── Message char counter ─────────────────────────────────────── */
function updateMsgCount() {
  const l = $('msg-input').value.length;
  $('msg-char-count').textContent = `${l.toLocaleString()} / 10,000 chars`;
}
$('msg-input').addEventListener('input', updateMsgCount);

/* ─── Result visibility ───────────────────────────────────────── */
function prepareResult() {
  const ra = $('result-area');
  ra.classList.add('hidden');
  $('url-result').hidden = true;
  $('msg-result').hidden = true;
}
function showError(msg) {
  $('result-area').classList.add('hidden');
  toast(msg, 'error', 5000);
}
function showUrlResult() {
  $('result-area').classList.remove('hidden');
  $('url-result').hidden = false;
  $('msg-result').hidden = true;
}
function showMsgResult() {
  $('result-area').classList.remove('hidden');
  $('url-result').hidden = true;
  $('msg-result').hidden = false;
}

/* ─── Gauge animation ──────────────────────────────────────────── */
function animateGauge(arcId, numId, score) {
  const arc = $(arcId);
  const num = $(numId);
  const offset = 314 - (score / 100) * 314;
  arc.style.strokeDashoffset = offset;
  num.textContent = score;
  arc.className = 'gauge-arc';
  if (score >= 65) arc.classList.add('danger');
  else if (score >= 35) arc.classList.add('warning');
  else arc.classList.add('safe');
}

/* ─── URL SCAN ─────────────────────────────────────────────────── */
let lastUrl = '';

async function doUrlScan(url) {
  if (!url.trim()) { toast('Please enter a URL.', 'error'); urlInput.focus(); return; }
  lastUrl = url;
  prepareResult();

  const btn = $('url-scan-btn');
  btn.disabled = true; btn.querySelector('span:last-child').textContent = '⏳ Scanning…';

  // Reset conf bar
  $('url-conf-fill').style.width = '0%';
  $('url-gauge-arc').style.strokeDashoffset = '314';

  try {
    const res = await fetch(`${API}/api/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
      signal: AbortSignal.timeout(15000),
    });
    if (!res.ok) { const e = await res.json().catch(()=>({})); throw new Error(e.detail || `Error ${res.status}`); }
    const d = await res.json();
    renderUrlResult(d);
    const isPhish = d.prediction === 'phishing';
    toast(isPhish ? `⚠️ Phishing! Risk: ${d.risk_score}/100` : `✅ Legit. Risk: ${d.risk_score}/100`,
          isPhish ? 'error' : 'success', 5000);
    loadStats(true); loadUrlHistory();
  } catch (err) {
    showError(err.name === 'TimeoutError' ? 'Timed out. Is the backend running?' : err.message);
  } finally {
    btn.disabled = false; btn.querySelector('span:last-child').textContent = '⚡ Scan URL';
  }
}

function renderUrlResult(d) {
  const isPhish = d.prediction === 'phishing';
  const row = $('url-verdict-row');
  row.className = `verdict-row ${d.prediction}`;
  $('url-verdict-icon').textContent = isPhish ? '🎣' : '✅';
  $('url-verdict-label').textContent = isPhish ? 'Phishing URL Detected' : 'Legitimate URL';
  $('url-verdict-url').textContent = d.url;
  $('url-verdict-pill').textContent = isPhish ? '⚠ DANGER' : '✓ SAFE';

  animateGauge('url-gauge-arc', 'url-gauge-num', d.risk_score);

  const confPct = Math.round(d.confidence * 100);
  $('url-conf-val').textContent = `${confPct}%`;
  setTimeout(() => { $('url-conf-fill').style.width = `${confPct}%`; }, 60);
  $('url-conf-note').textContent = isPhish ? 'Model is confident this is phishing' : 'Model is confident this is legitimate';

  $('url-scan-id').textContent = d.scan_id ? d.scan_id.slice(0,12)+'…' : '—';
  $('url-cached').textContent = d.cached ? '⚡ Yes' : '🔄 Fresh';
  $('url-protocol').textContent = d.url.startsWith('https') ? 'HTTPS' : 'HTTP';
  $('url-https').textContent = d.features?.is_https ? '🔒 Yes' : '🔓 No';

  // Indicators
  const indList = $('url-indicators-list');
  indList.innerHTML = '';
  (d.top_indicators || []).forEach((text, i) => {
    const li = document.createElement('li');
    const isSafe = text.includes('No suspicious') || text.includes('HTTPS') || text.includes('recognized');
    li.className = `ind-item ${isSafe ? 'safe' : (isPhish ? 'danger' : 'safe')}`;
    li.style.animationDelay = `${i * 55}ms`;
    li.innerHTML = `<span>${isSafe ? '✅' : '⚠️'}</span><span>${text}</span>`;
    indList.appendChild(li);
  });

  // Feature grid
  const grid = $('url-features-grid');
  grid.innerHTML = '';
  const feats = d.features || {};
  Object.entries(feats).forEach(([k, v]) => {
    const chip = document.createElement('div');
    const isHigh = typeof v === 'number' && v > 1 &&
      !['url_length','domain_length','path_length','query_length','count_digits','path_depth','domain_entropy'].includes(k);
    chip.className = `feat-chip${isHigh ? ' hi' : ''}`;
    chip.innerHTML = `<span class="fn">${k.replace(/_/g,' ')}</span><span class="fv">${typeof v==='number'&&!Number.isInteger(v)?v.toFixed(3):v}</span>`;
    grid.appendChild(chip);
  });

  showUrlResult();
  $('result-area').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

$('url-form').addEventListener('submit', e => {
  e.preventDefault();
  doUrlScan(urlInput.value.trim());
});

/* ─── MESSAGE SCAN ─────────────────────────────────────────────── */
let lastMsg = '';

async function doMsgScan(msg) {
  if (!msg.trim()) { toast('Please enter a message to analyze.', 'error'); $('msg-input').focus(); return; }
  lastMsg = msg;
  prepareResult();

  const btn = $('msg-scan-btn');
  btn.disabled = true; btn.querySelector('span:last-child').textContent = '⏳ Analyzing…';
  $('msg-gauge-arc').style.strokeDashoffset = '314';

  try {
    const res = await fetch(`${API}/check-message`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: msg }),
      signal: AbortSignal.timeout(10000),
    });
    if (!res.ok) { const e = await res.json().catch(()=>({})); throw new Error(e.detail || `Error ${res.status}`); }
    const d = await res.json();
    renderMsgResult(d, msg);

    const v = d.verdict;
    const toastType = v==='dangerous' ? 'error' : v==='suspicious' ? 'info' : 'success';
    const toastEmoji = v==='dangerous' ? '🚨' : v==='suspicious' ? '⚠️' : '✅';
    toast(`${toastEmoji} ${v.charAt(0).toUpperCase()+v.slice(1)} message. Risk: ${d.risk_score}/100`, toastType, 5000);
    loadStats(true); loadMsgHistory();
  } catch (err) {
    showError(err.name === 'TimeoutError' ? 'Timed out. Is the backend running?' : err.message);
  } finally {
    btn.disabled = false; btn.querySelector('span:last-child').textContent = '🔍 Analyze Message';
  }
}

function renderMsgResult(d, originalMsg) {
  const v = d.verdict; // safe | suspicious | dangerous
  const row = $('msg-verdict-row');
  row.className = `verdict-row ${v}`;

  const icons = { dangerous:'🚨', suspicious:'⚠️', safe:'✅' };
  const labels = { dangerous:'Dangerous — Social Engineering Detected', suspicious:'Suspicious Message', safe:'Message Appears Safe' };
  const pills  = { dangerous:'⚠ DANGEROUS', suspicious:'⚠ SUSPICIOUS', safe:'✓ SAFE' };

  $('msg-verdict-icon').textContent = icons[v] || '?';
  $('msg-verdict-label').textContent = labels[v] || v;
  $('msg-verdict-preview').textContent = (originalMsg || '').slice(0, 80) + ((originalMsg||'').length > 80 ? '…' : '');
  $('msg-verdict-pill').textContent = pills[v] || v;

  animateGauge('msg-gauge-arc', 'msg-gauge-num', d.risk_score);

  const cats = d.categories_triggered || [];
  $('msg-tactic-count').textContent = cats.length;
  $('msg-cats-note').textContent = `manipulation ${cats.length === 1 ? 'category' : 'categories'} detected`;
  const pillsWrap = $('msg-tactic-pills');
  pillsWrap.innerHTML = '';
  cats.forEach(c => {
    const p = document.createElement('span');
    p.className = 'tactic-pill';
    p.textContent = c;
    pillsWrap.appendChild(p);
  });

  const stats = d.statistics || {};
  $('msg-words').textContent = stats.word_count ?? '—';
  $('msg-urls').textContent = stats.url_count != null ? `${stats.url_count}${stats.has_urls ? ' ⚠' : ''}` : '—';
  $('msg-caps').textContent = stats.caps_ratio != null ? `${Math.round(stats.caps_ratio*100)}%` : '—';
  $('msg-excl').textContent = stats.exclamation_count ?? '—';

  // Warning signs
  const wList = $('msg-warnings-list');
  wList.innerHTML = '';
  (d.warning_signs || []).forEach((text, i) => {
    const li = document.createElement('li');
    const isSafe = text.includes('No social');
    li.className = `ind-item ${isSafe ? 'safe' : (v==='dangerous' ? 'danger' : v==='suspicious' ? 'warning' : 'safe')}`;
    li.style.animationDelay = `${i * 55}ms`;
    li.innerHTML = `<span>${isSafe ? '✅' : (v==='safe' ? '✅' : '🚩')}</span><span>${text}</span>`;
    wList.appendChild(li);
  });

  showMsgResult();
  $('result-area').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

$('msg-form').addEventListener('submit', e => {
  e.preventDefault();
  doMsgScan($('msg-input').value.trim());
});

/* ─── Feature toggle ───────────────────────────────────────────── */
$('url-features-toggle').addEventListener('click', () => {
  const grid = $('url-features-grid');
  const hidden = grid.classList.contains('hidden');
  grid.classList.toggle('hidden', !hidden);
  $('url-features-toggle').textContent = hidden ? 'Hide details' : 'Show details';
  $('url-features-toggle').setAttribute('aria-expanded', hidden);
});

/* ─── Stats ────────────────────────────────────────────────────── */
async function loadStats(silent = false) {
  try {
    const r = await fetch(`${API}/api/stats`, { signal: AbortSignal.timeout(5000) });
    if (!r.ok) throw new Error();
    const d = await r.json();

    // URL stats
    const u = d.url_scans || {};
    $('s-url-total').textContent = (u.total ?? 0).toLocaleString();
    $('s-url-phish').textContent = (u.phishing_count ?? 0).toLocaleString();
    $('s-url-legit').textContent = (u.legitimate_count ?? 0).toLocaleString();
    $('s-url-ratio').textContent  = u.phishing_ratio != null ? `${(u.phishing_ratio*100).toFixed(1)}%` : '—';

    // Message stats
    const m = d.message_scans || {};
    $('s-msg-total').textContent  = (m.total ?? 0).toLocaleString();
    $('s-msg-danger').textContent = (m.dangerous_count ?? 0).toLocaleString();
    $('s-msg-sus').textContent    = (m.suspicious_count ?? 0).toLocaleString();
    $('s-total').textContent      = (d.combined_total ?? 0).toLocaleString();

    if (!silent) toast('Stats refreshed.', 'success');
  } catch {
    if (!silent) toast('Could not load stats. Is the API running?', 'error');
  }
}
$('refresh-stats-btn').addEventListener('click', () => loadStats());

/* ─── URL History ──────────────────────────────────────────────── */
async function loadUrlHistory() {
  try {
    const r = await fetch(`${API}/api/history?limit=20`, { signal: AbortSignal.timeout(5000) });
    if (!r.ok) throw new Error();
    const d = await r.json();
    const tbody = $('url-history-body');
    if (!d.scans?.length) {
      tbody.innerHTML = '<tr><td colspan="5" class="empty-row">No URL scans yet.</td></tr>';
      return;
    }
    tbody.innerHTML = d.scans.map(s => `
      <tr>
        <td><span class="url-cell" title="${escHtml(s.url)}">${escHtml(s.url)}</span></td>
        <td><span class="pill ${s.prediction}">${s.prediction}</span></td>
        <td>${s.risk_score ?? '—'}/100</td>
        <td>${s.confidence != null ? (s.confidence*100).toFixed(1)+'%' : '—'}</td>
        <td>${fmtDate(s.timestamp)}</td>
      </tr>`).join('');
  } catch {
    $('url-history-body').innerHTML = '<tr><td colspan="5" class="empty-row">Failed to load. Is the API running?</td></tr>';
  }
}

/* ─── Message History ──────────────────────────────────────────── */
async function loadMsgHistory() {
  try {
    const r = await fetch(`${API}/api/message-history?limit=20`, { signal: AbortSignal.timeout(5000) });
    if (!r.ok) throw new Error();
    const d = await r.json();
    const tbody = $('msg-history-body');
    if (!d.scans?.length) {
      tbody.innerHTML = '<tr><td colspan="5" class="empty-row">No message scans yet.</td></tr>';
      return;
    }
    tbody.innerHTML = d.scans.map(s => `
      <tr>
        <td><span class="url-cell" style="max-width:220px" title="${escHtml(s.message_preview||'')}">${escHtml(s.message_preview||'—')}</span></td>
        <td><span class="pill ${s.verdict}">${s.verdict}</span></td>
        <td>${s.risk_score ?? '—'}/100</td>
        <td style="font-size:.74rem;color:var(--txt-2)">${(s.categories_triggered||[]).slice(0,2).join(', ') || '—'}</td>
        <td>${fmtDate(s.timestamp)}</td>
      </tr>`).join('');
  } catch {
    $('msg-history-body').innerHTML = '<tr><td colspan="5" class="empty-row">Failed to load.</td></tr>';
  }
}

function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

/* ─── History tab switching ────────────────────────────────────── */
document.querySelectorAll('.h-tab').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.h-tab').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    const target = btn.dataset.target;
    document.querySelectorAll('.history-panel').forEach(p => p.classList.add('hidden'));
    $(target).classList.remove('hidden');
  });
});

/* ─── Refresh + Clear history ──────────────────────────────────── */
$('refresh-history-btn').addEventListener('click', async () => {
  await Promise.all([loadUrlHistory(), loadMsgHistory()]);
  toast('History refreshed.', 'info');
});

$('clear-history-btn').addEventListener('click', async () => {
  if (!confirm('Clear ALL scan history? This cannot be undone.')) return;
  try {
    // Delete URL scans
    await fetch(`${API}/api/history`, { method: 'DELETE', signal: AbortSignal.timeout(5000) });
    await loadUrlHistory(); await loadMsgHistory(); await loadStats(true);
    toast('History cleared.', 'info');
  } catch { toast('Failed to clear.', 'error'); }
});

/* ─── Bulk scan ─────────────────────────────────────────────────── */
const bulkInput = $('bulk-input');
bulkInput.addEventListener('input', () => {
  const count = bulkInput.value.split('\n').map(s=>s.trim()).filter(Boolean).length;
  $('bulk-count').textContent = `${Math.min(count,20)} URL${count!==1?'s':''}`;
});

$('bulk-scan-btn').addEventListener('click', async () => {
  const urls = bulkInput.value.split('\n').map(s=>s.trim()).filter(Boolean).slice(0,20);
  if (!urls.length) { toast('Enter at least one URL.', 'error'); return; }
  const btn = $('bulk-scan-btn');
  btn.disabled=true; btn.querySelector('span:last-child').textContent='⏳ Scanning…';
  $('bulk-results').classList.add('hidden');
  try {
    const r = await fetch(`${API}/api/scan/bulk`, {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({urls}),
      signal:AbortSignal.timeout(30000),
    });
    if(!r.ok) throw new Error(`Error ${r.status}`);
    const d = await r.json();
    const rows = $('bulk-rows');
    rows.innerHTML='';
    d.results.forEach(item => {
      const row = document.createElement('div');
      row.className = `bulk-row ${item.prediction||''}`;
      if(item.error){
        row.innerHTML=`<span class="bulk-url">${escHtml(item.url)}</span><span style="color:var(--txt-3);font-size:.76rem">Error</span><span>—</span>`;
      } else {
        const isPhish = item.prediction==='phishing';
        row.innerHTML=`
          <span class="bulk-url">${escHtml(item.url)}</span>
          <span class="bulk-verdict ${item.prediction}">${isPhish?'⚠ Phishing':'✓ Legit'}</span>
          <span class="bulk-score">Risk: ${item.risk_score}/100</span>`;
      }
      rows.appendChild(row);
    });
    const phishN = d.results.filter(x=>x.prediction==='phishing').length;
    $('bulk-heading').textContent = `Results — ${phishN} phishing out of ${d.total}`;
    $('bulk-results').classList.remove('hidden');
    $('bulk-results').scrollIntoView({behavior:'smooth',block:'nearest'});
    toast(phishN?`⚠️ ${phishN} phishing URL${phishN>1?'s':''} detected!`:'✅ All URLs appear legitimate.',
          phishN?'error':'success', 5000);
    loadStats(true); loadUrlHistory();
  } catch(err){ toast(err.name==='TimeoutError'?'Request timed out.':err.message,'error'); }
  finally{ btn.disabled=false; btn.querySelector('span:last-child').textContent='🚀 Scan All'; }
});

/* ─── Nav smooth scroll ─────────────────────────────────────────── */
document.querySelectorAll('.nav-link').forEach(link => {
  link.addEventListener('click', e => {
    const href = link.getAttribute('href');
    if (href?.startsWith('#')) {
      e.preventDefault();
      document.querySelector(href)?.scrollIntoView({ behavior: 'smooth' });
    }
  });
});

/* ─── Init ──────────────────────────────────────────────────────── */
(async function init() {
  await checkApi();
  loadStats(true);
  loadUrlHistory();
  loadMsgHistory();
  setInterval(checkApi, 30_000);
})();
