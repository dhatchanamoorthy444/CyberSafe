/**
 * CyberSafe — Frontend Application Logic v2
 * Modes: Offline Analysis + Safe Recon
 */

// ============================================================================
// Configuration
// ============================================================================
const BASE_URL = (typeof import.meta !== 'undefined' && import.meta.env && import.meta.env.VITE_API_URL)
  ? import.meta.env.VITE_API_URL.replace(/\/$/, '')
  : '';

const API = {
  analyze: BASE_URL ? `${BASE_URL}/api/analyze` : '/api/analyze',
  recon:   BASE_URL ? `${BASE_URL}/api/recon`   : '/api/recon',
};

// ============================================================================
// DOM References
// ============================================================================
const form           = document.getElementById('analyze-form');
const urlInput       = document.getElementById('url-input');
const analyzeBtn     = document.getElementById('analyze-btn');
const qrToggleBtn    = document.getElementById('qr-toggle-btn');
const qrReaderContainer = document.getElementById('qr-reader-container');
const qrCloseBtn     = document.getElementById('qr-close-btn');

const loadingState   = document.getElementById('loading-state');
const loadingText    = document.getElementById('loading-text');
const errorState     = document.getElementById('error-state');
const errorTitle     = document.getElementById('error-title');
const errorMessage   = document.getElementById('error-message');
const resultsContainer = document.getElementById('results-container');

// Offline analysis elements
const offlineResults = document.getElementById('offline-results');
const verdictBanner  = document.getElementById('verdict-banner');
const verdictIcon    = document.getElementById('verdict-icon');
const verdictTitle   = document.getElementById('verdict-title');
const verdictRecommendation = document.getElementById('verdict-recommendation');
const scoreText      = document.getElementById('score-text');
const confidenceText = document.getElementById('confidence-text');
const anatomyGrid    = document.getElementById('anatomy-grid');
const findingsList   = document.getElementById('findings-list');
const findingsCount  = document.getElementById('findings-count');

// Recon elements
const reconResults      = document.getElementById('recon-results');
const reconSummaryGrid  = document.getElementById('recon-summary-grid');
const terminalView      = document.getElementById('terminal-view');
const terminalOutput    = document.getElementById('terminal-output');
const terminalToggleBtn = document.getElementById('terminal-toggle-btn');

// Mode selector
const modeOfflineBtn = document.getElementById('mode-offline-btn');
const modeReconBtn   = document.getElementById('mode-recon-btn');
const modeDescText   = document.getElementById('mode-desc-text');

// History
const historyList    = document.getElementById('history-list');
const emptyHistory   = document.getElementById('empty-history');
const clearHistoryBtn = document.getElementById('clear-history-btn');

// ============================================================================
// State
// ============================================================================
let qrScanner   = null;
let scanHistory = [];
let currentMode = 'offline'; // 'offline' | 'recon'

// ============================================================================
// Initialization
// ============================================================================
document.addEventListener('DOMContentLoaded', () => {
  if (typeof lucide !== 'undefined') lucide.createIcons();

  loadHistoryFromStorage();
  renderHistory();

  form.addEventListener('submit', handleFormSubmit);
  qrToggleBtn.addEventListener('click', toggleQRScanner);
  qrCloseBtn.addEventListener('click', closeQRScanner);
  clearHistoryBtn.addEventListener('click', clearHistory);

  // Mode buttons
  modeOfflineBtn.addEventListener('click', () => setMode('offline'));
  modeReconBtn.addEventListener('click',   () => setMode('recon'));

  // Demo buttons
  document.querySelectorAll('.demo-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      urlInput.value = btn.getAttribute('data-url');
      urlInput.focus();
    });
  });

  // Recon tab navigation
  document.querySelectorAll('.recon-tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const tab = btn.getAttribute('data-tab');
      document.querySelectorAll('.recon-tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.recon-tab-panel').forEach(p => p.classList.add('hidden'));
      btn.classList.add('active');
      const panel = document.getElementById(`recon-tab-${tab}`);
      if (panel) panel.classList.remove('hidden');
    });
  });

  // Terminal toggle
  if (terminalToggleBtn) {
    terminalToggleBtn.addEventListener('click', () => {
      terminalView.classList.toggle('hidden');
      terminalToggleBtn.textContent = terminalView.classList.contains('hidden')
        ? 'Terminal View' : 'Hide Terminal';
    });
  }
});

// ============================================================================
// Mode Management
// ============================================================================
function setMode(mode) {
  currentMode = mode;
  modeOfflineBtn.classList.toggle('active', mode === 'offline');
  modeReconBtn.classList.toggle('active',   mode === 'recon');

  if (mode === 'offline') {
    modeDescText.textContent = 'Offline mode — analyzes URL structure without contacting the destination.';
    analyzeBtn.querySelector('span') && (analyzeBtn.querySelector('span').textContent = 'Analyze');
  } else {
    modeDescText.textContent = 'Safe Recon — retrieves limited public technical metadata. Uses a real network request.';
    analyzeBtn.querySelector('span') && (analyzeBtn.querySelector('span').textContent = 'Run Recon');
  }
}

// ============================================================================
// Form Submission
// ============================================================================
async function handleFormSubmit(e) {
  e.preventDefault();
  const url = urlInput.value.trim();
  if (!url) return;

  hideError();
  hideResults();
  showLoading(currentMode === 'recon'
    ? 'Performing safe reconnaissance...'
    : 'Running deterministic security analysis...');

  try {
    if (currentMode === 'recon') {
      await handleRecon(url);
    } else {
      await handleAnalyze(url);
    }
  } catch (err) {
    showError('Request Failed', err.message);
  } finally {
    hideLoading();
  }
}

// ============================================================================
// Offline Analysis
// ============================================================================
async function handleAnalyze(url) {
  const response = await fetch(API.analyze, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url }),
  });

  const data = await response.json();
  if (!response.ok || !data.success) {
    throw new Error(data.error?.message || 'Analysis failed. Please try again.');
  }

  addToHistory({ url, verdict: data.analysis.verdict, score: data.analysis.score, timestamp: Date.now(), mode: 'offline' });
  renderAnalysisResults(data.analysis);
  showResults('offline');
}

// ============================================================================
// Safe Recon
// ============================================================================
async function handleRecon(url) {
  const response = await fetch(API.recon, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url }),
  });

  const data = await response.json();
  if (!response.ok || !data.success) {
    throw new Error(data.error?.message || data.error?.code || 'Recon failed.');
  }

  const recon = data.recon;
  const risk  = recon.risk || {};

  addToHistory({ url, verdict: risk.level || 'UNKNOWN', score: risk.score || 0, timestamp: Date.now(), mode: 'recon' });
  renderReconResults(recon);
  showResults('recon');
}

// ============================================================================
// Render — Offline Analysis
// ============================================================================
function renderAnalysisResults(analysis) {
  // Verdict banner
  const v = analysis.verdict;
  verdictBanner.className = `verdict-banner ${v}`;
  verdictTitle.textContent = v;
  verdictRecommendation.textContent = analysis.recommendation || '';
  scoreText.textContent   = `${analysis.score}/100`;
  confidenceText.textContent = (analysis.confidence || '').toUpperCase();

  const iconMap = { SAFE: 'shield-check', REVIEW: 'alert-circle', SUSPICIOUS: 'shield-alert' };
  verdictIcon.innerHTML = `<i data-lucide="${iconMap[v] || 'shield'}"></i>`;

  renderAnatomy(analysis);
  renderFindings(analysis.findings || []);
  if (typeof lucide !== 'undefined') lucide.createIcons();
}

function renderAnatomy(analysis) {
  const p = analysis.parsed || {};
  const items = [
    { label: 'Actual Hostname', value: analysis.actual_hostname || p.hostname || 'None' },
    { label: 'Scheme',          value: p.scheme || 'None' },
    { label: 'Userinfo (@)',    value: p.has_userinfo ? 'Yes — Deceptive Pattern' : 'No' },
    { label: 'Port',            value: p.port || 'Default' },
    { label: 'Path',            value: p.path || '/' },
    { label: 'Query',           value: p.query || 'None' },
    { label: 'Fragment',        value: p.fragment || 'None' },
    { label: 'Punycode',        value: p.is_punycode ? `Yes — ${p.unicode_hostname || 'IDN'}` : 'No' },
    { label: 'URL Length',      value: `${(p.original_url || '').length} chars` },
  ];
  anatomyGrid.innerHTML = items.map(i => `
    <div class="anatomy-item">
      <div class="anatomy-label">${escapeHTML(i.label)}</div>
      <div class="anatomy-value">${escapeHTML(String(i.value))}</div>
    </div>`).join('');
}

function renderFindings(findings) {
  findingsCount.textContent = `${findings.length} triggered`;
  if (findings.length === 0) {
    findingsList.innerHTML = `<div class="clean-slate"><p>✓ No structural risks or deception indicators detected.</p></div>`;
    return;
  }
  findingsList.innerHTML = findings.map(f => `
    <div class="finding-card">
      <div class="finding-header">
        <span class="finding-title">${escapeHTML(f.title)}</span>
        <span class="severity-badge ${escapeHTML(f.severity)}">${escapeHTML(f.severity)}</span>
      </div>
      <div class="finding-desc">${escapeHTML(f.message)}</div>
      ${f.evidence ? `<div class="finding-evidence">Evidence: ${escapeHTML(f.evidence)}</div>` : ''}
    </div>`).join('');
}

// ============================================================================
// Render — Safe Recon
// ============================================================================
function renderReconResults(recon) {
  const risk    = recon.risk    || {};
  const http    = recon.http    || {};
  const tls     = recon.tls     || {};
  const target  = recon.target  || {};
  const headers = recon.headers || {};

  // Top verdict banner (using recon risk)
  const level = risk.level || 'UNKNOWN';
  const levelClass = { LOW: 'SAFE', MEDIUM: 'REVIEW', HIGH: 'SUSPICIOUS', CRITICAL: 'SUSPICIOUS' }[level] || 'REVIEW';
  verdictBanner.className = `verdict-banner ${levelClass}`;
  verdictTitle.textContent = `RECON: ${level} RISK`;
  verdictRecommendation.textContent = risk.indicators?.length
    ? risk.indicators.join(' · ')
    : 'No critical indicators detected from public metadata.';
  scoreText.textContent    = `${risk.score || 0}/100`;
  confidenceText.textContent = 'RECON';
  verdictIcon.innerHTML    = `<i data-lucide="radar"></i>`;
  if (typeof lucide !== 'undefined') lucide.createIcons();

  // Summary grid
  reconSummaryGrid.innerHTML = [
    { label: 'HTTPS',    value: tls.enabled ? '✓ Enabled'  : '✗ Not enabled',  ok: tls.enabled },
    { label: 'TLS',      value: tls.expired === false ? '✓ Valid' : tls.expired ? '✗ Expired' : tls.enabled ? '? Unknown' : '— N/A', ok: !tls.expired && tls.enabled },
    { label: 'HTTP',     value: http.status_code ? `${http.status_code}` : '— N/A', ok: http.status_code >= 200 && http.status_code < 400 },
    { label: 'Redirects',value: http.redirect_count > 1 ? `⚠ ${http.redirect_count}` : `✓ ${http.redirect_count || 0}`, ok: (http.redirect_count || 0) <= 1 },
    { label: 'Sec Headers', value: (() => { const missing = Object.values(headers).filter(h => !h.present).length; return missing ? `⚠ ${missing} missing` : '✓ All present'; })(), ok: Object.values(headers).every(h => h.present) },
    { label: 'DNS',      value: recon.dns?.A?.length ? '✓ Resolved' : '? No A record', ok: (recon.dns?.A?.length || 0) > 0 },
  ].map(s => `
    <div class="recon-summary-item ${s.ok ? 'ok' : 'warn'}">
      <span class="recon-summary-label">${escapeHTML(s.label)}</span>
      <span class="recon-summary-value">${escapeHTML(s.value)}</span>
    </div>`).join('');

  // Terminal output
  if (terminalOutput) {
    terminalOutput.textContent = buildTerminalOutput(recon);
  }

  // Tabs
  renderReconTabDNS(recon.dns || {});
  renderReconTabHTTP(http);
  renderReconTabTLS(tls);
  renderReconTabHeaders(headers);
  renderReconTabCookies(recon.cookies || []);
  renderReconTabTech(recon.technology || {});
}

function renderReconTabDNS(dns) {
  const panel = document.getElementById('recon-tab-dns');
  if (!panel) return;
  const types = ['A','AAAA','CNAME','MX','NS','TXT'];
  panel.innerHTML = types.map(t => {
    const records = dns[t] || [];
    return `<div class="recon-record-group">
      <div class="recon-record-type">${t}</div>
      ${records.length === 0
        ? `<div class="recon-record-empty">No records</div>`
        : records.map(r => `<div class="recon-record-value font-mono">${escapeHTML(r.value || r.error || '')}${r.ttl ? `<span class="recon-ttl"> TTL ${r.ttl}s</span>` : ''}</div>`).join('')
      }
    </div>`;
  }).join('');
}

function renderReconTabHTTP(http) {
  const panel = document.getElementById('recon-tab-http');
  if (!panel) return;
  const rows = [
    ['Status',       http.status_code || '—'],
    ['Final URL',    http.final_url   || '—'],
    ['Redirects',    http.redirect_count ?? '—'],
    ['Content-Type', http.content_type || '—'],
    ['Server',       http.server       || '—'],
    ['Error',        http.error        || 'None'],
  ];
  let html = `<table class="recon-table">${rows.map(([k,v]) =>
    `<tr><td class="recon-table-key">${escapeHTML(k)}</td><td class="recon-table-val font-mono">${escapeHTML(String(v))}</td></tr>`).join('')}</table>`;

  if (http.redirects?.length > 1) {
    html += `<div class="recon-redirect-chain"><div class="recon-section-title">Redirect Chain</div>`;
    http.redirects.forEach((r, i) => {
      html += `<div class="recon-redirect-hop">
        <span class="recon-hop-num">${i+1}</span>
        <span class="recon-hop-url font-mono">${escapeHTML(r.url)}</span>
        <span class="recon-hop-status">${r.status}</span>
      </div>`;
    });
    html += `</div>`;
  }
  panel.innerHTML = html;
}

function renderReconTabTLS(tls) {
  const panel = document.getElementById('recon-tab-tls');
  if (!panel) return;
  if (!tls.enabled) {
    panel.innerHTML = `<div class="recon-warning">⚠ TLS not enabled or could not be retrieved.<br>${escapeHTML(tls.error || tls.reason || '')}</div>`;
    return;
  }
  const rows = [
    ['Enabled',          tls.enabled ? 'Yes' : 'No'],
    ['Version',          tls.version  || '—'],
    ['Subject',          tls.subject  || '—'],
    ['Issuer',           tls.issuer   || '—'],
    ['Valid From',       tls.valid_from  || '—'],
    ['Valid Until',      tls.valid_until || '—'],
    ['Expired',          tls.expired === true ? '⚠ Yes' : tls.expired === false ? '✓ No' : '?'],
    ['Days Remaining',   tls.days_remaining != null ? `${tls.days_remaining} days` : '—'],
    ['Hostname Matches', tls.hostname_matches === true ? '✓ Yes' : tls.hostname_matches === false ? '✗ No' : '?'],
  ];
  panel.innerHTML = `<table class="recon-table">${rows.map(([k,v]) =>
    `<tr><td class="recon-table-key">${escapeHTML(k)}</td><td class="recon-table-val font-mono">${escapeHTML(String(v))}</td></tr>`).join('')}</table>`;
}

function renderReconTabHeaders(headers) {
  const panel = document.getElementById('recon-tab-headers');
  if (!panel) return;
  panel.innerHTML = Object.entries(headers).map(([name, info]) => `
    <div class="recon-header-row ${info.present ? 'present' : 'missing'}">
      <div class="recon-header-name">
        <span class="recon-header-status">${info.present ? '✓' : '✗'}</span>
        ${escapeHTML(name)}
      </div>
      ${info.present && info.value ? `<div class="recon-header-value font-mono">${escapeHTML(info.value)}</div>` : ''}
      <div class="recon-header-desc">${escapeHTML(info.description || '')}</div>
    </div>`).join('');
}

function renderReconTabCookies(cookies) {
  const panel = document.getElementById('recon-tab-cookies');
  if (!panel) return;
  if (!cookies.length) {
    panel.innerHTML = `<div class="recon-empty">No cookies found in response.</div>`;
    return;
  }
  panel.innerHTML = cookies.map(c => `
    <div class="recon-cookie-card">
      <div class="recon-cookie-name font-mono">${escapeHTML(c.name)}</div>
      <div class="recon-cookie-flags">
        <span class="cookie-flag ${c.secure    ? 'ok' : 'warn'}">Secure: ${c.secure    ? '✓' : '✗'}</span>
        <span class="cookie-flag ${c.http_only ? 'ok' : 'warn'}">HttpOnly: ${c.http_only ? '✓' : '✗'}</span>
        <span class="cookie-flag ${c.same_site ? 'ok' : 'warn'}">SameSite: ${c.same_site ? escapeHTML(c.same_site) : '✗'}</span>
      </div>
      ${c.warnings.length ? `<div class="recon-cookie-warnings">${c.warnings.map(w => `<div class="recon-warning-item">⚠ ${escapeHTML(w)}</div>`).join('')}</div>` : ''}
    </div>`).join('');
}

function renderReconTabTech(tech) {
  const panel = document.getElementById('recon-tab-tech');
  if (!panel) return;
  const entries = Object.entries(tech);
  if (!entries.length) {
    panel.innerHTML = `<div class="recon-empty">No technology signals detected from public headers.</div>`;
    return;
  }
  panel.innerHTML = `<table class="recon-table">${entries.map(([k,v]) =>
    `<tr><td class="recon-table-key">${escapeHTML(k)}</td><td class="recon-table-val font-mono">${escapeHTML(String(v))}</td></tr>`).join('')}</table>`;
}

// ============================================================================
// Terminal View
// ============================================================================
function buildTerminalOutput(recon) {
  const t   = recon.target  || {};
  const dns = recon.dns     || {};
  const http = recon.http   || {};
  const tls  = recon.tls    || {};
  const risk = recon.risk   || {};
  const hdr  = recon.headers || {};

  const lines = [
    `$ cybersafe recon ${t.hostname || '?'}`,
    ``,
    `[+] Target:      ${t.hostname || '?'}`,
    `[+] Scheme:      ${(t.scheme || '').toUpperCase()}`,
    `[+] Registered:  ${t.registered_domain || t.hostname || '?'}`,
    ``,
    `[DNS]`,
    `[+] A:    ${(dns.A || []).map(r => r.value).join(', ') || 'no records'}`,
    `[+] AAAA: ${(dns.AAAA || []).map(r => r.value).join(', ') || 'no records'}`,
    `[+] MX:   ${(dns.MX || []).map(r => r.value).join(', ') || 'no records'}`,
    ``,
    `[HTTP]`,
    `[+] Status:     ${http.status_code || '—'}`,
    `[+] Final URL:  ${http.final_url || '—'}`,
    `[+] Redirects:  ${http.redirect_count || 0}`,
    ``,
    `[TLS]`,
    `[${tls.enabled ? '+' : '!'}] TLS:     ${tls.enabled ? 'ENABLED' : 'DISABLED'}`,
    ...(tls.enabled ? [
      `[${tls.expired ? '!' : '+'}] Expired: ${tls.expired ? 'YES' : 'NO'}`,
      `[${tls.hostname_matches ? '+' : '!'}] Hostname Match: ${tls.hostname_matches ? 'YES' : 'NO'}`,
    ] : []),
    ``,
    `[SECURITY HEADERS]`,
    ...Object.entries(hdr).map(([name, info]) =>
      `[${info.present ? '+' : '!'}] ${name}: ${info.present ? 'PRESENT' : 'MISSING'}`),
    ``,
    `[RISK]`,
    `[${risk.score > 40 ? '!' : '+'}] Score: ${risk.score || 0}/100 (${risk.level || '?'})`,
    ...(risk.indicators || []).map(i => `[!] ${i}`),
    ``,
    `[+] Completed: ${recon.timestamp || new Date().toISOString()}`,
  ];
  return lines.join('\n');
}

// ============================================================================
// QR Code Scanner
// ============================================================================
function toggleQRScanner() {
  qrReaderContainer.classList.contains('hidden') ? openQRScanner() : closeQRScanner();
}

function openQRScanner() {
  qrReaderContainer.classList.remove('hidden');
  if (!qrScanner && typeof Html5Qrcode !== 'undefined') {
    qrScanner = new Html5Qrcode('qr-reader');
    qrScanner.start(
      { facingMode: 'environment' },
      { fps: 10, qrbox: { width: 250, height: 250 } },
      text => { urlInput.value = text; closeQRScanner(); setTimeout(() => form.dispatchEvent(new Event('submit')), 300); },
      () => {}
    ).catch(err => { showError('QR Scanner Error', 'Could not access camera.'); closeQRScanner(); });
  }
}

function closeQRScanner() {
  qrReaderContainer.classList.add('hidden');
  if (qrScanner) {
    qrScanner.stop().then(() => { qrScanner.clear(); qrScanner = null; }).catch(() => {});
  }
}

// ============================================================================
// History
// ============================================================================
function loadHistoryFromStorage() {
  try { scanHistory = JSON.parse(localStorage.getItem('cybersafe_history') || '[]'); }
  catch { scanHistory = []; }
}
function saveHistoryToStorage() {
  try { localStorage.setItem('cybersafe_history', JSON.stringify(scanHistory)); } catch {}
}
function addToHistory(item) {
  scanHistory.unshift(item);
  if (scanHistory.length > 50) scanHistory = scanHistory.slice(0, 50);
  saveHistoryToStorage();
  renderHistory();
}
function renderHistory() {
  if (!scanHistory.length) {
    emptyHistory.classList.remove('hidden');
    historyList.querySelectorAll('.history-item').forEach(el => el.remove());
    return;
  }
  emptyHistory.classList.add('hidden');
  historyList.innerHTML = scanHistory.map((item, i) => `
    <div class="history-item" data-index="${i}">
      <span class="history-verdict ${escapeHTML(item.verdict)}">${escapeHTML(item.verdict)}</span>
      <span class="history-url" title="${escapeHTML(item.url)}">${escapeHTML(item.url)}</span>
      ${item.mode === 'recon' ? '<span class="history-mode-badge">RECON</span>' : ''}
    </div>`).join('');
  historyList.querySelectorAll('.history-item').forEach(el => {
    el.addEventListener('click', () => {
      const item = scanHistory[+el.getAttribute('data-index')];
      if (item) { urlInput.value = item.url; urlInput.focus(); }
    });
  });
}
function clearHistory() {
  scanHistory = []; saveHistoryToStorage(); renderHistory();
}

// ============================================================================
// UI State Helpers
// ============================================================================
function showLoading(msg) {
  if (loadingText) loadingText.textContent = msg || 'Analyzing...';
  loadingState.classList.remove('hidden');
  analyzeBtn.disabled = true;
}
function hideLoading() {
  loadingState.classList.add('hidden');
  analyzeBtn.disabled = false;
}
function showError(title, msg) {
  errorTitle.textContent   = title;
  errorMessage.textContent = msg;
  errorState.classList.remove('hidden');
}
function hideError()   { errorState.classList.add('hidden'); }
function hideResults() { resultsContainer.classList.add('hidden'); }
function showResults(mode) {
  resultsContainer.classList.remove('hidden');
  offlineResults.classList.toggle('hidden', mode !== 'offline');
  reconResults.classList.toggle('hidden',   mode !== 'recon');
}

// ============================================================================
// Utilities
// ============================================================================
function escapeHTML(str) {
  if (str == null) return '';
  return String(str).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
