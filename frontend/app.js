/**
 * CyberSafe — Frontend Application Logic v2.0
 * Modes: Offline Analysis + Safe Recon
 * CYBERSAFE 2.0: Explainable findings, visual risk score, attack lab, enhanced UX
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

  // Safe Recon button (separate from form submission)
  const reconBtn = document.getElementById('recon-btn');
  if (reconBtn) {
    reconBtn.addEventListener('click', () => {
      setMode('recon');
      const url = urlInput.value.trim();
      if (!url) return;
      hideError();
      hideResults();
      showLoading('Performing safe reconnaissance...');
      handleRecon(url).finally(() => hideLoading());
    });
  }

  // Demo buttons — Phase 9: Attack Lab — auto-analyze on click
  document.querySelectorAll('.demo-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const url = btn.getAttribute('data-url');
      urlInput.value = url;
      urlInput.focus();
      // Auto-trigger analysis for attack lab demo buttons
      if (btn.closest('.attack-lab-demos')) {
        setMode('offline');
        hideError();
        hideResults();
        showLoading('Analyzing URL structure...');
        handleAnalyze(url).catch(err => showError('Analysis Failed', err.message)).finally(() => hideLoading());
      }
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

  // Export report button
  const exportBtn = document.getElementById('export-report-btn');
  if (exportBtn) {
    exportBtn.addEventListener('click', exportReport);
  }

  // History search
  const historySearch = document.getElementById('history-search');
  if (historySearch) {
    historySearch.addEventListener('input', () => renderHistory(historySearch.value.trim()));
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
    const span = analyzeBtn.querySelector('span');
    if (span) span.textContent = 'Analyze Offline';
  } else {
    modeDescText.textContent = 'Safe Recon — retrieves limited public technical metadata. Uses a real network request.';
    const span = analyzeBtn.querySelector('span');
    if (span) span.textContent = 'Run Recon';
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
  // Phase 3: Fix loading text
  showLoading(currentMode === 'recon'
    ? 'Performing safe reconnaissance...'
    : 'Analyzing URL structure...');

  try {
    if (currentMode === 'recon') {
      await handleRecon(url);
    } else {
      await handleAnalyze(url);
    }
  } catch (err) {
    showError('Request Failed', getReadableError(err));
  } finally {
    hideLoading();
  }
}

// Phase 16: Readable error messages
function getReadableError(err) {
  const msg = err.message || '';
  if (msg.includes('Failed to fetch') || msg.includes('NetworkError')) {
    return 'Could not reach the analysis server. The backend may be starting up (free tier). Please wait 30 seconds and try again.';
  }
  if (msg.includes('timeout')) {
    return 'The request timed out. Please try again.';
  }
  if (msg.includes('rate limit') || msg.includes('429')) {
    return 'Too many requests. Please wait a moment before analyzing again.';
  }
  return msg || 'An unexpected error occurred. Please try again.';
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

  addToHistory({
    url,
    verdict: data.analysis.verdict,
    score: data.analysis.score,
    findingCount: (data.analysis.findings || []).length,
    timestamp: Date.now(),
    mode: 'offline',
  });
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

  addToHistory({
    url,
    verdict: risk.level || 'UNKNOWN',
    score: risk.score || 0,
    findingCount: (risk.indicators || []).length,
    timestamp: Date.now(),
    mode: 'recon',
  });
  renderReconResults(recon);
  showResults('recon');
}

// ============================================================================
// Render — Offline Analysis
// ============================================================================

// Phase 5: Score contribution weights by severity
const SEVERITY_SCORE = { critical: 40, high: 25, medium: 15, low: 8, info: 2 };

function renderAnalysisResults(analysis) {
  const v = analysis.verdict;
  verdictBanner.className = `verdict-banner ${v}`;
  verdictTitle.textContent = v;
  verdictRecommendation.textContent = analysis.recommendation || '';
  scoreText.textContent   = `${analysis.score}/100`;
  confidenceText.textContent = (analysis.confidence || '').toUpperCase();

  const iconMap = { SAFE: 'shield-check', REVIEW: 'alert-circle', SUSPICIOUS: 'shield-alert' };
  verdictIcon.innerHTML = `<i data-lucide="${iconMap[v] || 'shield'}"></i>`;

  renderAnatomy(analysis);
  renderFindings(analysis.findings || [], analysis.score);
  renderRiskScoreBar(analysis.score, analysis.findings || []);

  // Phase 12: store last analysis for export
  window._lastAnalysis = analysis;

  // Show export button
  const exportBtn = document.getElementById('export-report-btn');
  if (exportBtn) exportBtn.classList.remove('hidden');

  if (typeof lucide !== 'undefined') lucide.createIcons();
}

// Phase 4: Interactive URL Anatomy with visual highlights
function renderAnatomy(analysis) {
  const p = analysis.parsed || {};

  // Visual URL decomposition bar
  const anatomyVisual = document.getElementById('anatomy-visual');
  if (anatomyVisual) {
    anatomyVisual.innerHTML = buildURLVisual(analysis);
  }

  const items = [
    { label: 'Actual Hostname', value: analysis.actual_hostname || p.hostname || 'None', flag: p.has_userinfo ? 'warn' : '' },
    { label: 'Scheme',          value: p.scheme || 'None', flag: p.scheme && !['https','http'].includes(p.scheme) ? 'warn' : '' },
    { label: 'Userinfo (@)',    value: p.has_userinfo ? '⚠ Yes — Deceptive Pattern' : 'No', flag: p.has_userinfo ? 'warn' : '' },
    { label: 'Port',            value: p.port || 'Default', flag: '' },
    { label: 'Path',            value: p.path || '/', flag: '' },
    { label: 'Query',           value: p.query || 'None', flag: '' },
    { label: 'Fragment',        value: p.fragment || 'None', flag: '' },
    { label: 'Punycode',        value: p.is_punycode ? `⚠ Yes — ${p.unicode_hostname || 'IDN'}` : 'No', flag: p.is_punycode ? 'warn' : '' },
    { label: 'URL Length',      value: `${(p.original_url || '').length} chars`, flag: (p.original_url || '').length > 100 ? 'warn' : '' },
  ];
  anatomyGrid.innerHTML = items.map(i => `
    <div class="anatomy-item${i.flag ? ' anatomy-item--' + i.flag : ''}">
      <div class="anatomy-label">${escapeHTML(i.label)}</div>
      <div class="anatomy-value">${escapeHTML(String(i.value))}</div>
    </div>`).join('');
}

// Phase 4: Build visual URL breakdown
function buildURLVisual(analysis) {
  const p = analysis.parsed || {};
  const url = p.original_url || '';
  if (!url) return '';

  const parts = [];

  if (p.scheme) {
    parts.push({ text: p.scheme + '://', cls: ['https','http'].includes(p.scheme) ? 'url-part--scheme-safe' : 'url-part--scheme-danger', label: 'Scheme' });
  }
  if (p.has_userinfo) {
    const atIdx = url.indexOf('@');
    const afterScheme = url.indexOf('//') + 2;
    if (atIdx > afterScheme) {
      parts.push({ text: url.slice(afterScheme, atIdx + 1), cls: 'url-part--danger', label: '⚠ Deceptive @' });
    }
  }
  if (p.hostname) {
    parts.push({ text: p.hostname, cls: p.is_punycode ? 'url-part--warn' : 'url-part--hostname', label: p.is_punycode ? '⚠ Punycode' : 'Hostname' });
  }
  if (p.port) {
    parts.push({ text: ':' + p.port, cls: 'url-part--port', label: 'Port' });
  }
  if (p.path && p.path !== '/') {
    parts.push({ text: p.path, cls: 'url-part--path', label: 'Path' });
  }
  if (p.query) {
    parts.push({ text: '?' + p.query, cls: 'url-part--query', label: 'Query' });
  }
  if (p.fragment) {
    parts.push({ text: '#' + p.fragment, cls: 'url-part--fragment', label: 'Fragment' });
  }

  if (!parts.length) {
    return `<div class="url-visual-raw font-mono">${escapeHTML(url)}</div>`;
  }

  return `<div class="url-visual">
    ${parts.map(pt => `<span class="url-part ${escapeHTML(pt.cls)}" data-label="${escapeHTML(pt.label)}">${escapeHTML(pt.text)}</span>`).join('')}
  </div>`;
}

// Phase 5: Visual risk score bar with per-finding breakdown
function renderRiskScoreBar(score, findings) {
  const container = document.getElementById('risk-score-breakdown');
  if (!container) return;

  const pct = Math.min(100, score);
  const colorClass = score >= 50 ? 'bar--suspicious' : score >= 20 ? 'bar--review' : 'bar--safe';

  // Per-finding score contributions
  const contributions = findings.map(f => {
    const contrib = SEVERITY_SCORE[f.severity] || 5;
    return { title: f.title, severity: f.severity, contrib };
  });

  container.innerHTML = `
    <div class="risk-score-header">
      <span class="risk-score-label">Risk Score</span>
      <span class="risk-score-value font-mono">${score}/100</span>
    </div>
    <div class="risk-bar-track">
      <div class="risk-bar-fill ${colorClass}" style="width:${pct}%"></div>
    </div>
    ${contributions.length ? `
    <div class="risk-contributions">
      <div class="risk-contrib-title">Score contributors:</div>
      ${contributions.map(c => `
        <div class="risk-contrib-row">
          <span class="risk-contrib-name">${escapeHTML(c.title)}</span>
          <span class="risk-contrib-badge severity-badge ${escapeHTML(c.severity)}">${escapeHTML(c.severity)}</span>
          <span class="risk-contrib-pts font-mono">+${c.contrib}</span>
        </div>`).join('')}
    </div>` : ''}`;
}

// Phase 6: Explainable findings with WHAT/WHY/ACTION
const FINDING_EXPLANATIONS = {
  // Lookalike / brand impersonation
  'brand_impersonation': {
    what: 'The hostname closely resembles a trusted brand but is a different domain.',
    why: 'Attackers register look-alike domains (e.g., paypa1.com, google-secure.net) to steal credentials.',
    action: 'Do not enter credentials. Navigate directly to the official site by typing it yourself.',
  },
  // Deceptive @
  'userinfo_deception': {
    what: 'A "@" symbol appears in the URL before the actual hostname.',
    why: 'Everything before "@" is treated as credentials by browsers. The real destination is after "@".',
    action: 'The visual hostname is fake. The actual destination follows the "@" symbol.',
  },
  // IP address as host
  'ip_address_host': {
    what: 'The URL uses a raw IP address instead of a domain name.',
    why: 'Legitimate services rarely use bare IPs. This can mask the true identity of the server.',
    action: 'Exercise caution. Verify you trust this IP address before proceeding.',
  },
  // URL shortener
  'url_shortener': {
    what: 'This URL uses a known link-shortening service that hides the real destination.',
    why: 'Shortened URLs are commonly used in phishing to conceal malicious destinations.',
    action: 'Expand the link first using a URL expander tool, or avoid clicking if the source is untrusted.',
  },
  // Dangerous scheme
  'dangerous_scheme': {
    what: 'The URL uses a non-standard scheme (e.g., javascript:, data:, vbscript:).',
    why: 'These schemes can execute code directly in the browser when clicked.',
    action: 'Never click or paste this URL into a browser address bar.',
  },
  // Punycode
  'punycode_hostname': {
    what: 'The hostname contains internationalized characters encoded as punycode (xn--).',
    why: 'Homograph attacks use characters from other alphabets that look identical to Latin letters.',
    action: 'Verify the actual Unicode characters in the hostname match the expected site.',
  },
  // Suspicious patterns
  'suspicious_path': {
    what: 'The URL path contains patterns commonly associated with phishing pages.',
    why: 'Paths like /login, /verify, /secure are frequently used in credential-harvesting pages.',
    action: 'Verify the domain is legitimate before entering any information.',
  },
};

function getFindingExplanation(finding) {
  // Match by rule_id or by key words in the title
  if (finding.rule_id && FINDING_EXPLANATIONS[finding.rule_id]) {
    return FINDING_EXPLANATIONS[finding.rule_id];
  }
  const titleLower = (finding.title || '').toLowerCase();
  for (const [key, exp] of Object.entries(FINDING_EXPLANATIONS)) {
    if (titleLower.includes(key.replace(/_/g, ' ').split(' ')[0])) {
      return exp;
    }
  }
  return null;
}

function renderFindings(findings, totalScore) {
  findingsCount.textContent = `${findings.length} triggered`;
  if (findings.length === 0) {
    findingsList.innerHTML = `<div class="clean-slate">
      <i data-lucide="shield-check" style="width:2rem;height:2rem;color:var(--safe-text);margin-bottom:0.5rem"></i>
      <p>No structural risks or deception indicators detected.</p>
      <p style="font-size:0.85rem;margin-top:0.5rem;color:var(--text-dim)">SAFE verdict means no <em>structural</em> red flags — it does not guarantee the destination is safe.</p>
    </div>`;
    if (typeof lucide !== 'undefined') lucide.createIcons();
    return;
  }
  findingsList.innerHTML = findings.map((f, idx) => {
    const exp = getFindingExplanation(f);
    const expandId = `finding-expand-${idx}`;
    return `
    <div class="finding-card">
      <div class="finding-header">
        <span class="finding-title">${escapeHTML(f.title)}</span>
        <span class="severity-badge ${escapeHTML(f.severity)}">${escapeHTML(f.severity)}</span>
      </div>
      <div class="finding-desc">${escapeHTML(f.message)}</div>
      ${f.evidence ? `<div class="finding-evidence">Evidence: ${escapeHTML(f.evidence)}</div>` : ''}
      ${exp ? `
      <button class="finding-expand-btn" aria-expanded="false" aria-controls="${expandId}" onclick="toggleFindingExpand(this, '${expandId}')">
        <i data-lucide="chevron-down"></i> Explain this finding
      </button>
      <div class="finding-explanation hidden" id="${expandId}">
        <div class="explain-section">
          <div class="explain-label">WHAT</div>
          <div class="explain-text">${escapeHTML(exp.what)}</div>
        </div>
        <div class="explain-section">
          <div class="explain-label">WHY</div>
          <div class="explain-text">${escapeHTML(exp.why)}</div>
        </div>
        <div class="explain-section">
          <div class="explain-label">ACTION</div>
          <div class="explain-text">${escapeHTML(exp.action)}</div>
        </div>
      </div>` : ''}
    </div>`;
  }).join('');
  if (typeof lucide !== 'undefined') lucide.createIcons();
}

// Phase 6: Toggle finding explanation
function toggleFindingExpand(btn, id) {
  const panel = document.getElementById(id);
  if (!panel) return;
  const expanded = btn.getAttribute('aria-expanded') === 'true';
  btn.setAttribute('aria-expanded', String(!expanded));
  panel.classList.toggle('hidden', expanded);
  btn.querySelector('span') && (btn.querySelector('span').textContent = expanded ? 'Explain this finding' : 'Hide explanation');
  const icon = btn.querySelector('svg, i[data-lucide]');
  if (icon) {
    icon.setAttribute('data-lucide', expanded ? 'chevron-down' : 'chevron-up');
    if (typeof lucide !== 'undefined') lucide.createIcons();
  }
}
// Expose for inline onclick
window.toggleFindingExpand = toggleFindingExpand;

// ============================================================================
// Render — Safe Recon
// ============================================================================
function renderReconResults(recon) {
  const risk    = recon.risk    || {};
  const http    = recon.http    || {};
  const tls     = recon.tls     || {};
  const target  = recon.target  || {};
  const headers = recon.headers || {};

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

  if (terminalOutput) {
    terminalOutput.textContent = buildTerminalOutput(recon);
  }

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
// Phase 12: Security Report Export
// ============================================================================
function exportReport() {
  const a = window._lastAnalysis;
  if (!a) return;

  const p = a.parsed || {};
  const lines = [
    '═══════════════════════════════════════════',
    '  CyberSafe — Security Analysis Report',
    '═══════════════════════════════════════════',
    `  Generated : ${new Date().toISOString()}`,
    `  URL       : ${p.original_url || ''}`,
    `  Verdict   : ${a.verdict}`,
    `  Risk Score: ${a.score}/100`,
    `  Confidence: ${(a.confidence || '').toUpperCase()}`,
    '───────────────────────────────────────────',
    '  RECOMMENDATION',
    `  ${a.recommendation || ''}`,
    '───────────────────────────────────────────',
    '  URL STRUCTURE',
    `  Hostname : ${a.actual_hostname || p.hostname || '—'}`,
    `  Scheme   : ${p.scheme || '—'}`,
    `  Path     : ${p.path || '/'}`,
    `  Userinfo : ${p.has_userinfo ? 'YES — Deceptive pattern detected' : 'None'}`,
    `  Punycode : ${p.is_punycode ? 'YES — ' + (p.unicode_hostname || 'IDN') : 'No'}`,
    '───────────────────────────────────────────',
    `  FINDINGS (${(a.findings || []).length} total)`,
  ];

  (a.findings || []).forEach((f, i) => {
    lines.push(`  ${i + 1}. [${f.severity.toUpperCase()}] ${f.title}`);
    lines.push(`     ${f.message}`);
    if (f.evidence) lines.push(`     Evidence: ${f.evidence}`);
  });

  lines.push('───────────────────────────────────────────');
  lines.push('  ANALYSIS MODE: Offline — no destination requests were made.');
  lines.push('  CyberSafe analyzes URL structure only. SAFE does not');
  lines.push('  guarantee the destination is safe.');
  lines.push('═══════════════════════════════════════════');

  const report = lines.join('\n');

  // Copy to clipboard
  const btn = document.getElementById('export-report-btn');
  navigator.clipboard.writeText(report).then(() => {
    if (btn) {
      const original = btn.textContent;
      btn.textContent = '✓ Copied!';
      setTimeout(() => { btn.textContent = original; }, 2000);
    }
  }).catch(() => {
    // Fallback: show in a pre element
    showReportFallback(report);
  });
}

function showReportFallback(report) {
  let modal = document.getElementById('report-modal');
  if (!modal) {
    modal = document.createElement('div');
    modal.id = 'report-modal';
    modal.className = 'report-modal';
    modal.innerHTML = `
      <div class="report-modal-content glass-card">
        <div class="card-header">
          <h3><i data-lucide="file-text"></i> Security Report</h3>
          <button class="btn-icon" onclick="document.getElementById('report-modal').classList.add('hidden')"><i data-lucide="x"></i></button>
        </div>
        <pre id="report-text" class="report-pre font-mono"></pre>
        <p class="report-hint">Select all (Ctrl+A) and copy manually.</p>
      </div>`;
    document.body.appendChild(modal);
    if (typeof lucide !== 'undefined') lucide.createIcons();
  }
  document.getElementById('report-text').textContent = report;
  modal.classList.remove('hidden');
}

// ============================================================================
// Phase 10: QR Code Scanner — content type detection
// ============================================================================
const WEB_SCHEMES = ['http:', 'https:'];
const DANGEROUS_SCHEMES = ['javascript:', 'data:', 'vbscript:', 'blob:'];

function detectQRPayloadType(text) {
  try {
    const url = new URL(text);
    if (DANGEROUS_SCHEMES.includes(url.protocol)) return 'dangerous';
    if (WEB_SCHEMES.includes(url.protocol)) return 'web';
    return 'app-link'; // tel:, mailto:, sms:, etc.
  } catch {
    // Not a URL
    if (/^https?:\/\//i.test(text)) return 'web';
    if (/^[A-Za-z][A-Za-z0-9+\-.]*:/.test(text)) return 'app-link';
    return 'text';
  }
}

function handleQRResult(text) {
  closeQRScanner();
  const type = detectQRPayloadType(text);
  urlInput.value = text;

  if (type === 'dangerous') {
    showQRWarning('⚠ DANGEROUS PAYLOAD', `Detected scheme: ${text.split(':')[0]}:`, 'This payload can execute code in your browser. Do NOT click or paste it into a browser address bar. CyberSafe has loaded it for analysis only.', 'dangerous');
    return;
  }
  if (type === 'text') {
    showQRWarning('📄 NON-URL PAYLOAD', 'Plain text detected', 'This QR code contains plain text, not a URL. It has been loaded into the analyzer for inspection.', 'info');
    return;
  }
  if (type === 'app-link') {
    showQRWarning('⚠ NON-WEB PAYLOAD', `Detected scheme: ${text.split(':')[0]}:`, 'This QR code uses a non-web scheme. Review carefully before following any link.', 'warn');
    return;
  }

  // Web URL — auto-analyze
  setTimeout(() => {
    setMode('offline');
    hideError();
    hideResults();
    showLoading('Analyzing URL structure...');
    handleAnalyze(text).catch(err => showError('Analysis Failed', err.message)).finally(() => hideLoading());
  }, 300);
}

function showQRWarning(title, subtitle, message, level) {
  const existing = document.getElementById('qr-payload-warning');
  if (existing) existing.remove();

  const el = document.createElement('div');
  el.id = 'qr-payload-warning';
  el.className = `qr-payload-warning qr-warning--${level}`;
  el.innerHTML = `
    <div class="qr-warning-header">
      <span class="qr-warning-title">${escapeHTML(title)}</span>
      <button class="btn-icon" onclick="document.getElementById('qr-payload-warning').remove()"><i data-lucide="x"></i></button>
    </div>
    <div class="qr-warning-subtitle font-mono">${escapeHTML(subtitle)}</div>
    <div class="qr-warning-message">${escapeHTML(message)}</div>
    ${level !== 'info' ? `<button class="btn btn-primary" style="margin-top:0.75rem;width:100%" onclick="document.getElementById('qr-payload-warning').remove(); document.getElementById('analyze-form').dispatchEvent(new Event('submit'))">Analyze Anyway</button>` : ''}
  `;

  const inputCard = document.querySelector('.input-card');
  if (inputCard) inputCard.insertAdjacentElement('afterend', el);
  else form.insertAdjacentElement('afterend', el);
  if (typeof lucide !== 'undefined') lucide.createIcons();
}

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
      text => handleQRResult(text),
      () => {}
    ).catch(() => { showError('QR Scanner Error', 'Could not access camera. Please check permissions.'); closeQRScanner(); });
  }
}

function closeQRScanner() {
  qrReaderContainer.classList.add('hidden');
  if (qrScanner) {
    qrScanner.stop().then(() => { qrScanner.clear(); qrScanner = null; }).catch(() => {});
  }
}

// ============================================================================
// History — Phase 11: timestamp, score, finding count, search
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

function formatTimestamp(ts) {
  if (!ts) return '';
  try {
    const d = new Date(ts);
    const now = new Date();
    const diffMs = now - d;
    const diffMin = Math.floor(diffMs / 60000);
    if (diffMin < 1) return 'just now';
    if (diffMin < 60) return `${diffMin}m ago`;
    const diffHr = Math.floor(diffMin / 60);
    if (diffHr < 24) return `${diffHr}h ago`;
    return d.toLocaleDateString();
  } catch { return ''; }
}

function renderHistory(filter) {
  const items = filter
    ? scanHistory.filter(i => i.url && i.url.toLowerCase().includes(filter.toLowerCase()))
    : scanHistory;

  if (!items.length) {
    emptyHistory.classList.remove('hidden');
    historyList.querySelectorAll('.history-item').forEach(el => el.remove());
    return;
  }
  emptyHistory.classList.add('hidden');
  const existingItems = historyList.querySelectorAll('.history-item');
  existingItems.forEach(el => el.remove());

  const fragment = document.createDocumentFragment();
  items.forEach((item, i) => {
    const el = document.createElement('div');
    el.className = 'history-item';
    el.setAttribute('data-index', String(i));
    el.setAttribute('title', item.url || '');
    el.innerHTML = `
      <div class="history-item-top">
        <span class="history-verdict ${escapeHTML(item.verdict)}">${escapeHTML(item.verdict)}</span>
        <span class="history-meta font-mono">
          ${item.score != null ? `<span class="history-score">${item.score}</span>` : ''}
          ${item.findingCount != null ? `<span class="history-findings">${item.findingCount} ${item.findingCount === 1 ? 'finding' : 'findings'}</span>` : ''}
          ${item.mode === 'recon' ? '<span class="history-mode-badge">RECON</span>' : ''}
        </span>
      </div>
      <div class="history-item-bottom">
        <span class="history-url">${escapeHTML(item.url || '')}</span>
        <span class="history-time">${escapeHTML(formatTimestamp(item.timestamp))}</span>
      </div>`;
    el.addEventListener('click', () => {
      const orig = scanHistory[i];
      if (orig) { urlInput.value = orig.url; urlInput.focus(); }
    });
    fragment.appendChild(el);
  });
  historyList.appendChild(fragment);
}

function clearHistory() {
  scanHistory = []; saveHistoryToStorage(); renderHistory();
}

// ============================================================================
// UI State Helpers
// ============================================================================
function showLoading(msg) {
  if (loadingText) loadingText.textContent = msg || 'Analyzing URL structure...';
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
