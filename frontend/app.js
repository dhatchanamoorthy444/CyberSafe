/**
 * CyberSafe — Frontend Application Logic v2.0
 * Modes: Offline Analysis
 * CYBERSAFE 2.0: Phishing Gallery, Threat Feed, URL Compare, IOC
 */

// ============================================================================
// Configuration
// ============================================================================
const BASE_URL = (typeof import.meta !== 'undefined' && import.meta.env && import.meta.env.VITE_API_URL)
  ? import.meta.env.VITE_API_URL.replace(/\/$/, '')
  : '';

const API = {
  analyze: BASE_URL ? `${BASE_URL}/api/analyze` : '/api/analyze',
};

// ============================================================================
// DOM References
// ============================================================================
const form = document.getElementById('analyze-form');
const urlInput = document.getElementById('url-input');
const analyzeBtn = document.getElementById('analyze-btn');
const qrToggleBtn = document.getElementById('qr-toggle-btn');
const qrReaderContainer = document.getElementById('qr-reader-container');
const qrCloseBtn = document.getElementById('qr-close-btn');

const loadingState = document.getElementById('loading-state');
const loadingText = document.getElementById('loading-text');
const errorState = document.getElementById('error-state');
const errorTitle = document.getElementById('error-title');
const errorMessage = document.getElementById('error-message');
const resultsContainer = document.getElementById('results-container');

// Offline analysis elements
const offlineResults = document.getElementById('offline-results');
const verdictBanner = document.getElementById('verdict-banner');
const verdictIcon = document.getElementById('verdict-icon');
const verdictTitle = document.getElementById('verdict-title');
const verdictRecommendation = document.getElementById('verdict-recommendation');
const scoreText = document.getElementById('score-text');
const confidenceText = document.getElementById('confidence-text');
const anatomyGrid = document.getElementById('anatomy-grid');
const findingsList = document.getElementById('findings-list');
const findingsCount = document.getElementById('findings-count');
const anatomyVisual = document.getElementById('anatomy-visual');

// History
const historyList = document.getElementById('history-list');
const emptyHistory = document.getElementById('empty-history');
const clearHistoryBtn = document.getElementById('clear-history-btn');

// ============================================================================
// State
// ============================================================================
let qrScanner   = null;
let scanHistory = [];


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


  // Phishing Gallery
  initPhishingGallery();

  // Threat Feed
  initThreatFeed();

  // URL Comparison
  initURLComparison();

  // IOC Extraction
  initIOC();

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
// Simplified Analysis Render
// ============================================================================
function renderSimplifiedAnalysis(analysis) {
  const v = analysis.verdict;
  verdictBanner.className = `verdict-banner ${v}`;
  verdictTitle.textContent = v;
  verdictRecommendation.textContent = analysis.recommendation || '';
  // Risk score: 0-100 where higher means MORE dangerous (consistent labeling)
  scoreText.textContent = `${Math.max(0, Math.min(100, analysis.score || 0))}`;
  confidenceText.textContent = (analysis.confidence || '').toUpperCase();

  const iconMap = { SAFE: 'shield-check', REVIEW: 'alert-circle', SUSPICIOUS: 'shield-alert' };
  verdictIcon.innerHTML = `<i data-lucide="${iconMap[v] || 'shield'}"></i>`;

  renderAnatomy(analysis);
  renderFindings(analysis.findings || [], analysis.score);
  renderRiskReportCard(analysis);
  renderNetworkTransparency();
  renderTechnicalDetails(analysis);

  // Store last analysis for export and IOC
  window._lastAnalysis = analysis;

  if (typeof lucide !== 'undefined') lucide.createIcons();
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

  try {
    await handleAnalyze(url);
  } catch (err) {
    showError('Request Failed', getReadableError(err));
    hideLoading();
  }
}

// ============================================================================
// Simplified Analysis Render
// ============================================================================
function renderSimplifiedAnalysis(analysis) {
  const v = analysis.verdict;
  verdictBanner.className = `verdict-banner ${v}`;
  verdictTitle.textContent = v;
  verdictRecommendation.textContent = analysis.recommendation || '';
  // Risk score: 0-100 where higher means MORE dangerous (consistent labeling)
  scoreText.textContent = `${Math.max(0, Math.min(100, analysis.score || 0))}`;
  confidenceText.textContent = (analysis.confidence || '').toUpperCase();

  const iconMap = { SAFE: 'shield-check', REVIEW: 'alert-circle', SUSPICIOUS: 'shield-alert' };
  verdictIcon.innerHTML = `<i data-lucide="${iconMap[v] || 'shield'}"></i>`;

  renderAnatomy(analysis);
  renderFindings(analysis.findings || [], analysis.score);
  renderRiskReportCard(analysis);
  renderNetworkTransparency();
  renderTechnicalDetails(analysis);

  // Store last analysis for export and IOC
  window._lastAnalysis = analysis;

  if (typeof lucide !== 'undefined') lucide.createIcons();
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

// Stage updater helper
function updateStage(number) {
  for (let i = 1; i <= 7; i++) {
    const el = document.getElementById(`stage-${i}`);
    if (!el) continue;
    if (i < number) {
      el.innerHTML = `<i data-lucide="check-circle-2" style="color:var(--safe-text)"></i> ${el.innerText.trim()}`;
      el.style.opacity = '1';
    } else if (i === number) {
      el.innerHTML = `<i data-lucide="loader" class="rotating" style="color:var(--primary-light)"></i> ${el.innerText.trim()}`;
      el.style.opacity = '1';
    } else {
      el.innerHTML = `<i data-lucide="circle"></i> ${el.innerText.trim()}`;
      el.style.opacity = '0.5';
    }
  }
  if (typeof lucide !== 'undefined') lucide.createIcons();
}

// ============================================================================
// Offline Analysis
// ============================================================================
async function handleAnalyze(url) {
  showLoading('Initializing Security Pipeline...');

  // Fake animation of stages for UI feedback since backend does it in one call
  let currentStage = 1;
  const stageInterval = setInterval(() => {
    if (currentStage <= 6) {
      updateStage(currentStage);
      currentStage++;
    }
  }, 400);

  let response, data;
  try {
    response = await fetch(API.analyze, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });

    data = await response.json();
  } finally {
    clearInterval(stageInterval);
  }

  updateStage(7);

  if (!response.ok || !data.success) {
    throw new Error(data.error?.message || 'Analysis failed. Please try again.');
  }

  // Store vendor and AI data for the risk report card before rendering
  window._lastVendorData = data.vendors || {};
  window._lastAIAnalysis = data.ai || {};

  setTimeout(() => {
    hideLoading();

    addToHistory({
      url,
      verdict: data.analysis.verdict,
      score: data.analysis.score,
      findingCount: (data.analysis.findings || []).length,
      timestamp: Date.now(),
      mode: 'offline',
    });

    // Store vendor and AI data for the risk report card before rendering
    window._lastVendorData = data.vendors || {};
    window._lastAIAnalysis = data.ai || {};

    renderSimplifiedAnalysis(data.analysis);
    if (data.ai) renderAIExplanation(data.ai);
    showResults();
    renderIOC(data.analysis);
    if (data.vendors) renderVendorAnalysis(data.vendors);
  }, 500);
}

function renderAIExplanation(ai) {
  const panel = document.getElementById('ai-explanation-panel');
  if (!panel) return;
  panel.classList.remove('hidden');

  // Update the overview section (already has static content, but we can enhance it)
  const overviewSection = panel.querySelector('.analysis-section h4');
  if (overviewSection && overviewSection.textContent === 'Overview') {
    const overviewP = overviewSection.nextElementSibling;
    if (overviewP && ai.explanation) {
      overviewP.textContent = ai.explanation;
    }
  }

  // Populate Key Findings list
  const findingsList = document.getElementById('ai-findings-list');
  if (findingsList && ai.key_findings && Array.isArray(ai.key_findings)) {
    if (ai.key_findings.length === 0) {
      findingsList.innerHTML = '<li>No structural risk indicators detected in URL analysis.</li>';
    } else {
      findingsList.innerHTML = ai.key_findings.map(finding =>
        `<li>${escapeHTML(finding)}</li>`
      ).join('');
    }
  }

  // Populate Risk Indicators
  const riskIndicators = document.getElementById('ai-risk-indicators');
  if (riskIndicators && ai.risk_indicators) {
    if (Array.isArray(ai.risk_indicators) && ai.risk_indicators.length > 0) {
      riskIndicators.innerHTML = ai.risk_indicators.map(indicator =>
        `<p>${escapeHTML(indicator)}</p>`
      ).join('');
    } else if (typeof ai.risk_indicators === 'string') {
      riskIndicators.textContent = ai.risk_indicators;
    } else {
      riskIndicators.textContent = 'No specific risk indicators identified in the structural analysis.';
    }
  }

  // Populate Recommendations
  const recommendations = document.getElementById('ai-recommendations');
  if (recommendations && ai.recommendations) {
    recommendations.textContent = ai.recommendations;
  }

  // Update Limitations
  const limitations = document.getElementById('ai-limitations');
  if (limitations && ai.limitations) {
    limitations.textContent = ai.limitations;
  }

  // Update the legacy content div for backward compatibility
  const content = document.getElementById('ai-explanation-content');
  if (content) {
    let html = `<div style="margin-top:1rem;padding-top:1rem;border-top:1px solid var(--border-subtle)">`;

    if (ai.verdict_label) {
      html += `<p><strong>Risk Level:</strong> ${escapeHTML(ai.verdict_label)}</p>`;
    }

    if (ai.risk_summary && ai.risk_summary !== 'N/A' && ai.risk_summary !== 'Analysis failed.') {
      html += `<p><strong>Summary:</strong> ${escapeHTML(ai.risk_summary)}</p>`;
    }

    html += `</div>`;
    content.innerHTML = html;
  }
}

// ============================================================================
// Render — Offline Analysis
// ============================================================================
function renderAnalysisResults(analysis) {
  const v = analysis.verdict;
  verdictBanner.className = `verdict-banner ${v}`;
  verdictTitle.textContent = v;
  verdictRecommendation.textContent = analysis.recommendation || '';
  // Risk score: 0-100 where higher means MORE dangerous (consistent labeling)
  scoreText.textContent   = `${Math.max(0, Math.min(100, analysis.score || 0))}`;
  confidenceText.textContent = (analysis.confidence || '').toUpperCase();

  const iconMap = { SAFE: 'shield-check', REVIEW: 'alert-circle', SUSPICIOUS: 'shield-alert' };
  verdictIcon.innerHTML = `<i data-lucide="${iconMap[v] || 'shield'}"></i>`;

  renderAnatomy(analysis);
  renderFindings(analysis.findings || [], analysis.score);
  renderRiskReportCard(analysis);
  renderNetworkTransparency();
  renderTechnicalDetails(analysis);

  // Store last analysis for export and IOC
  // (_lastVendorData and _lastAIAnalysis are set by the caller before renderAnalysisResults)
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

// ============================================================================
// Risk Report Card — Clear, consistent risk scoring
// ============================================================================

/**
 * Maps severity to a visual color class for the risk bar.
 */
function getRiskColorClass(score) {
  if (score >= 75) return 'bar--critical';
  if (score >= 50) return 'bar--high';
  if (score >= 25) return 'bar--moderate';
  return 'bar--low';
}

/**
 * Maps score to a human-readable risk level label.
 */
function getRiskLevelLabel(score) {
  if (score >= 75) return 'Critical Risk';
  if (score >= 50) return 'High Risk';
  if (score >= 25) return 'Moderate Risk';
  if (score > 0) return 'Low Risk';
  return 'No Risk Detected';
}

/**
 * Returns an emoji icon appropriate for the risk level.
 */
function getRiskEmoji(score) {
  if (score >= 75) return '🚨';
  if (score >= 50) return '⚠️';
  if (score >= 25) return '⚡';
  if (score > 0) return 'ℹ️';
  return '✅';
}

/**
 * Main render function for the Risk Report Card.
 * Displays a single, consistent risk score (0-100) where higher = more dangerous.
 */
function renderRiskReportCard(analysis) {
  const container = document.getElementById('risk-score-breakdown');
  if (!container) return;

  const score = Math.max(0, Math.min(100, analysis.score || 0));
  const findings = analysis.findings || [];
  const verdict = analysis.verdict || 'UNKNOWN';
  const parsed = analysis.parsed || {};

  const colorClass = getRiskColorClass(score);
  const riskLabel = getRiskLevelLabel(score);
  const riskEmoji = getRiskEmoji(score);

  // Determine if VirusTotal data is available
  const vendorData = window._lastVendorData || {};
  const vtResult = vendorData.results?.find(r => r.vendor === 'VirusTotal');
  const hasVT = vtResult && vtResult.status !== 'not_checked' && vtResult.status !== 'error';

  // Determine if AI analysis is available
  const aiData = window._lastAIAnalysis || {};
  const hasAI = aiData && aiData.explanation && !aiData.explanation.includes('unavailable');

  container.innerHTML = `
    <div class="risk-report-card" role="region" aria-label="Risk Report">
      <!-- Verdict Header -->
      <div class="risk-report-header">
        <div class="risk-report-verdict">
          <span class="risk-emoji" aria-hidden="true">${riskEmoji}</span>
          <span class="risk-level-label">${riskLabel}</span>
        </div>
        <div class="risk-score-display">
          <span class="risk-number font-mono">${score}</span>
          <span class="risk-max">/100</span>
        </div>
      </div>

      <!-- Visual Risk Scale -->
      <div class="risk-scale-container" role="img" aria-label="Risk scale showing ${score} out of 100">
        <div class="risk-scale-labels">
          <span class="scale-label">Low</span>
          <span class="scale-label">Moderate</span>
          <span class="scale-label">High</span>
          <span class="scale-label">Critical</span>
        </div>
        <div class="risk-bar-track">
          <div class="risk-bar-fill ${colorClass}" style="width:${score}%"></div>
          <div class="risk-marker" style="left:${score}%"></div>
        </div>
      </div>

      <!-- Summary Explanation -->
      <div class="risk-summary">
        ${getRiskSummaryText(verdict, findings, score)}
      </div>

      <!-- Evidence Breakdown -->
      ${findings.length > 0 ? `
      <div class="risk-breakdown-section">
        <button class="risk-breakdown-toggle" aria-expanded="false" onclick="toggleRiskBreakdown(this)">
          <i data-lucide="chevron-down"></i>
          <span>Why this score? (${findings.length} indicator${findings.length !== 1 ? 's' : ''})</span>
        </button>
        <div class="risk-breakdown-content hidden">
          <div class="risk-contributions">
            ${findings.map(f => `
              <div class="risk-contrib-row">
                <div class="risk-contrib-main">
                  <span class="risk-contrib-name">${escapeHTML(f.title || f.rule_id)}</span>
                  <span class="severity-badge ${escapeHTML(f.severity)}">${escapeHTML(f.severity)}</span>
                </div>
                <span class="risk-contrib-pts font-mono">+${f.score}</span>
              </div>
              <div class="risk-contrib-message">${escapeHTML(f.message)}</div>
            `).join('')}
          </div>
        </div>
      </div>` : `
      <div class="risk-no-findings">
        <i data-lucide="check-circle-2" style="color:var(--safe-text)"></i>
        <span>No structural risk indicators detected in this URL.</span>
      </div>`}

      <!-- Data Sources Status -->
      <div class="risk-sources">
        <span class="source-badge source--offline ${hasVT ? '' : 'source--unavailable'}">
          <i data-lucide="activity"></i> Offline Analysis
        </span>
        <span class="source-badge source--vt ${hasVT ? (vtResult.status === 'malicious' || vtResult.status === 'suspicious' ? 'source--danger' : 'source--safe') : 'source--unavailable'}">
          <i data-lucide="shield"></i> VirusTotal ${hasVT ? vtResult.status : 'Unavailable'}
        </span>
        <span class="source-badge source--ai ${hasAI ? 'source--info' : 'source--unavailable'}">
          <i data-lucide="bot"></i> AI Analysis ${hasAI ? 'Ready' : 'Unavailable'}
        </span>
      </div>

      <!-- Limitations Note -->
      <div class="risk-limitations">
        <i data-lucide="info"></i>
        <span>This analysis checks URL <strong>structure only</strong>. Destination content and live behavior were not evaluated.</span>
      </div>
    </div>
  `;

  if (typeof lucide !== 'undefined') lucide.createIcons();
}

/**
 * Returns summary text based on verdict and findings.
 */
function getRiskSummaryText(verdict, findings, score) {
  if (findings.length === 0) {
    return `<p>No structural risk indicators were detected in this URL. The URL appears structurally clean based on offline analysis.</p>`;
  }

  const highSeverityCount = findings.filter(f => f.severity === 'high' || f.severity === 'critical').length;
  const mediumSeverityCount = findings.filter(f => f.severity === 'medium').length;

  if (score >= 50) {
    return `<p><strong>Multiple risk indicators detected.</strong> ${highSeverityCount} high-severity finding${highSeverityCount !== 1 ? 's' : ''} contribute to this elevated risk score. Exercise extreme caution before proceeding.</p>`;
  } else if (score >= 25) {
    return `<p><strong>Some concerns identified.</strong> ${mediumSeverityCount} medium-severity indicator${mediumSeverityCount !== 1 ? 's' : ''} were found. Review the breakdown below before visiting this URL.</p>`;
  } else {
    return `<p><strong>Minor structural issues detected.</strong> ${findings.length} low-severity indicator${findings.length !== 1 ? 's' : ''} were found. These are typically configuration concerns rather than security threats.</p>`;
  }
}

/**
 * Toggle the risk breakdown section.
 */
function toggleRiskBreakdown(btn) {
  const content = btn.nextElementSibling;
  const isExpanded = !content.classList.contains('hidden');
  content.classList.toggle('hidden');
  btn.setAttribute('aria-expanded', !isExpanded);
  const icon = btn.querySelector('[data-lucide]');
  if (icon) {
    icon.setAttribute('data-lucide', isExpanded ? 'chevron-down' : 'chevron-up');
    if (typeof lucide !== 'undefined') lucide.createIcons();
  }
}

// Toggle finding expand - made available globally
window.toggleFindingExpand = function(btn, expandId) {
  const content = document.getElementById(expandId);
  if (!content) return;
  const isExpanded = !content.classList.contains('hidden');
  content.classList.toggle('hidden');
  btn.setAttribute('aria-expanded', !isExpanded);
  const icon = btn.querySelector('[data-lucide]');
  if (icon) {
    icon.setAttribute('data-lucide', isExpanded ? 'chevron-down' : 'chevron-up');
    if (typeof lucide !== 'undefined') lucide.createIcons();
  }
};

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

function renderVendorAnalysis(vendors) {
  const card = document.getElementById('vendor-analysis-card');
  if (!card) return;
  const listEl = document.getElementById('vendor-list');
  const summaryEl = document.getElementById('vendor-summary');
  const label = document.getElementById('vendor-config-label');

  card.classList.remove('hidden');

  const results = vendors.results || [];
  const checked = results.filter(r => r.checked).length;
  const malicious = results.filter(r => r.status === 'malicious').length;
  const suspicious = results.filter(r => r.status === 'suspicious').length;
  const clean = results.filter(r => r.status === 'clean').length;
  const unrated = results.filter(r => r.status === 'unrated').length;
  const errors = results.filter(r => r.status === 'error').length;
  const total = results.length;

  if (summaryEl) {
    summaryEl.innerHTML = `<strong>Security vendors' analysis</strong><br>
      ${checked > 0 ? `<span style="color:var(--safe-text)">${checked} / ${total}</span> vendors flagged this URL` : `<span style="color:var(--text-dim)">No threat-intelligence providers configured.</span>`}<br>
      <span style="font-size:0.82rem;opacity:0.8">${checked} checked • ${malicious} malicious • ${suspicious} suspicious • ${clean} clean • ${unrated} unrated • ${errors} errors • ${new Date(vendors.scan_timestamp || Date.now()).toLocaleString()}</span>`;
  }
  if (label) label.textContent = checked === 0 ? 'No providers configured' : `${checked}/${total} checked`;

  if (!listEl) return;
  const rows = results.map(r => {
    const statusClass = r.status || 'not_checked';
    return `<tr data-vendor="${escapeHTML(r.vendor)}" data-status="${escapeHTML(statusClass)}">
      <td>${escapeHTML(r.vendor)}</td>
      <td><span class="status-badge-vendor ${escapeHTML(statusClass)}">${escapeHTML((r.status || 'not checked').replace(/_/g,' '))}</span></td>
      <td>${escapeHTML(r.details || '')}</td>
    </tr>`;
  }).join('');
  listEl.innerHTML = `<table class="vendor-table" role="table" aria-label="Security vendors analysis">
    <thead><tr><th>Vendor</th><th>Result</th><th>Details</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>`;

  if (checked === 0) {
    listEl.insertAdjacentHTML('beforeend', `<div style="padding:1.5rem;color:var(--text-dim);text-align:center;font-size:0.9rem;">Vendor results are unavailable because no threat-intelligence providers are configured. The local CyberSafe analysis is shown separately.</div>`);
  }

  const searchInput = document.getElementById('vendor-search');
  const filterBtns = document.querySelectorAll('.vendor-filters .filter-btn');
  function applyFilters() {
    const text = (searchInput ? searchInput.value : '').toLowerCase();
    let status = 'ALL';
    filterBtns.forEach(b => { if (b.classList.contains('active')) status = (b.getAttribute('data-vendor-filter') || 'ALL'); });
    const trs = listEl.querySelectorAll('tbody tr');
    trs.forEach(row => {
      const v = (row.getAttribute('data-vendor') || '').toLowerCase();
      const s = row.getAttribute('data-status') || '';
      row.style.display = ((!text || v.includes(text)) && (status === 'ALL' || s === status)) ? '' : 'none';
    });
  }
  if (searchInput) searchInput.addEventListener('input', applyFilters);
  filterBtns.forEach(btn => btn.addEventListener('click', () => {
    filterBtns.forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    applyFilters();
  }));
  applyFilters();
}
window.renderVendorAnalysis = renderVendorAnalysis;

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
    `  Risk Score: ${Math.max(0, Math.min(100, a.score || 0))}/100 (0=No risk, 100=Critical risk)`,
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
