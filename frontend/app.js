/**
 * CyberSafe — Frontend Application Logic
 * Handles URL analysis, QR scanning, demo modes, and history management
 */

// ============================================================================
// DOM Element References
// ============================================================================
const form = document.getElementById('analyze-form');
const urlInput = document.getElementById('url-input');
const analyzeBtn = document.getElementById('analyze-btn');
const qrToggleBtn = document.getElementById('qr-toggle-btn');
const qrReaderContainer = document.getElementById('qr-reader-container');
const qrCloseBtn = document.getElementById('qr-close-btn');

const loadingState = document.getElementById('loading-state');
const errorState = document.getElementById('error-state');
const errorTitle = document.getElementById('error-title');
const errorMessage = document.getElementById('error-message');
const resultsContainer = document.getElementById('results-container');

const verdictBanner = document.getElementById('verdict-banner');
const verdictIcon = document.getElementById('verdict-icon');
const verdictTitle = document.getElementById('verdict-title');
const verdictRecommendation = document.getElementById('verdict-recommendation');
const scoreText = document.getElementById('score-text');
const confidenceText = document.getElementById('confidence-text');

const anatomyGrid = document.getElementById('anatomy-grid');
const findingsList = document.getElementById('findings-list');
const findingsCount = document.getElementById('findings-count');

const historyList = document.getElementById('history-list');
const emptyHistory = document.getElementById('empty-history');
const clearHistoryBtn = document.getElementById('clear-history-btn');

// ============================================================================
// State Management
// ============================================================================
let qrScanner = null;
let scanHistory = [];

// ============================================================================
// Initialization
// ============================================================================
document.addEventListener('DOMContentLoaded', () => {
  // Initialize Lucide icons
  if (typeof lucide !== 'undefined') {
    lucide.createIcons();
  }

  // Load scan history from localStorage
  loadHistoryFromStorage();
  renderHistory();

  // Setup event listeners
  form.addEventListener('submit', handleFormSubmit);
  qrToggleBtn.addEventListener('click', toggleQRScanner);
  qrCloseBtn.addEventListener('click', closeQRScanner);
  clearHistoryBtn.addEventListener('click', clearHistory);

  // Demo button listeners
  document.querySelectorAll('.demo-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const demoUrl = btn.getAttribute('data-url');
      urlInput.value = demoUrl;
      urlInput.focus();
    });
  });
});

// ============================================================================
// Form Submission & Analysis
// ============================================================================
async function handleFormSubmit(e) {
  e.preventDefault();

  const url = urlInput.value.trim();
  if (!url) return;

  // Reset UI states
  hideError();
  hideResults();
  showLoading();

  try {
    // Use Vite Environment variable if provided, fallback to standard endpoints
    const baseUrl = (typeof import.meta !== 'undefined' && import.meta.env && import.meta.env.VITE_API_URL)
      ? import.meta.env.VITE_API_URL.replace(/\/$/, '')
      : '';
    const apiUrl = baseUrl ? `${baseUrl}/api/analyze` : '/api/analyze';

    const response = await fetch(apiUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ url })
    });

    const data = await response.json();

    if (!response.ok || !data.success) {
      throw new Error(data.error?.message || 'Analysis failed. Please try again.');
    }

    // Store in history
    addToHistory({
      url,
      verdict: data.analysis.verdict,
      score: data.analysis.score,
      timestamp: Date.now()
    });

    // Render results
    renderResults(data.analysis);
    showResults();
  } catch (err) {
    showError('Analysis Error', err.message);
  } finally {
    hideLoading();
  }
}

// ============================================================================
// QR Code Scanner
// ============================================================================
function toggleQRScanner() {
  if (qrReaderContainer.classList.contains('hidden')) {
    openQRScanner();
  } else {
    closeQRScanner();
  }
}

function openQRScanner() {
  qrReaderContainer.classList.remove('hidden');

  // Initialize QR scanner if not already initialized
  if (!qrScanner && typeof Html5Qrcode !== 'undefined') {
    qrScanner = new Html5Qrcode('qr-reader');

    const config = {
      fps: 10,
      qrbox: { width: 250, height: 250 }
    };

    qrScanner.start(
      { facingMode: 'environment' },
      config,
      onQRScanSuccess,
      onQRScanError
    ).catch(err => {
      console.error('QR Scanner failed to start:', err);
      showError('QR Scanner Error', 'Could not access camera. Please check permissions.');
      closeQRScanner();
    });
  }
}

function closeQRScanner() {
  qrReaderContainer.classList.add('hidden');

  if (qrScanner) {
    qrScanner.stop().then(() => {
      qrScanner.clear();
      qrScanner = null;
    }).catch(err => {
      console.error('QR Scanner stop error:', err);
    });
  }
}

function onQRScanSuccess(decodedText) {
  // Populate input with scanned URL
  urlInput.value = decodedText;
  closeQRScanner();

  // Auto-submit after short delay
  setTimeout(() => {
    form.dispatchEvent(new Event('submit'));
  }, 300);
}

function onQRScanError(errorMessage) {
  // Ignore scan errors (common when no QR in frame)
}

// ============================================================================
// Results Rendering
// ============================================================================
function renderResults(analysis) {
  // Verdict banner
  verdictBanner.className = `verdict-banner ${analysis.verdict}`;
  verdictTitle.textContent = analysis.verdict;
  verdictRecommendation.textContent = analysis.recommendation || '';
  scoreText.textContent = `${analysis.score}/100`;
  confidenceText.textContent = analysis.confidence.toUpperCase();

  // Verdict icon
  const iconMap = {
    SAFE: 'shield-check',
    REVIEW: 'alert-circle',
    SUSPICIOUS: 'shield-alert'
  };
  verdictIcon.innerHTML = '';
  const icon = document.createElement('i');
  icon.setAttribute('data-lucide', iconMap[analysis.verdict] || 'shield');
  verdictIcon.appendChild(icon);

  // Render URL anatomy
  renderAnatomy(analysis);

  // Render findings
  renderFindings(analysis.findings || []);

  // Re-initialize icons
  if (typeof lucide !== 'undefined') {
    lucide.createIcons();
  }
}

function renderAnatomy(analysis) {
  const parsed = analysis.parsed || {};

  const items = [
    { label: 'Actual Hostname', value: analysis.actual_hostname || parsed.hostname || 'None' },
    { label: 'Scheme', value: parsed.scheme || 'None' },
    { label: 'Userinfo (@)', value: parsed.has_userinfo ? 'Yes (Deceptive Pattern)' : 'No' },
    { label: 'Port', value: parsed.port || 'Default' },
    { label: 'Path', value: parsed.path || '/' },
    { label: 'Punycode', value: parsed.is_punycode ? 'Yes (IDN)' : 'No' }
  ];

  anatomyGrid.innerHTML = items.map(item => `
    <div class="anatomy-item">
      <div class="anatomy-label">${escapeHTML(item.label)}</div>
      <div class="anatomy-value">${escapeHTML(item.value)}</div>
    </div>
  `).join('');
}

function renderFindings(findings) {
  findingsCount.textContent = `${findings.length} triggered`;

  if (findings.length === 0) {
    findingsList.innerHTML = `
      <div class="clean-slate">
        <p>✓ No structural risks or deception indicators detected for this link.</p>
      </div>
    `;
    return;
  }

  findingsList.innerHTML = findings.map(finding => `
    <div class="finding-card">
      <div class="finding-header">
        <span class="finding-title">${escapeHTML(finding.title)}</span>
        <span class="severity-badge ${escapeHTML(finding.severity)}">${escapeHTML(finding.severity)}</span>
      </div>
      <div class="finding-desc">${escapeHTML(finding.message)}</div>
      ${finding.evidence ? `<div class="finding-evidence">Evidence: ${escapeHTML(finding.evidence)}</div>` : ''}
    </div>
  `).join('');
}

// ============================================================================
// History Management
// ============================================================================
function loadHistoryFromStorage() {
  try {
    const stored = localStorage.getItem('cybersafe_history');
    if (stored) {
      scanHistory = JSON.parse(stored);
    }
  } catch (err) {
    console.warn('Could not load history from localStorage:', err);
    scanHistory = [];
  }
}

function saveHistoryToStorage() {
  try {
    localStorage.setItem('cybersafe_history', JSON.stringify(scanHistory));
  } catch (err) {
    console.warn('Could not save history to localStorage:', err);
  }
}

function addToHistory(item) {
  // Prepend to history (most recent first)
  scanHistory.unshift(item);

  // Limit to 50 items
  if (scanHistory.length > 50) {
    scanHistory = scanHistory.slice(0, 50);
  }

  saveHistoryToStorage();
  renderHistory();
}

function renderHistory() {
  if (scanHistory.length === 0) {
    emptyHistory.classList.remove('hidden');
    historyList.querySelectorAll('.history-item').forEach(el => el.remove());
    return;
  }

  emptyHistory.classList.add('hidden');

  historyList.innerHTML = scanHistory.map((item, index) => `
    <div class="history-item" data-index="${index}">
      <span class="history-verdict ${escapeHTML(item.verdict)}">${escapeHTML(item.verdict)}</span>
      <span class="history-url" title="${escapeHTML(item.url)}">${escapeHTML(item.url)}</span>
    </div>
  `).join('');

  // Add click listeners
  historyList.querySelectorAll('.history-item').forEach(el => {
    el.addEventListener('click', () => {
      const index = parseInt(el.getAttribute('data-index'));
      const item = scanHistory[index];
      if (item) {
        urlInput.value = item.url;
        urlInput.focus();
      }
    });
  });
}

function clearHistory() {
  if (confirm('Clear all scan history? This cannot be undone.')) {
    scanHistory = [];
    saveHistoryToStorage();
    renderHistory();
  }
}

// ============================================================================
// UI State Management
// ============================================================================
function showLoading() {
  loadingState.classList.remove('hidden');
  analyzeBtn.disabled = true;
}

function hideLoading() {
  loadingState.classList.add('hidden');
  analyzeBtn.disabled = false;
}

function showError(title, message) {
  errorTitle.textContent = title;
  errorMessage.textContent = message;
  errorState.classList.remove('hidden');
}

function hideError() {
  errorState.classList.add('hidden');
}

function showResults() {
  resultsContainer.classList.remove('hidden');
}

function hideResults() {
  resultsContainer.classList.add('hidden');
}

// ============================================================================
// Utility Functions
// ============================================================================
function escapeHTML(str) {
  if (str === null || str === undefined) return '';
  return String(str).replace(/[&<>"']/g, tag => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  }[tag] || tag));
}
