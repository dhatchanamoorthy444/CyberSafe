// CyberSafe Browser Extension — Popup Script

const API_URL = 'https://cybersafe01.vercel.app/api/analyze';

const elements = {
  urlInput: document.getElementById('url-input'),
  analyzeBtn: document.getElementById('analyze-btn'),
  currentTabBtn: document.getElementById('current-tab-btn'),
  loading: document.getElementById('loading'),
  error: document.getElementById('error'),
  errorText: document.getElementById('error-text'),
  results: document.getElementById('results'),
  verdict: document.getElementById('verdict'),
  findings: document.getElementById('findings'),
  fullPageLink: document.getElementById('full-page-link'),
};

// Analyze button handler
elements.analyzeBtn.addEventListener('click', async () => {
  const url = elements.urlInput.value.trim();
  if (!url) return;
  await analyzeURL(url);
});

// Current tab button handler
elements.currentTabBtn.addEventListener('click', async () => {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab?.url) {
      elements.urlInput.value = tab.url;
      await analyzeURL(tab.url);
    }
  } catch (err) {
    showError('Could not access current tab URL.');
  }
});

// Enter key support
elements.urlInput.addEventListener('keypress', (e) => {
  if (e.key === 'Enter') {
    elements.analyzeBtn.click();
  }
});

// Main analysis function
async function analyzeURL(url) {
  hideAll();
  showLoading();

  try {
    const response = await fetch(API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });

    const data = await response.json();

    if (!response.ok || !data.success) {
      throw new Error(data.error?.message || 'Analysis failed');
    }

    displayResults(data.analysis, url);
  } catch (err) {
    showError(err.message || 'Could not reach the analysis server.');
  }
}

function displayResults(analysis, url) {
  hideAll();

  // Set verdict
  elements.verdict.textContent = `${analysis.verdict} — Risk: ${analysis.score}/100`;
  elements.verdict.className = analysis.verdict;

  // Render findings
  const findings = analysis.findings || [];
  if (findings.length === 0) {
    elements.findings.innerHTML = '<div style="color:#94a3b8;text-align:center;padding:8px">No structural risks detected</div>';
  } else {
    elements.findings.innerHTML = findings.map(f => `
      <div class="finding-item">
        <div class="finding-title">${escapeHTML(f.title)} [${escapeHTML(f.severity)}]</div>
        <div class="finding-msg">${escapeHTML(f.message)}</div>
      </div>
    `).join('');
  }

  // Set full page link
  elements.fullPageLink.href = `https://cybersafe01.vercel.app/?url=${encodeURIComponent(url)}`;

  elements.results.classList.remove('hidden');
}

function showLoading() {
  elements.loading.classList.remove('hidden');
}

function showError(message) {
  elements.errorText.textContent = message;
  elements.error.classList.remove('hidden');
}

function hideAll() {
  elements.loading.classList.add('hidden');
  elements.error.classList.add('hidden');
  elements.results.classList.add('hidden');
}

function escapeHTML(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

// Auto-analyze if URL is in input (from context menu)
chrome.storage.local.get(['pendingURL'], (result) => {
  if (result.pendingURL) {
    elements.urlInput.value = result.pendingURL;
    chrome.storage.local.remove(['pendingURL']);
    analyzeURL(result.pendingURL);
  }
});
