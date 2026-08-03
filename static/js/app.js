/**
 * =====================================================================
 *  PhishGuard AI – Frontend JavaScript
 *  File: static/js/app.js
 *  Description: Handles URL submission, API interaction, dynamic DOM
 *               updates, animations, and user feedback for the phishing
 *               detection web application.
 * =====================================================================
 */

'use strict';

/* ─── DOM References ─────────────────────────────────────────────── */
const scanForm       = document.getElementById('scan-form');
const urlInput       = document.getElementById('url-input');
const scanBtn        = document.getElementById('scan-btn');
const clearBtn       = document.getElementById('clear-btn');
const inputError     = document.getElementById('input-error');

const loadingSection = document.getElementById('loading-section');
const resultsSection = document.getElementById('results-section');
const errorSection   = document.getElementById('error-section');
const errorMessage   = document.getElementById('error-message');
const retryBtn       = document.getElementById('retry-btn');
const scanAgainBtn   = document.getElementById('scan-again-btn');

// Loading steps
const steps = [
  document.getElementById('step-1'),
  document.getElementById('step-2'),
  document.getElementById('step-3'),
  document.getElementById('step-4'),
];

// Result elements
const verdictBanner   = document.getElementById('verdict-banner');
const verdictIcon     = document.getElementById('verdict-icon');
const verdictText     = document.getElementById('verdict-text');
const verdictUrl      = document.getElementById('verdict-url');
const verdictRisk     = document.getElementById('verdict-risk');

const scoreConfidence = document.getElementById('score-confidence');
const scorePhish      = document.getElementById('score-phish');
const scoreLegit      = document.getElementById('score-legit');
const barConfidence   = document.getElementById('bar-confidence');
const barPhish        = document.getElementById('bar-phish');
const barLegit        = document.getElementById('bar-legit');

const featureList       = document.getElementById('feature-list');
const recommendationText= document.getElementById('recommendation-text');
const riskMeterFill     = document.getElementById('risk-meter-fill');
const riskMeterThumb    = document.getElementById('risk-meter-thumb');
const riskMeterValue    = document.getElementById('risk-meter-value');

// Example buttons
document.getElementById('ex-legit').addEventListener('click', loadExample);
document.getElementById('ex-phish').addEventListener('click', loadExample);
document.getElementById('ex-ip').addEventListener('click', loadExample);


/* ─── State ──────────────────────────────────────────────────────── */
let isScanning = false;
let loadingTimers = [];


/* ─── Event Listeners ────────────────────────────────────────────── */

// Form submit
scanForm.addEventListener('submit', (e) => {
  e.preventDefault();
  startScan();
});

// Input: show/hide clear button + remove error state
urlInput.addEventListener('input', () => {
  clearBtn.hidden = !urlInput.value.trim();
  if (inputError.textContent) {
    hideInputError();
  }
});

// Clear button
clearBtn.addEventListener('click', () => {
  urlInput.value = '';
  clearBtn.hidden = true;
  urlInput.focus();
  hideInputError();
});

// Retry button
retryBtn.addEventListener('click', resetToHome);

// Scan Again button
scanAgainBtn.addEventListener('click', resetToHome);

// Enter key shortcut
urlInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    e.preventDefault();
    startScan();
  }
});


/* ─── Quick Examples ─────────────────────────────────────────────── */

/**
 * Load an example URL into the input field and auto-scan.
 * @param {Event} e - The click event from an example button
 */
function loadExample(e) {
  const url = e.currentTarget.dataset.url;
  urlInput.value = url;
  clearBtn.hidden = false;
  hideInputError();
  // Small delay for visual feedback before scanning
  setTimeout(() => startScan(), 100);
}


/* ─── Input Validation ───────────────────────────────────────────── */

/**
 * Client-side URL validation before sending to the server.
 * @param {string} url
 * @returns {{ valid: boolean, message: string }}
 */
function validateUrl(url) {
  if (!url || !url.trim()) {
    return { valid: false, message: '⚠️ Please enter a URL to scan.' };
  }

  const trimmed = url.trim();

  if (trimmed.length < 4) {
    return { valid: false, message: '⚠️ URL is too short to analyze.' };
  }

  if (trimmed.length > 2048) {
    return { valid: false, message: '⚠️ URL exceeds maximum length of 2048 characters.' };
  }

  // Check it contains at least a dot (very basic check)
  const checkUrl = trimmed.startsWith('http') ? trimmed : 'http://' + trimmed;
  try {
    const parsed = new URL(checkUrl);
    if (!parsed.hostname.includes('.') && !/^\d{1,3}(\.\d{1,3}){3}$/.test(parsed.hostname)) {
      return { valid: false, message: '⚠️ Please enter a valid URL with a domain (e.g., example.com).' };
    }
  } catch (_) {
    return { valid: false, message: '⚠️ Invalid URL format. Try something like https://example.com' };
  }

  return { valid: true, message: '' };
}

function showInputError(msg) {
  inputError.textContent = msg;
  inputError.hidden = false;
  urlInput.classList.add('is-error');
  urlInput.setAttribute('aria-invalid', 'true');
}

function hideInputError() {
  inputError.hidden = true;
  inputError.textContent = '';
  urlInput.classList.remove('is-error');
  urlInput.removeAttribute('aria-invalid');
}


/* ─── Section Visibility ─────────────────────────────────────────── */

function showSection(section) {
  [loadingSection, resultsSection, errorSection].forEach(s => {
    s.hidden = (s !== section);
  });
}

function hideAllSections() {
  loadingSection.hidden = true;
  resultsSection.hidden = true;
  errorSection.hidden = true;
}


/* ─── Loading Animation ──────────────────────────────────────────── */

/**
 * Animate the loading steps sequentially.
 */
function animateLoadingSteps() {
  // Reset steps
  steps.forEach(s => {
    s.classList.remove('loading-step--active', 'loading-step--done');
  });
  steps[0].classList.add('loading-step--active');

  const durations = [400, 700, 500, 300];
  let cumulative = 0;

  durations.forEach((duration, i) => {
    cumulative += duration;
    const t = setTimeout(() => {
      // Mark current as done
      steps[i].classList.remove('loading-step--active');
      steps[i].classList.add('loading-step--done');
      // Activate next
      if (i + 1 < steps.length) {
        steps[i + 1].classList.add('loading-step--active');
      }
    }, cumulative);
    loadingTimers.push(t);
  });
}

function clearLoadingTimers() {
  loadingTimers.forEach(t => clearTimeout(t));
  loadingTimers = [];
}


/* ─── Button State ───────────────────────────────────────────────── */

function setScanningState(scanning) {
  isScanning = scanning;
  scanBtn.disabled = scanning;

  const icon = scanBtn.querySelector('.scan-btn__icon');
  const text = scanBtn.querySelector('.scan-btn__text');

  if (scanning) {
    scanBtn.classList.add('scan-btn--loading');
    icon.textContent = '⏳';
    text.textContent = 'Scanning…';
  } else {
    scanBtn.classList.remove('scan-btn--loading');
    icon.textContent = '🔎';
    text.textContent = 'Scan URL';
  }
}


/* ─── Main Scan Function ─────────────────────────────────────────── */

/**
 * Validates the input, calls the API, and displays results.
 */
async function startScan() {
  if (isScanning) return;

  const url = urlInput.value.trim();

  // Client-side validation
  const { valid, message } = validateUrl(url);
  if (!valid) {
    showInputError(message);
    urlInput.focus();
    return;
  }

  hideInputError();
  setScanningState(true);
  showSection(loadingSection);
  animateLoadingSteps();

  try {
    const response = await fetch('/api/predict', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });

    const data = await response.json();

    clearLoadingTimers();

    if (!response.ok || !data.success) {
      throw new Error(data.error || `Server error (${response.status})`);
    }

    // Small delay to let loading animation complete
    await sleep(300);

    displayResults(data);
    showSection(resultsSection);

  } catch (err) {
    clearLoadingTimers();
    console.error('[PhishGuard] Scan error:', err);
    displayError(err.message || 'An unexpected error occurred. Please try again.');
    showSection(errorSection);
  } finally {
    setScanningState(false);
  }
}


/* ─── Display Results ────────────────────────────────────────────── */

/**
 * Populates all result elements with API response data.
 * @param {Object} data - API response from /api/predict
 */
function displayResults(data) {
  const isPhishing = data.is_phishing;

  /* ── Verdict Banner ── */
  verdictBanner.className = `verdict-banner verdict-banner--${isPhishing ? 'danger' : 'safe'}`;
  verdictIcon.textContent = isPhishing ? '🚨' : '✅';
  verdictText.textContent = data.prediction;
  verdictText.className   = `verdict-banner__result verdict-text--${isPhishing ? 'danger' : 'safe'}`;

  // Truncate long URLs for display
  const displayUrl = data.url.length > 60
    ? data.url.slice(0, 57) + '…'
    : data.url;
  verdictUrl.textContent = displayUrl;
  verdictUrl.title = data.url;

  // Risk tag
  const riskColorMap = {
    'red':    'risk-tag--red',
    'orange': 'risk-tag--orange',
    'green':  'risk-tag--green',
    'blue':   'risk-tag--blue',
  };
  verdictRisk.textContent = `⚠ ${data.risk_level} Risk`;
  verdictRisk.className = `verdict-banner__risk ${riskColorMap[data.risk_color] || 'risk-tag--blue'}`;

  /* ── Score Cards ── */
  animateNumber(scoreConfidence, 0, data.confidence, '%');
  animateNumber(scorePhish,      0, data.phishing_prob, '%');
  animateNumber(scoreLegit,      0, data.legitimate_prob, '%');

  // Bars animate after a small delay
  setTimeout(() => {
    barConfidence.style.width = `${data.confidence}%`;
    barPhish.style.width      = `${data.phishing_prob}%`;
    barLegit.style.width      = `${data.legitimate_prob}%`;
  }, 200);

  /* ── Feature Analysis ── */
  renderFeatureList(data.feature_analysis);

  /* ── Recommendation ── */
  recommendationText.textContent = data.recommendation;

  /* ── Risk Meter ── */
  const riskPercent = calculateRiskPercent(data.risk_level);
  setTimeout(() => {
    riskMeterFill.style.width  = `${riskPercent}%`;
    riskMeterThumb.style.left  = `${riskPercent}%`;
  }, 300);
  riskMeterValue.textContent = `${data.risk_level} Risk — ${data.confidence.toFixed(1)}% confidence`;

  // Update thumb color
  const thumbColors = {
    'red': '#ef4444', 'orange': '#f59e0b',
    'green': '#10b981', 'blue': '#3b82f6'
  };
  riskMeterThumb.style.borderColor = thumbColors[data.risk_color] || '#6366f1';
}


/* ─── Feature List Renderer ──────────────────────────────────────── */

/**
 * Renders the feature analysis list items.
 * @param {Array} features - Array of feature objects from API
 */
function renderFeatureList(features) {
  featureList.innerHTML = '';

  features.forEach((feat, index) => {
    const li = document.createElement('li');
    li.className = `feature-item feature-item--${feat.status}`;
    li.style.animationDelay = `${index * 60}ms`;
    li.setAttribute('role', 'listitem');
    li.innerHTML = `
      <div class="feature-item__dot" aria-hidden="true"></div>
      <div class="feature-item__name">${escapeHtml(feat.name)}</div>
      <div class="feature-item__value">${escapeHtml(String(feat.value))}</div>
    `;
    // Tooltip-style description via title
    li.title = feat.description;
    li.setAttribute('aria-label', `${feat.name}: ${feat.value}. ${feat.description}`);
    featureList.appendChild(li);
  });
}


/* ─── Error Display ──────────────────────────────────────────────── */

/**
 * Shows the error section with a message.
 * @param {string} msg - Error message to display
 */
function displayError(msg) {
  errorMessage.textContent = msg;
}


/* ─── Reset to Home ──────────────────────────────────────────────── */

/**
 * Resets the UI back to the initial scan state.
 */
function resetToHome() {
  hideAllSections();
  setScanningState(false);
  urlInput.focus();
  urlInput.select();
  // Scroll to top of scanner
  document.querySelector('.scanner-card').scrollIntoView({
    behavior: 'smooth', block: 'center'
  });
}


/* ─── Stats Counter Animation ────────────────────────────────────── */

/**
 * Animates a number counter from 0 to target value using IntersectionObserver.
 */
function initStatsCounters() {
  const statNumbers = document.querySelectorAll('.stat-card__number');

  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting && !entry.target.dataset.animated) {
        entry.target.dataset.animated = 'true';
        const target = parseInt(entry.target.dataset.target, 10);
        const suffix = entry.target.dataset.suffix || '';
        animateNumber(entry.target, 0, target, suffix, 1500);
        observer.unobserve(entry.target);
      }
    });
  }, { threshold: 0.5 });

  statNumbers.forEach(el => observer.observe(el));
}


/* ─── Utility Functions ──────────────────────────────────────────── */

/**
 * Animates a number from start to end in the given element.
 * @param {HTMLElement} el
 * @param {number} start
 * @param {number} end
 * @param {string} suffix
 * @param {number} duration - ms
 */
function animateNumber(el, start, end, suffix = '', duration = 800) {
  const startTime = performance.now();
  const range = end - start;

  function update(currentTime) {
    const elapsed  = currentTime - startTime;
    const progress = Math.min(elapsed / duration, 1);
    // Easing: ease-out cubic
    const eased = 1 - Math.pow(1 - progress, 3);
    const current = start + (range * eased);

    el.textContent = (Number.isInteger(end) && Number.isInteger(start))
      ? Math.round(current) + suffix
      : current.toFixed(1) + suffix;

    if (progress < 1) {
      requestAnimationFrame(update);
    }
  }

  requestAnimationFrame(update);
}

/**
 * Calculates a 0–100 percentage for the risk meter.
 * @param {string} riskLevel
 * @returns {number}
 */
function calculateRiskPercent(riskLevel) {
  const map = {
    'Low':        10,
    'Low-Medium': 30,
    'Medium':     60,
    'High':       90,
  };
  return map[riskLevel] ?? 50;
}

/**
 * Escapes HTML special characters to prevent XSS.
 * @param {string} str
 * @returns {string}
 */
function escapeHtml(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/**
 * Returns a promise that resolves after ms milliseconds.
 * @param {number} ms
 * @returns {Promise<void>}
 */
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}


/* ─── Initialize ─────────────────────────────────────────────────── */

/**
 * Application initialization on DOM load.
 */
function init() {
  // Start stats counters
  initStatsCounters();

  // Focus input on page load
  urlInput.focus();

  // Feature item hover tooltip enhancement
  document.addEventListener('mouseover', (e) => {
    const item = e.target.closest('.feature-item');
    if (item && item.title) {
      // Title attr serves as tooltip — no extra lib needed
    }
  });

  console.log('[PhishGuard AI] Application initialized. Ready to scan URLs.');
}

// Run when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
