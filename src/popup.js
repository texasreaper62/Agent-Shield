'use strict';

/**
 * AI Shield Popup Script
 *
 * Manages the popup UI that appears when clicking the extension icon.
 * Fetches scan results, displays threats, and handles rescan requests.
 */
(() => {
  // =========================================================================
  // STATUS DEFINITIONS
  // =========================================================================

  const STATUS_CONFIG = {
    safe: {
      icon: '\u2705',
      title: 'Safe',
      description: 'This page looks clean. No AI threats detected.',
      className: 'status-safe'
    },
    caution: {
      icon: '\u26A0\uFE0F',
      title: 'Caution',
      description: 'We noticed a few things on this page, but nothing dangerous. Stay alert when using AI assistants here.',
      className: 'status-caution'
    },
    warning: {
      icon: '\u26A0\uFE0F',
      title: 'Warning',
      description: 'This page contains content that could manipulate AI assistants. Be careful what you copy or paste from here.',
      className: 'status-warning'
    },
    danger: {
      icon: '\u274C',
      title: 'Danger',
      description: 'This page is actively trying to manipulate AI assistants. Hidden instructions were found that could hijack your AI tools.',
      className: 'status-danger'
    }
  };

  // Category display names
  const CATEGORY_NAMES = {
    prompt_injection: 'Prompt Injection',
    hidden_text: 'Hidden Text',
    role_hijack: 'Role Hijack',
    data_exfiltration: 'Data Exfiltration',
    fake_ai_interface: 'Fake AI Interface',
    social_engineering: 'Social Engineering',
    instruction_override: 'Instruction Override'
  };

  // =========================================================================
  // DOM ELEMENTS
  // =========================================================================

  const statusCard = document.getElementById('status-card');
  const statusIcon = document.getElementById('status-icon');
  const statusTitle = document.getElementById('status-title');
  const statusDescription = document.getElementById('status-description');
  const threatList = document.getElementById('threat-list');
  const threatsContainer = document.getElementById('threats-container');
  const statScanTime = document.getElementById('stat-scan-time');
  const statTotalScans = document.getElementById('stat-total-scans');
  const statTotalThreats = document.getElementById('stat-total-threats');
  const rescanBtn = document.getElementById('rescan-btn');

  // =========================================================================
  // UI RENDERING
  // =========================================================================

  /**
   * Updates the status card with scan results.
   * @param {object} result - Scan result from the detector.
   */
  const updateStatusCard = (result) => {
    const config = STATUS_CONFIG[result.status] || STATUS_CONFIG.safe;

    // Remove all status classes
    statusCard.classList.remove('status-safe', 'status-caution', 'status-warning', 'status-danger');
    statusCard.classList.add(config.className);

    statusIcon.textContent = config.icon;
    statusTitle.textContent = config.title;
    statusDescription.textContent = config.description;
  };

  /**
   * Renders the threat list.
   * @param {Array} threats - Array of threat objects.
   */
  const renderThreats = (threats) => {
    if (!threats || threats.length === 0) {
      threatList.style.display = 'none';
      return;
    }

    threatList.style.display = 'block';
    threatsContainer.innerHTML = '';

    for (const threat of threats) {
      const item = document.createElement('div');
      item.className = 'threat-item';

      const categoryName = CATEGORY_NAMES[threat.category] || threat.category;

      item.innerHTML = `
        <div class="threat-header">
          <span class="threat-chevron">&#x25B6;</span>
          <span class="severity-badge severity-${threat.severity}">${threat.severity}</span>
          <span class="threat-description">${escapeHtml(threat.description)}</span>
        </div>
        <div class="threat-detail">
          ${escapeHtml(threat.detail)}
          <br>
          <span class="threat-category">${escapeHtml(categoryName)}</span>
        </div>
      `;

      // Toggle expand/collapse
      const header = item.querySelector('.threat-header');
      header.addEventListener('click', () => {
        item.classList.toggle('expanded');
      });

      threatsContainer.appendChild(item);
    }
  };

  /**
   * Updates the stats bar.
   * @param {object} result - Scan result from the detector.
   */
  const updateStats = (result) => {
    statScanTime.textContent = result.stats.scanTimeMs + 'ms';

    // Fetch cumulative stats from background
    chrome.runtime.sendMessage({ type: 'GET_STATS' }, (response) => {
      if (response) {
        statTotalScans.textContent = formatNumber(response.totalScans);
        statTotalThreats.textContent = formatNumber(response.totalThreatsFound);
      }
    });
  };

  /**
   * Displays scan results in the popup.
   * @param {object} result - Scan result from the detector.
   */
  const displayResults = (result) => {
    if (!result) {
      statusIcon.textContent = '\u2753';
      statusTitle.textContent = 'No Data';
      statusDescription.textContent = 'Could not scan this page. It may be a browser internal page.';
      return;
    }

    updateStatusCard(result);
    renderThreats(result.threats);
    updateStats(result);
  };

  // =========================================================================
  // UTILITY FUNCTIONS
  // =========================================================================

  /**
   * Escapes HTML to prevent XSS in rendered threat details.
   * @param {string} text - Text to escape.
   * @returns {string} Escaped text.
   */
  const escapeHtml = (text) => {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  };

  /**
   * Formats a number with commas for readability.
   * @param {number} num - Number to format.
   * @returns {string} Formatted number string.
   */
  const formatNumber = (num) => {
    if (num === undefined || num === null) return '—';
    return num.toLocaleString();
  };

  // =========================================================================
  // DATA FETCHING
  // =========================================================================

  /**
   * Fetches scan results for the current tab.
   */
  const fetchResults = () => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (!tabs || tabs.length === 0) {
        displayResults(null);
        return;
      }

      const tab = tabs[0];

      // Skip non-scannable pages
      if (!tab.url || tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://') || tab.url.startsWith('about:')) {
        statusIcon.textContent = '\u2139\uFE0F';
        statusTitle.textContent = 'Cannot Scan';
        statusDescription.textContent = 'AI Shield cannot scan browser internal pages. Navigate to a website to see results.';
        statusCard.classList.remove('status-safe', 'status-caution', 'status-warning', 'status-danger');
        statusCard.classList.add('status-safe');

        // Still fetch cumulative stats
        chrome.runtime.sendMessage({ type: 'GET_STATS' }, (response) => {
          if (response) {
            statTotalScans.textContent = formatNumber(response.totalScans);
            statTotalThreats.textContent = formatNumber(response.totalThreatsFound);
          }
        });
        return;
      }

      // Try to get results from content script first
      chrome.tabs.sendMessage(tab.id, { type: 'GET_SCAN_RESULT' }, (response) => {
        if (chrome.runtime.lastError || !response) {
          // Fallback: try background script
          chrome.runtime.sendMessage({ type: 'GET_TAB_RESULT', tabId: tab.id }, (bgResponse) => {
            if (bgResponse) {
              displayResults(bgResponse);
            } else {
              // Fallback: try storage
              chrome.storage.local.get('lastScanResult', (data) => {
                if (data.lastScanResult && data.lastScanResult.url === tab.url) {
                  displayResults(data.lastScanResult);
                } else {
                  displayResults(null);
                }
              });
            }
          });
        } else {
          displayResults(response);
        }
      });
    });
  };

  // =========================================================================
  // EVENT HANDLERS
  // =========================================================================

  // Rescan button
  rescanBtn.addEventListener('click', () => {
    rescanBtn.disabled = true;
    rescanBtn.textContent = 'Scanning...';

    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (!tabs || tabs.length === 0) {
        rescanBtn.disabled = false;
        rescanBtn.textContent = 'Scan Again';
        return;
      }

      chrome.tabs.sendMessage(tabs[0].id, { type: 'RESCAN' }, (response) => {
        if (response) {
          displayResults(response);
        }
        rescanBtn.disabled = false;
        rescanBtn.textContent = 'Scan Again';
      });
    });
  });

  // =========================================================================
  // INITIALIZATION
  // =========================================================================

  fetchResults();
})();
