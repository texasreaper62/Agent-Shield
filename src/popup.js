'use strict';

/**
 * AI Shield Popup Script
 *
 * Manages the popup UI that appears when clicking the extension icon.
 * Fetches scan results, displays threats, handles rescan requests,
 * pause/resume toggle, export reports, and settings navigation.
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
    instruction_override: 'Instruction Override',
    clipboard_hijack: 'Clipboard Hijack',
    malicious_plugin: 'Suspicious Plugin',
    ai_phishing: 'AI Phishing'
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
  const exportBtn = document.getElementById('export-btn');
  const pauseBtn = document.getElementById('pause-btn');
  const pauseIcon = document.getElementById('pause-icon');
  const pausedBanner = document.getElementById('paused-banner');
  const resumeLink = document.getElementById('resume-link');
  const settingsBtn = document.getElementById('settings-btn');

  // Current scan result (for export)
  let currentResult = null;

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
      exportBtn.style.display = 'none';
      return;
    }

    threatList.style.display = 'block';
    exportBtn.style.display = 'block';
    threatsContainer.innerHTML = '';

    for (const threat of threats) {
      const item = document.createElement('div');
      item.className = 'threat-item';

      const categoryName = CATEGORY_NAMES[threat.category] || threat.category;

      const confidenceHtml = threat.confidenceLabel
        ? `<br><span class="threat-confidence">${escapeHtml(threat.confidenceLabel)}</span>`
        : '';

      item.innerHTML = `
        <div class="threat-header">
          <span class="threat-chevron">&#x25B6;</span>
          <span class="severity-badge severity-${threat.severity}">${threat.severity}</span>
          <span class="threat-description">${escapeHtml(threat.description)}</span>
        </div>
        <div class="threat-detail">
          ${escapeHtml(threat.detail)}
          <br>
          <span class="threat-category">${escapeHtml(categoryName)}</span>${confidenceHtml}
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
    const timeText = result.stats.scanTimeMs + 'ms';
    statScanTime.textContent = timeText;

    // Show warning if scan was truncated due to time budget
    if (result.stats.budgetExceeded) {
      statScanTime.title = 'Scan was truncated because this page is very large. Results may be incomplete.';
      statScanTime.style.color = '#f59e0b';
    } else {
      statScanTime.title = '';
      statScanTime.style.color = '';
    }

    // Fetch cumulative stats from background
    chrome.runtime.sendMessage({ type: 'GET_STATS' }, (response) => {
      if (chrome.runtime.lastError) return;
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
    currentResult = result;

    if (!result) {
      statusIcon.textContent = '\u2753';
      statusTitle.textContent = 'No Data';
      statusDescription.textContent = 'Could not scan this page. It may be a browser internal page.';
      exportBtn.style.display = 'none';
      return;
    }

    updateStatusCard(result);
    renderThreats(result.threats);
    updateStats(result);
  };

  // =========================================================================
  // PAUSE / RESUME
  // =========================================================================

  /**
   * Loads the current enabled state and updates UI.
   */
  const loadPauseState = () => {
    chrome.storage.local.get('settings', (data) => {
      const settings = data.settings || {};
      const enabled = settings.enabled !== false; // Default to enabled
      updatePauseUI(enabled);
    });
  };

  /**
   * Toggles the pause state.
   */
  const togglePause = () => {
    chrome.storage.local.get('settings', (data) => {
      const settings = data.settings || {};
      const currentlyEnabled = settings.enabled !== false;
      settings.enabled = !currentlyEnabled;

      chrome.storage.local.set({ settings }, () => {
        updatePauseUI(settings.enabled);

        // Notify background
        chrome.runtime.sendMessage({
          type: 'SETTINGS_CHANGED',
          settings: settings
        });
      });
    });
  };

  /**
   * Updates the UI to reflect pause state.
   * @param {boolean} enabled - Whether scanning is enabled.
   */
  const updatePauseUI = (enabled) => {
    if (enabled) {
      pauseIcon.textContent = '\u23F8\uFE0F';
      pauseBtn.title = 'Pause scanning';
      pausedBanner.style.display = 'none';
      rescanBtn.disabled = false;
    } else {
      pauseIcon.textContent = '\u25B6\uFE0F';
      pauseBtn.title = 'Resume scanning';
      pausedBanner.style.display = 'block';
      rescanBtn.disabled = true;
    }
  };

  // =========================================================================
  // EXPORT REPORT
  // =========================================================================

  /**
   * Generates a plain-text threat report and copies it to clipboard.
   */
  const exportReport = () => {
    if (!currentResult) return;

    const lines = [];
    lines.push('AI SHIELD THREAT REPORT');
    lines.push('='.repeat(40));
    lines.push('');
    lines.push(`URL: ${currentResult.url}`);
    lines.push(`Scanned: ${new Date(currentResult.timestamp).toLocaleString()}`);
    lines.push(`Status: ${currentResult.status.toUpperCase()}`);
    lines.push(`Total Threats: ${currentResult.stats.totalThreats}`);

    if (currentResult.stats.critical > 0) lines.push(`  Critical: ${currentResult.stats.critical}`);
    if (currentResult.stats.high > 0) lines.push(`  High: ${currentResult.stats.high}`);
    if (currentResult.stats.medium > 0) lines.push(`  Medium: ${currentResult.stats.medium}`);
    if (currentResult.stats.low > 0) lines.push(`  Low: ${currentResult.stats.low}`);

    lines.push(`Scan Time: ${currentResult.stats.scanTimeMs}ms`);
    lines.push('');

    if (currentResult.threats.length > 0) {
      lines.push('THREATS DETECTED:');
      lines.push('-'.repeat(40));

      for (let i = 0; i < currentResult.threats.length; i++) {
        const threat = currentResult.threats[i];
        const categoryName = CATEGORY_NAMES[threat.category] || threat.category;
        lines.push('');
        lines.push(`${i + 1}. [${threat.severity.toUpperCase()}] ${categoryName}`);
        lines.push(`   ${threat.description}`);
        lines.push(`   Detail: ${threat.detail}`);
        if (threat.confidenceLabel) {
          lines.push(`   Confidence: ${threat.confidenceLabel}`);
        }
      }
    }

    lines.push('');
    lines.push('-'.repeat(40));
    lines.push('Generated by AI Shield (https://github.com/texasreaper62/AI-Shield)');

    const report = lines.join('\n');

    navigator.clipboard.writeText(report).then(() => {
      exportBtn.textContent = 'Copied!';
      exportBtn.classList.add('copied');
      setTimeout(() => {
        exportBtn.textContent = 'Copy Report';
        exportBtn.classList.remove('copied');
      }, 2000);
    }).catch(() => {
      exportBtn.textContent = 'Failed';
      setTimeout(() => {
        exportBtn.textContent = 'Copy Report';
      }, 2000);
    });
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
    if (num === undefined || num === null) return '\u2014';
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
          if (chrome.runtime.lastError) return;
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
            if (chrome.runtime.lastError) {
              displayResults(null);
              return;
            }
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
        if (chrome.runtime.lastError) {
          // Content script not available
        } else if (response) {
          displayResults(response);
        }
        rescanBtn.disabled = false;
        rescanBtn.textContent = 'Scan Again';
      });
    });
  });

  // Export button
  exportBtn.addEventListener('click', exportReport);

  // Pause/resume button
  pauseBtn.addEventListener('click', togglePause);
  resumeLink.addEventListener('click', togglePause);

  // Settings button
  settingsBtn.addEventListener('click', () => {
    chrome.runtime.openOptionsPage();
  });

  // =========================================================================
  // INITIALIZATION
  // =========================================================================

  loadPauseState();
  fetchResults();
})();
