'use strict';

/**
 * AI Shield History Page Script
 *
 * Displays browsable scan history with search, filter, export, and cleanup.
 * All data is stored locally via chrome.storage.local.
 */
(() => {
  // =========================================================================
  // DOM ELEMENTS
  // =========================================================================

  const searchInput = document.getElementById('search-input');
  const historyList = document.getElementById('history-list');
  const emptyState = document.getElementById('empty-state');
  const noResults = document.getElementById('no-results');
  const exportBtn = document.getElementById('export-history-btn');
  const clearBtn = document.getElementById('clear-history-btn');
  const statTotal = document.getElementById('stat-total');
  const statThreats = document.getElementById('stat-threats');
  const statDanger = document.getElementById('stat-danger');
  const statSites = document.getElementById('stat-sites');
  const chips = document.querySelectorAll('.chip');

  let allHistory = [];
  let activeFilter = 'all';

  // =========================================================================
  // THEME
  // =========================================================================

  /**
   * Applies theme from settings.
   */
  const applyTheme = () => {
    chrome.storage.local.get('settings', (data) => {
      const settings = data.settings || {};
      if (settings.theme === 'light') {
        document.body.classList.add('light-theme');
      }
    });
  };

  // =========================================================================
  // DATA LOADING
  // =========================================================================

  /**
   * Loads history from background and renders it.
   */
  const loadHistory = () => {
    chrome.runtime.sendMessage({ type: 'GET_HISTORY' }, (history) => {
      if (chrome.runtime.lastError) {
        allHistory = [];
      } else {
        allHistory = history || [];
      }
      updateStats();
      renderAnalytics();
      renderHistory();
    });
  };

  // =========================================================================
  // STATS
  // =========================================================================

  /**
   * Updates the summary statistics.
   */
  const updateStats = () => {
    statTotal.textContent = allHistory.length;

    let totalThreats = 0;
    let dangerCount = 0;
    const sites = new Set();

    for (const entry of allHistory) {
      totalThreats += entry.stats.totalThreats;
      if (entry.status === 'danger') dangerCount++;
      sites.add(entry.hostname);
    }

    statThreats.textContent = totalThreats;
    statDanger.textContent = dangerCount;
    statSites.textContent = sites.size;
  };

  // =========================================================================
  // ANALYTICS
  // =========================================================================

  const CATEGORY_DISPLAY = {
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

  const CATEGORY_COLORS = {
    prompt_injection: '#ef4444',
    hidden_text: '#f97316',
    role_hijack: '#eab308',
    data_exfiltration: '#ef4444',
    fake_ai_interface: '#f97316',
    social_engineering: '#eab308',
    instruction_override: '#ef4444',
    clipboard_hijack: '#f97316',
    malicious_plugin: '#8b949e',
    ai_phishing: '#ef4444'
  };

  const analyticsSection = document.getElementById('analytics-section');
  const categoryChart = document.getElementById('category-chart');
  const activityChart = document.getElementById('activity-chart');

  /**
   * Renders analytics charts from history data.
   */
  const renderAnalytics = () => {
    if (allHistory.length === 0) {
      analyticsSection.style.display = 'none';
      return;
    }
    analyticsSection.style.display = 'block';

    // Category breakdown
    const categoryCounts = {};
    for (const entry of allHistory) {
      if (!entry.threats) continue;
      for (const threat of entry.threats) {
        const cat = threat.category || 'unknown';
        categoryCounts[cat] = (categoryCounts[cat] || 0) + 1;
      }
    }

    const sorted = Object.entries(categoryCounts).sort((a, b) => b[1] - a[1]);
    const maxCount = sorted.length > 0 ? sorted[0][1] : 1;

    if (sorted.length > 0) {
      categoryChart.innerHTML = sorted.map(([cat, count]) => {
        const pct = Math.max(2, (count / maxCount) * 100);
        const label = CATEGORY_DISPLAY[cat] || cat;
        const color = CATEGORY_COLORS[cat] || '#58a6ff';
        return `<div class="cat-bar-row">
          <span class="cat-bar-label">${escapeHtml(label)}</span>
          <div class="cat-bar-track"><div class="cat-bar-fill" style="width:${pct}%;background-color:${color};"></div></div>
          <span class="cat-bar-count">${count}</span>
        </div>`;
      }).join('');
    } else {
      categoryChart.innerHTML = '<div style="font-size:12px;color:#8b949e;">No threats recorded yet.</div>';
    }

    // Activity chart (last 7 days)
    const days = [];
    const dayLabels = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
    const now = new Date();

    for (let i = 6; i >= 0; i--) {
      const d = new Date(now);
      d.setDate(d.getDate() - i);
      d.setHours(0, 0, 0, 0);
      days.push({
        start: d.getTime(),
        end: d.getTime() + 86400000,
        label: dayLabels[d.getDay()],
        count: 0
      });
    }

    for (const entry of allHistory) {
      for (const day of days) {
        if (entry.timestamp >= day.start && entry.timestamp < day.end) {
          day.count++;
          break;
        }
      }
    }

    const maxDay = Math.max(1, ...days.map(d => d.count));
    activityChart.innerHTML = days.map(day => {
      const height = Math.max(2, (day.count / maxDay) * 48);
      return `<div class="activity-bar-wrap">
        <div class="activity-bar" style="height:${height}px;" title="${day.count} scans"></div>
        <span class="activity-bar-label">${day.label}</span>
      </div>`;
    }).join('');
  };

  // =========================================================================
  // RENDERING
  // =========================================================================

  /**
   * Escapes HTML to prevent XSS.
   * @param {string} text - Text to escape.
   * @returns {string}
   */
  const escapeHtml = (text) => {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  };

  /**
   * Formats a timestamp to a readable date/time string.
   * @param {number} ts - Timestamp in ms.
   * @returns {string}
   */
  const formatDate = (ts) => {
    const d = new Date(ts);
    const now = new Date();
    const diff = now - d;

    // Less than 1 hour: "X minutes ago"
    if (diff < 3600000) {
      const mins = Math.floor(diff / 60000);
      return mins <= 1 ? 'Just now' : `${mins} minutes ago`;
    }

    // Less than 24 hours: "X hours ago"
    if (diff < 86400000) {
      const hours = Math.floor(diff / 3600000);
      return `${hours} hour${hours !== 1 ? 's' : ''} ago`;
    }

    // Same year: "Mar 17, 2:30 PM"
    if (d.getFullYear() === now.getFullYear()) {
      return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) +
        ', ' + d.toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' });
    }

    // Different year: full date
    return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
  };

  /**
   * Returns the color for a safety score.
   * @param {number} score - Safety score 0-100.
   * @returns {string} Color hex code.
   */
  const scoreColor = (score) => {
    if (score >= 90) return '#22c55e';
    if (score >= 70) return '#eab308';
    if (score >= 50) return '#f97316';
    return '#ef4444';
  };

  /**
   * Filters and renders the history list.
   */
  const renderHistory = () => {
    const query = searchInput.value.toLowerCase().trim();

    // Filter by status and search query
    const filtered = allHistory.filter(entry => {
      if (activeFilter !== 'all' && entry.status !== activeFilter) return false;
      if (query && !entry.url.toLowerCase().includes(query) &&
          !entry.hostname.toLowerCase().includes(query)) return false;
      return true;
    });

    historyList.innerHTML = '';

    if (allHistory.length === 0) {
      emptyState.style.display = 'block';
      noResults.style.display = 'none';
      historyList.style.display = 'none';
      return;
    }

    emptyState.style.display = 'none';

    if (filtered.length === 0) {
      noResults.style.display = 'block';
      historyList.style.display = 'none';
      return;
    }

    noResults.style.display = 'none';
    historyList.style.display = 'flex';

    for (const entry of filtered) {
      const el = document.createElement('div');
      el.className = 'history-entry';

      const score = entry.stats.safetyScore !== undefined ? entry.stats.safetyScore : null;
      const scoreHtml = score !== null
        ? `<span class="history-score" style="color:${scoreColor(score)}">${score}</span>`
        : '';

      const threatText = entry.stats.totalThreats === 0
        ? 'No threats'
        : `${entry.stats.totalThreats} threat${entry.stats.totalThreats !== 1 ? 's' : ''}`;

      // Build threat detail section
      let detailHtml = '';
      if (entry.threats && entry.threats.length > 0) {
        const threatItems = entry.threats.map(t =>
          `<div class="threat-summary-item"><strong>[${escapeHtml(t.severity)}]</strong> ${escapeHtml(t.description)}</div>`
        ).join('');
        detailHtml = `<div class="history-detail">${threatItems}</div>`;
      }

      el.innerHTML = `
        <span class="history-status-dot dot-${entry.status}"></span>
        <div class="history-info">
          <div class="history-url" title="${escapeHtml(entry.url)}">${escapeHtml(entry.hostname)}${escapeHtml(new URL(entry.url).pathname)}</div>
          <div class="history-meta">${formatDate(entry.timestamp)} &middot; ${entry.stats.scanTimeMs}ms</div>
        </div>
        ${scoreHtml}
        <span class="history-threats">${threatText}</span>
        <button class="history-delete" title="Remove from history" data-ts="${entry.timestamp}">&times;</button>
        ${detailHtml}
      `;

      // Toggle detail on click (but not on button click)
      el.addEventListener('click', (e) => {
        if (e.target.classList.contains('history-delete')) return;
        el.classList.toggle('expanded');
      });

      // Delete button
      const deleteBtn = el.querySelector('.history-delete');
      deleteBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        deleteEntry(entry.timestamp);
      });

      historyList.appendChild(el);
    }
  };

  // =========================================================================
  // ACTIONS
  // =========================================================================

  /**
   * Deletes a single history entry.
   * @param {number} timestamp - The entry timestamp to delete.
   */
  const deleteEntry = (timestamp) => {
    chrome.runtime.sendMessage({ type: 'DELETE_HISTORY_ENTRY', timestamp }, () => {
      allHistory = allHistory.filter(h => h.timestamp !== timestamp);
      updateStats();
      renderHistory();
    });
  };

  /**
   * Exports history as JSON file download.
   */
  const exportHistory = () => {
    const data = {
      exported: new Date().toISOString(),
      version: '0.6.0',
      totalEntries: allHistory.length,
      history: allHistory
    };

    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ai-shield-history-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);

    exportBtn.textContent = 'Exported!';
    setTimeout(() => { exportBtn.textContent = 'Export JSON'; }, 2000);
  };

  /**
   * Clears all history with a confirmation dialog.
   */
  const clearHistory = () => {
    // Create confirmation dialog
    const overlay = document.createElement('div');
    overlay.className = 'confirm-overlay';
    overlay.innerHTML = `
      <div class="confirm-dialog">
        <h3>Clear all history?</h3>
        <p>This will permanently delete all ${allHistory.length} scan records. This cannot be undone.</p>
        <div class="confirm-actions">
          <button class="btn btn-secondary" id="confirm-cancel">Cancel</button>
          <button class="btn btn-danger-outline" id="confirm-clear">Clear All</button>
        </div>
      </div>
    `;

    document.body.appendChild(overlay);

    document.getElementById('confirm-cancel').addEventListener('click', () => overlay.remove());
    overlay.addEventListener('click', (e) => { if (e.target === overlay) overlay.remove(); });

    document.getElementById('confirm-clear').addEventListener('click', () => {
      chrome.runtime.sendMessage({ type: 'CLEAR_HISTORY' }, () => {
        allHistory = [];
        updateStats();
        renderHistory();
        overlay.remove();
      });
    });
  };

  // =========================================================================
  // EVENT LISTENERS
  // =========================================================================

  searchInput.addEventListener('input', renderHistory);

  for (const chip of chips) {
    chip.addEventListener('click', () => {
      for (const c of chips) c.classList.remove('chip-active');
      chip.classList.add('chip-active');
      activeFilter = chip.dataset.filter;
      renderHistory();
    });
  }

  exportBtn.addEventListener('click', exportHistory);
  clearBtn.addEventListener('click', clearHistory);

  // =========================================================================
  // INITIALIZATION
  // =========================================================================

  applyTheme();
  loadHistory();
})();
