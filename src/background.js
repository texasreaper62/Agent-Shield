'use strict';

/**
 * AI Shield Background Service Worker
 *
 * Manages the extension badge, per-tab state, and cumulative statistics.
 * Receives scan results from content scripts and updates the UI accordingly.
 */

// Per-tab scan result storage
const tabResults = new Map();

// Badge colors for each status
const BADGE_COLORS = {
  safe: '#22c55e',     // Green
  caution: '#eab308',  // Yellow
  warning: '#f97316',  // Orange
  danger: '#ef4444'    // Red
};

// Status tooltip text
const TOOLTIP_TEXT = {
  safe: 'AI Shield: This page is safe',
  caution: 'AI Shield: Minor items detected',
  warning: 'AI Shield: Potential AI threats detected',
  danger: 'AI Shield: Dangerous AI threats detected!'
};

// =========================================================================
// BADGE MANAGEMENT
// =========================================================================

/**
 * Updates the extension badge for a specific tab.
 * @param {number} tabId - The tab ID to update.
 * @param {object} result - Scan result from the detector.
 */
const updateBadge = async (tabId, result) => {
  try {
    const { status, stats } = result;

    if (status === 'safe') {
      // Clear badge for safe pages
      await chrome.action.setBadgeText({ text: '', tabId });
    } else {
      // Show threat count on badge
      const count = stats.totalThreats;
      await chrome.action.setBadgeText({
        text: count > 99 ? '99+' : String(count),
        tabId
      });
    }

    // Set badge color
    await chrome.action.setBadgeBackgroundColor({
      color: BADGE_COLORS[status] || BADGE_COLORS.safe,
      tabId
    });

    // Set tooltip
    await chrome.action.setTitle({
      title: TOOLTIP_TEXT[status] || 'AI Shield',
      tabId
    });

  } catch (e) {
    // Tab may have been closed
    console.warn('[AI Shield] Could not update badge for tab', tabId, ':', e.message);
  }
};

/**
 * Clears the badge for a specific tab.
 * @param {number} tabId - The tab ID to clear.
 */
const clearBadge = async (tabId) => {
  try {
    await chrome.action.setBadgeText({ text: '', tabId });
    await chrome.action.setTitle({ title: 'AI Shield - Click to see scan results', tabId });
  } catch (e) {
    // Tab may not exist
  }
};

// =========================================================================
// BROWSER NOTIFICATIONS
// =========================================================================

/**
 * Shows a browser notification for critical threats (if enabled in settings).
 * @param {number} tabId - The tab ID.
 * @param {object} result - Scan result from the detector.
 */
const showCriticalNotification = async (tabId, result) => {
  if (result.stats.critical === 0) return;

  try {
    const data = await chrome.storage.local.get('settings');
    const settings = data.settings || {};
    if (settings.notifications === false) return;

    // Avoid repeat notifications for the same tab/URL
    const notifKey = `notified_${tabId}`;
    const prev = await chrome.storage.session.get(notifKey);
    if (prev[notifKey] === result.url) return;
    await chrome.storage.session.set({ [notifKey]: result.url });

    const notifId = `ai-shield-critical-${tabId}`;
    await chrome.notifications.create(notifId, {
      type: 'basic',
      iconUrl: 'icons/shield-green-128.png',
      title: 'AI Shield: Danger Detected',
      message: `${result.stats.critical} critical threat${result.stats.critical > 1 ? 's' : ''} found on this page. Click the AI Shield icon for details.`,
      priority: 2
    });
  } catch (e) {
    // Notifications API may not be available — fail silently
  }
};

// =========================================================================
// STATISTICS
// =========================================================================

/**
 * Updates cumulative statistics stored in chrome.storage.local.
 * @param {object} result - Scan result from the detector.
 */
const updateStats = async (result) => {
  try {
    const data = await chrome.storage.local.get(['totalScans', 'totalThreatsFound']);
    const totalScans = (data.totalScans || 0) + 1;
    const totalThreatsFound = (data.totalThreatsFound || 0) + result.stats.totalThreats;

    await chrome.storage.local.set({ totalScans, totalThreatsFound });
  } catch (e) {
    console.warn('[AI Shield] Could not update stats:', e.message);
  }
};

// =========================================================================
// SCAN HISTORY
// =========================================================================

/** Maximum history entries to keep. */
const MAX_HISTORY_ENTRIES = 500;

/**
 * Saves a scan result to the history log.
 * Only stores one entry per URL per day to avoid bloat.
 * @param {object} result - Scan result from the detector.
 */
const saveToHistory = async (result) => {
  try {
    const data = await chrome.storage.local.get('scanHistory');
    const history = data.scanHistory || [];

    // Deduplicate: skip if same URL scanned in the last hour
    const oneHourAgo = Date.now() - 3600000;
    const recentDupe = history.find(h =>
      h.url === result.url && h.timestamp > oneHourAgo
    );
    if (recentDupe) {
      // Update the existing entry instead
      recentDupe.status = result.status;
      recentDupe.stats = result.stats;
      recentDupe.threats = result.threats;
      recentDupe.timestamp = result.timestamp;
      await chrome.storage.local.set({ scanHistory: history });
      return;
    }

    // Add new entry (most recent first)
    history.unshift({
      url: result.url,
      hostname: result.hostname,
      status: result.status,
      stats: result.stats,
      threats: result.threats,
      timestamp: result.timestamp
    });

    // Trim to max size
    if (history.length > MAX_HISTORY_ENTRIES) {
      history.length = MAX_HISTORY_ENTRIES;
    }

    await chrome.storage.local.set({ scanHistory: history });
  } catch (e) {
    console.warn('[AI Shield] Could not save to history:', e.message);
  }
};

/**
 * Runs auto-cleanup of history entries older than the configured retention period.
 */
const runAutoCleanup = async () => {
  try {
    const data = await chrome.storage.local.get(['settings', 'scanHistory']);
    const settings = data.settings || {};
    const history = data.scanHistory || [];
    const retentionDays = settings.historyRetention || 90;

    const cutoff = Date.now() - (retentionDays * 86400000);
    const filtered = history.filter(h => h.timestamp > cutoff);

    if (filtered.length < history.length) {
      await chrome.storage.local.set({ scanHistory: filtered });
      console.log(`[AI Shield] Auto-cleanup: removed ${history.length - filtered.length} old history entries.`);
    }
  } catch (e) {
    console.warn('[AI Shield] Auto-cleanup failed:', e.message);
  }
};

// =========================================================================
// MESSAGE HANDLING
// =========================================================================

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'SCAN_COMPLETE' && sender.tab) {
    const tabId = sender.tab.id;
    const result = message.result;

    // Store result per tab
    tabResults.set(tabId, result);

    // Update badge (respect showBadge setting)
    chrome.storage.local.get('settings', (data) => {
      const settings = data.settings || {};
      if (settings.showBadge !== false) {
        updateBadge(tabId, result);
      } else {
        clearBadge(tabId);
      }
    });

    // Update cumulative stats
    updateStats(result);

    // Browser notification for critical threats
    showCriticalNotification(tabId, result);

    // Save to history
    saveToHistory(result);

    sendResponse({ received: true });
    return true;
  }

  if (message.type === 'GET_TAB_RESULT') {
    const tabId = message.tabId;
    const result = tabResults.get(tabId) || null;
    sendResponse(result);
    return true;
  }

  if (message.type === 'GET_STATS') {
    chrome.storage.local.get(['totalScans', 'totalThreatsFound'], (data) => {
      if (chrome.runtime.lastError) {
        sendResponse({ totalScans: 0, totalThreatsFound: 0 });
      } else {
        sendResponse({
          totalScans: data.totalScans || 0,
          totalThreatsFound: data.totalThreatsFound || 0
        });
      }
    });
    return true;
  }

  if (message.type === 'GET_HISTORY') {
    chrome.storage.local.get('scanHistory', (data) => {
      if (chrome.runtime.lastError) {
        sendResponse([]);
      } else {
        sendResponse(data.scanHistory || []);
      }
    });
    return true;
  }

  if (message.type === 'CLEAR_HISTORY') {
    chrome.storage.local.set({ scanHistory: [] }, () => {
      sendResponse({ success: true });
    });
    return true;
  }

  if (message.type === 'DELETE_HISTORY_ENTRY') {
    chrome.storage.local.get('scanHistory', (data) => {
      const history = data.scanHistory || [];
      const filtered = history.filter(h => h.timestamp !== message.timestamp);
      chrome.storage.local.set({ scanHistory: filtered }, () => {
        sendResponse({ success: true });
      });
    });
    return true;
  }

  if (message.type === 'EXPORT_SETTINGS') {
    chrome.storage.local.get('settings', (data) => {
      sendResponse(data.settings || {});
    });
    return true;
  }

  if (message.type === 'IMPORT_SETTINGS') {
    const imported = message.settings;
    chrome.storage.local.set({ settings: imported }, () => {
      sendResponse({ success: true });
    });
    return true;
  }

  if (message.type === 'SETTINGS_CHANGED') {
    const settings = message.settings || {};

    // If scanning was paused, clear all badges
    if (settings.enabled === false) {
      tabResults.forEach((_, tabId) => clearBadge(tabId));
    }

    // If badge display was turned off, clear all badges
    if (settings.showBadge === false) {
      tabResults.forEach((_, tabId) => clearBadge(tabId));
    }

    sendResponse({ received: true });
    return true;
  }
});

// =========================================================================
// TAB LIFECYCLE
// =========================================================================

// Clean up when tab closes
chrome.tabs.onRemoved.addListener((tabId) => {
  tabResults.delete(tabId);
});

// Reset badge when tab navigates to a new page
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === 'loading') {
    tabResults.delete(tabId);
    clearBadge(tabId);
  }
});

// =========================================================================
// INITIALIZATION
// =========================================================================

console.log('[AI Shield] Background service worker started.');

// Run auto-cleanup on startup
runAutoCleanup();

// =========================================================================
// CONTEXT MENU
// =========================================================================

// Create "Scan selection with AI Shield" context menu item
chrome.contextMenus.create({
  id: 'ai-shield-scan-selection',
  title: 'Scan selection with AI Shield',
  contexts: ['selection']
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === 'ai-shield-scan-selection' && tab && tab.id) {
    chrome.tabs.sendMessage(tab.id, {
      type: 'SCAN_SELECTION',
      text: info.selectionText
    });
  }
});

// =========================================================================
// KEYBOARD SHORTCUT
// =========================================================================

chrome.commands.onCommand.addListener((command) => {
  if (command === 'rescan-page') {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs && tabs.length > 0) {
        chrome.tabs.sendMessage(tabs[0].id, { type: 'RESCAN' });
      }
    });
  }
});
