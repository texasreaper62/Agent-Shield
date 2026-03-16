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
