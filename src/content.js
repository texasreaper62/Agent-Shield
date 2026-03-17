'use strict';

/**
 * AI Shield Content Script
 *
 * Runs on every web page. Orchestrates scanning via the detection engine,
 * manages the warning banner, handles messaging with popup and background,
 * and observes DOM mutations for dynamic content.
 */
(() => {
  const BANNER_ID = 'ai-shield-warning-banner';
  const DEBOUNCE_MS = 2000;

  let lastScanResult = null;
  let debounceTimer = null;
  let bannerDismissed = false;

  // =========================================================================
  // WARNING BANNER
  // =========================================================================

  /**
   * Creates and shows the warning banner at the top of the page.
   * @param {object} result - Scan result from the detector.
   */
  const showBanner = (result) => {
    if (bannerDismissed) return;

    // Only show banner for warning or danger status
    if (result.status !== 'warning' && result.status !== 'danger') {
      removeBanner();
      return;
    }

    // Remove existing banner if present
    removeBanner();

    const banner = document.createElement('div');
    banner.id = BANNER_ID;

    const isDanger = result.status === 'danger';
    const bgColor = isDanger ? '#dc2626' : '#f59e0b';
    const statusText = isDanger
      ? 'Danger: This page is actively trying to manipulate AI assistants.'
      : 'Warning: This page contains content that could manipulate AI assistants.';

    const threatCount = result.stats.totalThreats;
    const criticalCount = result.stats.critical;
    const highCount = result.stats.high;

    let detailParts = [];
    if (criticalCount > 0) detailParts.push(`${criticalCount} critical`);
    if (highCount > 0) detailParts.push(`${highCount} high severity`);
    const detailText = detailParts.length > 0
      ? `${threatCount} threat${threatCount !== 1 ? 's' : ''} found (${detailParts.join(', ')}). Click the AI Shield icon for details.`
      : `${threatCount} threat${threatCount !== 1 ? 's' : ''} found. Click the AI Shield icon for details.`;

    banner.innerHTML = `
      <div style="display:flex!important;align-items:center!important;justify-content:space-between!important;max-width:1200px!important;margin:0 auto!important;padding:0 16px!important;">
        <div style="display:flex!important;align-items:center!important;gap:12px!important;flex:1!important;">
          <span style="font-size:24px!important;line-height:1!important;">&#x1F6E1;&#xFE0F;</span>
          <div>
            <div style="font-weight:700!important;font-size:14px!important;margin-bottom:2px!important;">${statusText}</div>
            <div style="font-size:12px!important;opacity:0.9!important;">${detailText}</div>
          </div>
        </div>
        <button id="ai-shield-dismiss" style="background:none!important;border:none!important;color:white!important;font-size:20px!important;cursor:pointer!important;padding:4px 8px!important;opacity:0.8!important;line-height:1!important;" aria-label="Dismiss warning">&times;</button>
      </div>
    `;

    // Apply styles directly to avoid any page CSS interference
    const styles = {
      position: 'fixed',
      top: '0',
      left: '0',
      right: '0',
      zIndex: '2147483647',
      backgroundColor: bgColor,
      color: 'white',
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
      fontSize: '14px',
      padding: '10px 0',
      boxShadow: '0 2px 8px rgba(0,0,0,0.3)',
      transform: 'translateY(-100%)',
      transition: 'transform 0.3s ease-out',
      lineHeight: '1.4'
    };

    for (const [prop, val] of Object.entries(styles)) {
      banner.style.setProperty(prop, val, 'important');
    }

    document.documentElement.appendChild(banner);

    // Trigger slide-down animation
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        banner.style.setProperty('transform', 'translateY(0)', 'important');
      });
    });

    // Dismiss button handler
    const dismissBtn = document.getElementById('ai-shield-dismiss');
    if (dismissBtn) {
      dismissBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        bannerDismissed = true;
        removeBanner();
      });
    }
  };

  /**
   * Removes the warning banner from the page.
   */
  const removeBanner = () => {
    const existing = document.getElementById(BANNER_ID);
    if (existing) {
      existing.remove();
    }
  };

  // =========================================================================
  // SCANNING
  // =========================================================================

  /**
   * Runs a scan and processes the results.
   */
  /**
   * Reads settings and runs scan if appropriate.
   * Checks: enabled state, domain allowlist, sensitivity level.
   */
  const runScan = () => {
    try {
      if (typeof AIShieldDetector === 'undefined') {
        console.error('[AI Shield] Detector not loaded.');
        return;
      }

      // Load settings and check before scanning
      chrome.storage.local.get('settings', (data) => {
        const settings = data.settings || {};

        // Check if scanning is enabled
        if (settings.enabled === false) {
          console.log('[AI Shield] Scanning is paused.');
          return;
        }

        // Check allowlist
        const hostname = window.location.hostname.toLowerCase().replace(/^www\./, '');
        const allowlist = settings.allowlist || [];
        if (allowlist.some(domain => hostname === domain || hostname.endsWith('.' + domain))) {
          console.log(`[AI Shield] ${hostname} is in trusted sites list. Skipping scan.`);
          lastScanResult = {
            status: 'safe',
            threats: [],
            stats: { totalThreats: 0, critical: 0, high: 0, medium: 0, low: 0, scanTimeMs: 0 },
            url: window.location.href,
            hostname: hostname,
            timestamp: Date.now(),
            skipped: true,
            skipReason: 'trusted_site'
          };
          removeBanner();
          return;
        }

        // Run scan with sensitivity setting
        const sensitivity = settings.sensitivity || 'medium';
        const result = AIShieldDetector.scan({ sensitivity });
        lastScanResult = result;

        // Show/hide warning banner (respect showBanner setting)
        if (settings.showBanner !== false) {
          showBanner(result);
        } else {
          removeBanner();
        }

        // Send results to background script
        try {
          chrome.runtime.sendMessage({
            type: 'SCAN_COMPLETE',
            result: result
          });
        } catch (e) {
          console.warn('[AI Shield] Could not send scan results to background:', e.message);
        }

        // Store in local storage for popup retrieval
        try {
          chrome.storage.local.set({
            [`scan_${result.url}`]: result,
            lastScanResult: result
          });
        } catch (e) {
          console.warn('[AI Shield] Could not store scan results:', e.message);
        }
      });

    } catch (e) {
      console.error('[AI Shield] Scan failed:', e);
    }
  };

  /**
   * Debounced scan — waits for DOM mutations to settle before re-scanning.
   */
  const debouncedScan = () => {
    if (debounceTimer) clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      pendingBatches = 0;
      console.log('[AI Shield] Re-scanning after DOM change...');
      runScan();
    }, DEBOUNCE_MS);
  };

  // =========================================================================
  // MESSAGING
  // =========================================================================

  /**
   * Listen for messages from popup and background.
   */
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'GET_SCAN_RESULT') {
      if (lastScanResult) {
        sendResponse(lastScanResult);
      } else {
        // Run a scan if we don't have results yet
        runScan();
        sendResponse(lastScanResult);
      }
      return true;
    }

    if (message.type === 'RESCAN') {
      bannerDismissed = false;
      runScan();
      sendResponse(lastScanResult);
      return true;
    }
  });

  // =========================================================================
  // DOM MUTATION OBSERVER
  // =========================================================================

  /**
   * Observe DOM changes and trigger re-scans for dynamically loaded content.
   * Tracks the size of mutations to avoid rescanning for trivial changes.
   */
  let mutationObserver = null;

  /** Maximum number of mutation batches to accumulate before forcing a rescan. */
  const MAX_PENDING_BATCHES = 10;

  let pendingBatches = 0;

  const setupMutationObserver = () => {
    mutationObserver = new MutationObserver((mutations) => {
      // Check if meaningful content was added (skip our own banner)
      let hasNewContent = false;
      for (const mutation of mutations) {
        if (mutation.type === 'childList') {
          for (const node of mutation.addedNodes) {
            if (node.nodeType === Node.ELEMENT_NODE && node.id !== BANNER_ID) {
              hasNewContent = true;
              break;
            }
          }
        }
        if (hasNewContent) break;
      }

      if (!hasNewContent) return;

      pendingBatches++;

      // Force immediate scan if too many batches have accumulated
      if (pendingBatches >= MAX_PENDING_BATCHES) {
        if (debounceTimer) clearTimeout(debounceTimer);
        pendingBatches = 0;
        console.log('[AI Shield] Re-scanning after significant DOM changes...');
        runScan();
      } else {
        debouncedScan();
      }
    });

    mutationObserver.observe(document.documentElement, {
      childList: true,
      subtree: true
    });
  };

  // =========================================================================
  // INITIALIZATION
  // =========================================================================

  console.log('[AI Shield] Content script loaded.');

  // Run initial scan
  runScan();

  // Set up mutation observer for dynamic content
  setupMutationObserver();

  // Clean up on page unload
  window.addEventListener('beforeunload', () => {
    if (debounceTimer) clearTimeout(debounceTimer);
    if (mutationObserver) mutationObserver.disconnect();
  });

})();
