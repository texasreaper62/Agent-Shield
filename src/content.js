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
  let pendingBatches = 0;

  /**
   * Escapes HTML special characters to prevent XSS.
   * @param {string} text - Text to escape.
   * @returns {string} Escaped text.
   */
  const escapeDiv = document.createElement('div');
  const escapeHtml = (text) => {
    escapeDiv.textContent = text;
    return escapeDiv.innerHTML;
  };

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
  // SELECTION SCAN OVERLAY
  // =========================================================================

  const OVERLAY_ID = 'ai-shield-selection-overlay';

  /**
   * Shows a floating overlay with scan results for selected text.
   * @param {object} result - Scan result from scanText.
   */
  const showSelectionOverlay = (result) => {
    removeSelectionOverlay();

    const overlay = document.createElement('div');
    overlay.id = OVERLAY_ID;

    const isSafe = result.status === 'safe';
    const bgColor = isSafe ? '#161b22' : (result.status === 'danger' ? '#dc2626' : (result.status === 'warning' ? '#f97316' : '#eab308'));
    const borderColor = isSafe ? '#22c55e' : bgColor;

    let statusText;
    if (isSafe) {
      statusText = 'No AI threats found in selected text.';
    } else {
      const count = result.stats.totalThreats;
      statusText = `${count} threat${count !== 1 ? 's' : ''} found in selected text.`;
    }

    let threatHtml = '';
    if (result.threats.length > 0) {
      const items = result.threats.slice(0, 5).map(t => {
        const sevColor = t.severity === 'critical' ? '#ef4444' : t.severity === 'high' ? '#f97316' : t.severity === 'medium' ? '#eab308' : '#22c55e';
        return `<div style="margin-top:6px!important;font-size:12px!important;color:#e6edf3!important;"><span style="color:${sevColor}!important;font-weight:700!important;text-transform:uppercase!important;font-size:10px!important;">${escapeHtml(t.severity)}</span> ${escapeHtml(t.description)}</div>`;
      }).join('');
      threatHtml = items;
    }

    overlay.innerHTML = `
      <div style="display:flex!important;align-items:flex-start!important;justify-content:space-between!important;gap:8px!important;">
        <div style="flex:1!important;">
          <div style="font-weight:700!important;font-size:13px!important;margin-bottom:4px!important;color:${isSafe ? '#22c55e' : 'white'}!important;">${isSafe ? '&#x2705;' : '&#x26A0;&#xFE0F;'} ${statusText}</div>
          ${threatHtml}
        </div>
        <button id="ai-shield-overlay-close" style="background:none!important;border:none!important;color:#8b949e!important;font-size:18px!important;cursor:pointer!important;padding:0 4px!important;line-height:1!important;" aria-label="Close">&times;</button>
      </div>
    `;

    const styles = {
      position: 'fixed',
      bottom: '20px',
      right: '20px',
      zIndex: '2147483646',
      backgroundColor: '#0d1117',
      color: '#e6edf3',
      border: `2px solid ${borderColor}`,
      borderRadius: '10px',
      padding: '14px 16px',
      maxWidth: '380px',
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
      fontSize: '13px',
      lineHeight: '1.4',
      boxShadow: '0 4px 16px rgba(0,0,0,0.5)',
      opacity: '0',
      transform: 'translateY(10px)',
      transition: 'opacity 0.2s ease, transform 0.2s ease'
    };

    for (const [prop, val] of Object.entries(styles)) {
      overlay.style.setProperty(prop, val, 'important');
    }

    document.documentElement.appendChild(overlay);

    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        overlay.style.setProperty('opacity', '1', 'important');
        overlay.style.setProperty('transform', 'translateY(0)', 'important');
      });
    });

    const closeBtn = document.getElementById('ai-shield-overlay-close');
    if (closeBtn) {
      closeBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        removeSelectionOverlay();
      });
    }

    // Auto-dismiss after 8 seconds
    setTimeout(removeSelectionOverlay, 8000);
  };

  /**
   * Removes the selection scan overlay.
   */
  const removeSelectionOverlay = () => {
    const existing = document.getElementById(OVERLAY_ID);
    if (existing) existing.remove();
  };

  // =========================================================================
  // PASTE SCANNING
  // =========================================================================

  /**
   * Monitors paste events and warns if pasted content contains threats.
   */
  const setupPasteScanning = () => {
    document.addEventListener('paste', (e) => {
      try {
        if (typeof AIShieldDetector === 'undefined') return;

        const text = (e.clipboardData || window.clipboardData).getData('text');
        if (!text || text.trim().length < 20) return;

        const result = AIShieldDetector.scanText({
          text: text,
          source: 'pasted text',
          sensitivity: 'medium'
        });

        if (result.status !== 'safe') {
          showSelectionOverlay(result);
        }
      } catch (err) {
        // Fail silently — don't interfere with paste
      }
    }, true);
  };

  // =========================================================================
  // FORM INPUT MONITORING
  // =========================================================================

  /**
   * Scans pre-filled form inputs for hidden injections.
   * Only checks hidden inputs and inputs with suspicious pre-filled values.
   */
  const scanFormInputs = () => {
    try {
      if (typeof AIShieldDetector === 'undefined') return;

      const hiddenInputs = document.querySelectorAll(
        'input[type="hidden"], textarea[style*="display:none"], textarea[style*="visibility:hidden"]'
      );

      for (const input of hiddenInputs) {
        const val = input.value || '';
        if (val.length < 20) continue;

        const result = AIShieldDetector.scanText({
          text: val,
          source: 'hidden form field',
          sensitivity: 'medium'
        });

        if (result.threats.length > 0) {
          // Merge threats into the page scan result
          if (lastScanResult && lastScanResult.threats) {
            for (const threat of result.threats) {
              const isDupe = lastScanResult.threats.some(t =>
                t.description === threat.description && t.category === threat.category
              );
              if (!isDupe) {
                lastScanResult.threats.push(threat);
                lastScanResult.stats.totalThreats++;
                lastScanResult.stats[threat.severity]++;
              }
            }
          }
        }
      }
    } catch (err) {
      console.warn('[AI Shield] Form input scan failed:', err.message);
    }
  };

  // =========================================================================
  // SUSPICIOUS LINK HIGHLIGHTING
  // =========================================================================

  /** Known AI/tech brand domains for phishing detection. */
  const BRAND_DOMAINS = {
    'openai.com': 'OpenAI',
    'chat.openai.com': 'ChatGPT',
    'anthropic.com': 'Anthropic',
    'claude.ai': 'Claude',
    'google.com': 'Google',
    'bard.google.com': 'Bard',
    'gemini.google.com': 'Gemini',
    'microsoft.com': 'Microsoft',
    'copilot.microsoft.com': 'Copilot',
    'github.com': 'GitHub'
  };

  /** Common homoglyph/typosquat patterns. */
  const SUSPICIOUS_PATTERNS = [
    /\.ru\//i,
    /\.cn\//i,
    /bit\.ly/i,
    /tinyurl\.com/i,
    /login|signin|verify|confirm|secure|account|update/i
  ];

  /**
   * Checks if a URL looks like a phishing attempt targeting known AI brands.
   * @param {string} href - The link URL.
   * @returns {{suspicious: boolean, reason: string}} Result.
   */
  const checkLinkSuspicion = (href) => {
    if (!href) return { suspicious: false, reason: '' };

    try {
      // Check data: and javascript: URIs
      if (/^(data|javascript):/i.test(href)) {
        return { suspicious: true, reason: 'Uses a potentially dangerous URL scheme.' };
      }

      const url = new URL(href, window.location.href);
      const host = url.hostname.toLowerCase();

      // Skip same-domain links
      if (host === window.location.hostname) return { suspicious: false, reason: '' };

      // Check for brand impersonation (e.g., openai-login.evil.com)
      for (const [domain, brand] of Object.entries(BRAND_DOMAINS)) {
        const brandWord = domain.split('.')[0];
        if (host !== domain && !host.endsWith('.' + domain) && host.includes(brandWord)) {
          return { suspicious: true, reason: `May be impersonating ${brand} (${domain}).` };
        }
      }

      // Check for suspicious URL keywords (login/verify pages on external sites)
      const fullUrl = url.href.toLowerCase();
      if (/\/(login|signin|verify|confirm|auth|secure|account)/.test(url.pathname) &&
          !BRAND_DOMAINS[host]) {
        // Only flag if the link text mentions a brand
        return { suspicious: false, reason: '', flagIfBrandText: true };
      }

      // Check for suspicious patterns
      for (const pattern of SUSPICIOUS_PATTERNS) {
        if (pattern.test(fullUrl)) {
          return { suspicious: true, reason: 'Link has suspicious URL characteristics.' };
        }
      }

      return { suspicious: false, reason: '' };
    } catch (e) {
      return { suspicious: false, reason: '' };
    }
  };

  /**
   * Scans all links on the page and highlights suspicious ones.
   */
  const scanLinks = () => {
    const links = document.querySelectorAll('a[href]');
    let flaggedCount = 0;

    for (const link of links) {
      // Skip already-processed links
      if (link.dataset.aiShieldChecked) continue;
      link.dataset.aiShieldChecked = 'true';

      const href = link.getAttribute('href');
      const result = checkLinkSuspicion(href);

      // Check if link text mentions a brand while pointing elsewhere
      if (!result.suspicious && result.flagIfBrandText) {
        const text = (link.textContent || '').toLowerCase();
        for (const [domain, brand] of Object.entries(BRAND_DOMAINS)) {
          if (text.includes(brand.toLowerCase()) || text.includes(domain.split('.')[0])) {
            result.suspicious = true;
            result.reason = `Link text mentions "${brand}" but points to a different site.`;
            break;
          }
        }
      }

      if (result.suspicious) {
        flaggedCount++;
        link.style.setProperty('outline', '2px dashed #f97316', 'important');
        link.style.setProperty('outline-offset', '2px', 'important');
        link.style.setProperty('position', 'relative', 'important');
        link.title = `[AI Shield] ${result.reason}`;
      }
    }

    if (flaggedCount > 0) {
      console.log(`[AI Shield] Flagged ${flaggedCount} suspicious link${flaggedCount !== 1 ? 's' : ''}.`);
    }
  };

  // =========================================================================
  // MESSAGING
  // =========================================================================

  /**
   * Listen for messages from popup and background.
   */
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'GET_SCAN_RESULT') {
      if (!lastScanResult) {
        // Trigger a scan; results will be sent via SCAN_COMPLETE when ready
        runScan();
      }
      sendResponse(lastScanResult);
      return true;
    }

    if (message.type === 'RESCAN') {
      bannerDismissed = false;
      runScan();
      sendResponse(lastScanResult);
      return true;
    }

    if (message.type === 'SCAN_SELECTION') {
      try {
        if (typeof AIShieldDetector === 'undefined') return true;
        const result = AIShieldDetector.scanText({
          text: message.text,
          source: 'selected text (context menu)',
          sensitivity: 'medium'
        });
        showSelectionOverlay(result);
      } catch (err) {
        console.warn('[AI Shield] Selection scan failed:', err.message);
      }
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

  // Scan pre-filled form inputs
  scanFormInputs();

  // Set up paste monitoring
  setupPasteScanning();

  // Scan links for suspicious URLs
  scanLinks();

  // Set up mutation observer for dynamic content
  setupMutationObserver();

  // Clean up on page unload
  window.addEventListener('beforeunload', () => {
    if (debounceTimer) clearTimeout(debounceTimer);
    if (mutationObserver) mutationObserver.disconnect();
  });

})();
