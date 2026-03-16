'use strict';

/**
 * AI Shield Options Page Script
 *
 * Manages user settings: sensitivity level, domain allowlist,
 * and notification preferences.
 */
(() => {
  // =========================================================================
  // DEFAULT SETTINGS
  // =========================================================================

  const DEFAULTS = {
    sensitivity: 'medium',
    allowlist: [],
    showBanner: true,
    showBadge: true,
    enabled: true
  };

  // =========================================================================
  // DOM ELEMENTS
  // =========================================================================

  const sensitivityRadios = document.querySelectorAll('input[name="sensitivity"]');
  const allowlistInput = document.getElementById('allowlist-input');
  const allowlistAddBtn = document.getElementById('allowlist-add-btn');
  const allowlistError = document.getElementById('allowlist-error');
  const allowlistContainer = document.getElementById('allowlist-container');
  const allowlistEmpty = document.getElementById('allowlist-empty');
  const showBannerToggle = document.getElementById('show-banner');
  const showBadgeToggle = document.getElementById('show-badge');
  const saveStatus = document.getElementById('save-status');

  // =========================================================================
  // SETTINGS MANAGEMENT
  // =========================================================================

  /**
   * Loads settings from chrome.storage.local and populates the UI.
   */
  const loadSettings = () => {
    chrome.storage.local.get('settings', (data) => {
      const settings = Object.assign({}, DEFAULTS, data.settings || {});

      // Set sensitivity
      const radio = document.getElementById(`sensitivity-${settings.sensitivity}`);
      if (radio) radio.checked = true;

      // Set toggles
      showBannerToggle.checked = settings.showBanner;
      showBadgeToggle.checked = settings.showBadge;

      // Render allowlist
      renderAllowlist(settings.allowlist);
    });
  };

  /**
   * Saves current settings to chrome.storage.local.
   */
  const saveSettings = () => {
    const sensitivity = document.querySelector('input[name="sensitivity"]:checked').value;

    chrome.storage.local.get('settings', (data) => {
      const settings = Object.assign({}, DEFAULTS, data.settings || {});
      settings.sensitivity = sensitivity;
      settings.showBanner = showBannerToggle.checked;
      settings.showBadge = showBadgeToggle.checked;

      chrome.storage.local.set({ settings }, () => {
        showSaveConfirmation();

        // Notify background script of settings change
        chrome.runtime.sendMessage({
          type: 'SETTINGS_CHANGED',
          settings: settings
        });
      });
    });
  };

  /**
   * Shows a brief save confirmation message.
   */
  const showSaveConfirmation = () => {
    saveStatus.style.display = 'block';
    setTimeout(() => {
      saveStatus.style.display = 'none';
    }, 2000);
  };

  // =========================================================================
  // ALLOWLIST MANAGEMENT
  // =========================================================================

  /**
   * Validates a domain string.
   * @param {string} domain - The domain to validate.
   * @returns {string|null} Cleaned domain or null if invalid.
   */
  const validateDomain = (domain) => {
    // Strip protocol, path, and whitespace
    let cleaned = domain.trim()
      .replace(/^https?:\/\//, '')
      .replace(/^www\./, '')
      .replace(/\/.*$/, '')
      .toLowerCase();

    if (!cleaned) return null;

    // Basic domain validation
    const domainRegex = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*\.[a-z]{2,}$/;
    if (!domainRegex.test(cleaned)) return null;

    return cleaned;
  };

  /**
   * Adds a domain to the allowlist.
   */
  const addToAllowlist = () => {
    const raw = allowlistInput.value;
    const domain = validateDomain(raw);

    if (!domain) {
      showError('Please enter a valid domain (e.g., example.com).');
      return;
    }

    chrome.storage.local.get('settings', (data) => {
      const settings = Object.assign({}, DEFAULTS, data.settings || {});
      const allowlist = settings.allowlist || [];

      if (allowlist.includes(domain)) {
        showError('This domain is already in your trusted list.');
        return;
      }

      allowlist.push(domain);
      settings.allowlist = allowlist;

      chrome.storage.local.set({ settings }, () => {
        allowlistInput.value = '';
        hideError();
        renderAllowlist(allowlist);
        showSaveConfirmation();

        chrome.runtime.sendMessage({
          type: 'SETTINGS_CHANGED',
          settings: settings
        });
      });
    });
  };

  /**
   * Removes a domain from the allowlist.
   * @param {string} domain - The domain to remove.
   */
  const removeFromAllowlist = (domain) => {
    chrome.storage.local.get('settings', (data) => {
      const settings = Object.assign({}, DEFAULTS, data.settings || {});
      settings.allowlist = (settings.allowlist || []).filter(d => d !== domain);

      chrome.storage.local.set({ settings }, () => {
        renderAllowlist(settings.allowlist);
        showSaveConfirmation();

        chrome.runtime.sendMessage({
          type: 'SETTINGS_CHANGED',
          settings: settings
        });
      });
    });
  };

  /**
   * Renders the allowlist in the UI.
   * @param {Array<string>} allowlist - Array of domain strings.
   */
  const renderAllowlist = (allowlist) => {
    // Clear existing items (but keep empty state element)
    const items = allowlistContainer.querySelectorAll('.allowlist-item');
    for (const item of items) item.remove();

    if (!allowlist || allowlist.length === 0) {
      allowlistEmpty.style.display = 'block';
      return;
    }

    allowlistEmpty.style.display = 'none';

    for (const domain of allowlist) {
      const item = document.createElement('div');
      item.className = 'allowlist-item';
      item.innerHTML = `
        <span class="allowlist-domain">${escapeHtml(domain)}</span>
        <button class="btn btn-danger" data-domain="${escapeHtml(domain)}">Remove</button>
      `;

      const removeBtn = item.querySelector('button');
      removeBtn.addEventListener('click', () => removeFromAllowlist(domain));

      allowlistContainer.appendChild(item);
    }
  };

  // =========================================================================
  // UTILITY FUNCTIONS
  // =========================================================================

  /**
   * Escapes HTML special characters.
   * @param {string} text - Text to escape.
   * @returns {string} Escaped text.
   */
  const escapeHtml = (text) => {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  };

  /**
   * Shows an error message below the allowlist input.
   * @param {string} message - Error message to display.
   */
  const showError = (message) => {
    allowlistError.textContent = message;
    allowlistError.style.display = 'block';
  };

  /**
   * Hides the error message.
   */
  const hideError = () => {
    allowlistError.style.display = 'none';
  };

  // =========================================================================
  // EVENT LISTENERS
  // =========================================================================

  // Sensitivity radio changes
  for (const radio of sensitivityRadios) {
    radio.addEventListener('change', saveSettings);
  }

  // Toggle changes
  showBannerToggle.addEventListener('change', saveSettings);
  showBadgeToggle.addEventListener('change', saveSettings);

  // Allowlist add
  allowlistAddBtn.addEventListener('click', addToAllowlist);
  allowlistInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      addToAllowlist();
    }
  });

  // Clear error on input
  allowlistInput.addEventListener('input', hideError);

  // =========================================================================
  // INITIALIZATION
  // =========================================================================

  loadSettings();
})();
