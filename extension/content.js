// Live Phishing Detection Content Script

(function () {
  let warningOverlayInstance = null;

  // Listen for messages from background script
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === "SHOW_WARNING_OVERLAY") {
      renderWarningOverlay(message.data);
      sendResponse({ status: "overlay_displayed" });
    }
  });

  function renderWarningOverlay(data) {
    if (warningOverlayInstance) return; // Prevent duplicate overlays

    const overlay = document.createElement("div");
    overlay.id = "phishing-detection-overlay-container";

    const breakdownItems = (data.breakdown || [])
      .map(item => `<li><strong>${item.feature}:</strong> ${item.detail}</li>`)
      .join("");

    overlay.innerHTML = `
      <div id="phishing-detection-card">
        <div class="phishing-header-badge">
          <span>⚠️ Security Warning</span>
        </div>
        <div class="phishing-icon-shield">🛡️</div>
        <h1 class="phishing-title">Deceptive Site Blocked</h1>
        <p class="phishing-description">
          Our AI Machine Learning Classifier detected that <strong>${data.domain}</strong> presents a high risk of phishing, credentials theft, or fraud.
        </p>

        <div class="phishing-risk-box">
          <div class="phishing-risk-header">
            <span>Threat Probability:</span>
            <span class="phishing-threat-score">${data.risk_score}% Risk</span>
          </div>
          <ul class="phishing-features-list">
            ${breakdownItems || "<li>Suspicious structural patterns matched phishing datasets</li>"}
          </ul>
        </div>

        <div class="phishing-actions-group">
          <button id="btn-go-safe" class="phishing-btn-primary">
            🛡️ Go Back to Safety (Recommended)
          </button>
          <button id="btn-whitelist-site" class="phishing-btn-secondary">
            ✅ Trust & Whitelist Domain
          </button>
          <button id="btn-proceed-anyways" class="phishing-btn-secondary">
            ⚠️ Ignore Warning & Proceed Anyways
          </button>
        </div>
      </div>
    `;

    document.documentElement.appendChild(overlay);
    warningOverlayInstance = overlay;

    // Attach Event Handlers
    document.getElementById("btn-go-safe").addEventListener("click", () => {
      window.location.href = "https://www.google.com";
    });

    document.getElementById("btn-proceed-anyways").addEventListener("click", () => {
      chrome.runtime.sendMessage({ action: "PROCEED_ANYWAYS", domain: data.domain }, () => {
        if (warningOverlayInstance) {
          warningOverlayInstance.remove();
          warningOverlayInstance = null;
        }
      });
    });

    document.getElementById("btn-whitelist-site").addEventListener("click", async () => {
      try {
        const result = await chrome.storage.local.get(["apiUrl"]);
        const apiUrl = result.apiUrl || "http://127.0.0.1:8000";
        await fetch(`${apiUrl}/api/v1/whitelist`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ domain: data.domain })
        });
        chrome.runtime.sendMessage({ action: "RESCAN_CURRENT_TAB" });
        if (warningOverlayInstance) {
          warningOverlayInstance.remove();
          warningOverlayInstance = null;
        }
      } catch (e) {
        alert("Could not reach Whitelist API backend.");
      }
    });
  }
})();
