document.addEventListener("DOMContentLoaded", async () => {
  let currentScanData = null;
  let activeTab = null;
  const DEFAULT_API_URL = "http://127.0.0.1:8000";

  // Navigation Tabs logic
  const tabBtns = document.querySelectorAll(".tab-btn");
  const tabContents = document.querySelectorAll(".tab-content");

  tabBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      tabBtns.forEach(b => b.classList.remove("active"));
      tabContents.forEach(c => c.classList.remove("active"));
      btn.classList.add("active");
      const target = btn.getAttribute("data-tab");
      document.getElementById(target).classList.add("active");

      if (target === "tab-history") {
        fetchScanHistory();
      }
    });
  });

  // Get active tab URL
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  activeTab = tabs[0];

  if (!activeTab || !activeTab.url || !activeTab.url.startsWith("http")) {
    renderEmptyTabState("Extension active on browser internal pages. Open a web domain to scan.");
    return;
  }

  const domain = new URL(activeTab.url).hostname;
  document.getElementById("domain-name").textContent = domain;
  document.getElementById("url-subtext").textContent = activeTab.url;

  // Retrieve cached scan result from storage
  const storageData = await chrome.storage.local.get([`scan_${activeTab.id}`, "apiUrl"]);
  const apiUrl = storageData.apiUrl || DEFAULT_API_URL;

  if (storageData[`scan_${activeTab.id}`]) {
    currentScanData = storageData[`scan_${activeTab.id}`];
    renderScanResults(currentScanData);
  } else {
    // Run immediate scan request
    fetchLiveScan(activeTab.url, apiUrl);
  }

  // Check Backend Connection Status
  checkBackendHealth(apiUrl);

  // Event Listeners
  document.getElementById("btn-open-settings").addEventListener("click", () => {
    chrome.runtime.openOptionsPage();
  });

  document.getElementById("btn-rescan").addEventListener("click", () => {
    fetchLiveScan(activeTab.url, apiUrl);
  });

  document.getElementById("btn-toggle-whitelist").addEventListener("click", () => {
    toggleWhitelist(domain, apiUrl);
  });

  // Report Modal handlers
  const reportModal = document.getElementById("report-modal");
  document.getElementById("btn-show-report-modal").addEventListener("click", () => {
    reportModal.classList.remove("hidden");
  });
  document.getElementById("btn-cancel-report").addEventListener("click", () => {
    reportModal.classList.add("hidden");
  });

  document.getElementById("btn-submit-report").addEventListener("click", async () => {
    const comments = document.getElementById("report-comments").value;
    try {
      const res = await fetch(`${apiUrl}/api/v1/report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: activeTab.url, comments })
      });
      if (res.ok) {
        alert("Phishing report submitted successfully!");
        reportModal.classList.add("hidden");
        document.getElementById("report-comments").value = "";
      }
    } catch (err) {
      alert("Failed to submit report. Please verify FastAPI backend server.");
    }
  });

  document.getElementById("btn-refresh-history").addEventListener("click", () => {
    fetchScanHistory(apiUrl);
  });

  // Helper Functions
  async function fetchLiveScan(url, apiUrl) {
    document.getElementById("badge-text").textContent = "SCANNING...";
    try {
      const res = await fetch(`${apiUrl}/api/v1/predict`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url })
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      currentScanData = data;
      chrome.storage.local.set({ [`scan_${activeTab.id}`]: data });
      renderScanResults(data);
    } catch (err) {
      console.error("Scan error:", err);
      renderErrorState("Backend API unreachable");
    }
  }

  function renderScanResults(data) {
    const riskScore = data.risk_score || 0.0;
    const classification = data.classification || "Safe";

    // 1. Update Gauge
    document.getElementById("risk-score-value").textContent = Math.round(riskScore);
    const gaugeFill = document.getElementById("gauge-fill");
    // stroke-dasharray is 264
    const offset = 264 - (264 * (riskScore / 100));
    gaugeFill.style.strokeDashoffset = offset;

    // Gauge color change based on threat level
    if (classification === "Phishing") {
      gaugeFill.style.stroke = "#ef4444";
    } else if (classification === "Suspicious") {
      gaugeFill.style.stroke = "#f59e0b";
    } else {
      gaugeFill.style.stroke = "#10b981";
    }

    // 2. Update Badge
    const badge = document.getElementById("status-badge");
    const badgeText = document.getElementById("badge-text");
    badge.className = "status-badge";

    if (classification === "Phishing") {
      badge.classList.add("badge-phishing");
      badgeText.textContent = "PHISHING THREAT";
    } else if (classification === "Suspicious") {
      badge.classList.add("badge-suspicious");
      badgeText.textContent = "SUSPICIOUS";
    } else {
      badge.classList.add("badge-safe");
      badgeText.textContent = data.is_whitelisted ? "TRUSTED WHITELIST" : "SAFE WEBSITE";
    }

    // 3. Update Whitelist Button text
    const whitelistBtn = document.getElementById("btn-toggle-whitelist");
    if (data.is_whitelisted) {
      whitelistBtn.textContent = "Remove Whitelist";
      whitelistBtn.className = "btn-action btn-danger";
    } else {
      whitelistBtn.textContent = "Whitelist Site";
      whitelistBtn.className = "btn-action btn-outline";
    }

    // 4. Render Breakdown Cards
    const breakdownList = document.getElementById("breakdown-list");
    breakdownList.innerHTML = "";

    if (!data.breakdown || data.breakdown.length === 0) {
      breakdownList.innerHTML = '<div class="empty-state">✅ No security anomalies or deceptive patterns detected.</div>';
    } else {
      data.breakdown.forEach(item => {
        const card = document.createElement("div");
        card.className = `breakdown-card risk-${item.risk.toLowerCase()}`;
        card.innerHTML = `
          <div class="breakdown-title">${item.feature}</div>
          <div class="breakdown-detail">${item.detail}</div>
        `;
        breakdownList.appendChild(card);
      });
    }
  }

  async function toggleWhitelist(domain, apiUrl) {
    const isWhitelisted = currentScanData && currentScanData.is_whitelisted;
    const method = isWhitelisted ? "DELETE" : "POST";
    const endpoint = isWhitelisted ? `${apiUrl}/api/v1/whitelist/${domain}` : `${apiUrl}/api/v1/whitelist`;
    const body = isWhitelisted ? null : JSON.stringify({ domain });

    try {
      const res = await fetch(endpoint, {
        method,
        headers: { "Content-Type": "application/json" },
        body
      });
      if (res.ok) {
        // Rescan tab to reflect whitelist status change
        chrome.runtime.sendMessage({ action: "RESCAN_CURRENT_TAB" });
        setTimeout(() => fetchLiveScan(activeTab.url, apiUrl), 300);
      }
    } catch (err) {
      alert("Failed to update whitelist.");
    }
  }

  async function fetchScanHistory(apiUrl) {
    const targetUrl = apiUrl || DEFAULT_API_URL;
    const historyContainer = document.getElementById("history-list");
    historyContainer.innerHTML = '<div class="empty-state">Loading history...</div>';

    try {
      const res = await fetch(`${targetUrl}/api/v1/history?limit=15`);
      const data = await res.json();

      if (!data.history || data.history.length === 0) {
        historyContainer.innerHTML = '<div class="empty-state">No scan history recorded yet.</div>';
        return;
      }

      historyContainer.innerHTML = "";
      data.history.forEach(item => {
        const row = document.createElement("div");
        row.className = "history-item";
        const tagClass = item.classification === "Phishing" ? "tag-phishing" : (item.classification === "Suspicious" ? "tag-suspicious" : "tag-safe");
        row.innerHTML = `
          <div>
            <div class="history-domain">${item.domain}</div>
            <div style="font-size:10px; color:#64748b;">${new Date(item.scanned_at).toLocaleTimeString()}</div>
          </div>
          <span class="history-tag ${tagClass}">${Math.round(item.risk_score)}% ${item.classification}</span>
        `;
        historyContainer.appendChild(row);
      });
    } catch (err) {
      historyContainer.innerHTML = '<div class="empty-state">Failed to load history logs.</div>';
    }
  }

  async function checkBackendHealth(apiUrl) {
    const dot = document.getElementById("backend-status-dot");
    try {
      const res = await fetch(`${apiUrl}/`);
      if (res.ok) {
        dot.className = "status-dot online";
        dot.title = "Backend Server Online";
      } else {
        dot.className = "status-dot offline";
      }
    } catch (e) {
      dot.className = "status-dot offline";
      dot.title = "Backend Server Offline";
    }
  }

  function renderEmptyTabState(msg) {
    document.getElementById("domain-name").textContent = "Browser System Page";
    document.getElementById("url-subtext").textContent = msg;
    document.getElementById("risk-score-value").textContent = "0";
    document.getElementById("badge-text").textContent = "INACTIVE";
  }

  function renderErrorState(msg) {
    document.getElementById("badge-text").textContent = "API ERROR";
    document.getElementById("status-badge").className = "status-badge badge-neutral";
    document.getElementById("breakdown-list").innerHTML = `<div class="empty-state">⚠️ ${msg}. Ensure FastAPI server is running on http://127.0.0.1:8000</div>`;
  }
});
