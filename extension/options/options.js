document.addEventListener("DOMContentLoaded", async () => {
  const DEFAULT_API_URL = "http://127.0.0.1:8000";
  let currentApiUrl = DEFAULT_API_URL;
  let whitelistCache = [];

  // Load Saved API URL & Settings from Storage
  const storage = await chrome.storage.local.get(["apiUrl", "warningThreshold"]);
  if (storage.apiUrl) {
    currentApiUrl = storage.apiUrl;
    document.getElementById("api-url-input").value = currentApiUrl;
  } else {
    document.getElementById("api-url-input").value = DEFAULT_API_URL;
  }

  if (storage.warningThreshold) {
    document.getElementById("threshold-slider").value = storage.warningThreshold;
    document.getElementById("threshold-val").textContent = `${storage.warningThreshold}%`;
  }

  // Sidebar Navigation Switcher
  const navItems = document.querySelectorAll(".nav-item");
  const panelSections = document.querySelectorAll(".panel-section");

  const panelTitles = {
    "panel-whitelist": { title: "Trusted Whitelist Management", sub: "Manage domains that bypass dynamic machine learning phishing scanning" },
    "panel-reports": { title: "User Phishing Reports", sub: "Review malicious site reports submitted by users" },
    "panel-history": { title: "Scan Activity Logs", sub: "Inspect recent URL scan history logs" },
    "panel-config": { title: "API Configuration", sub: "Configure FastAPI backend connection and threat threshold settings" }
  };

  navItems.forEach(item => {
    item.addEventListener("click", () => {
      navItems.forEach(n => n.classList.remove("active"));
      panelSections.forEach(p => p.classList.remove("active"));
      
      item.classList.add("active");
      const targetPanel = item.getAttribute("data-target");
      document.getElementById(targetPanel).classList.add("active");

      document.getElementById("panel-title").textContent = panelTitles[targetPanel].title;
      document.getElementById("panel-subtitle").textContent = panelTitles[targetPanel].sub;

      if (targetPanel === "panel-whitelist") fetchWhitelist();
      if (targetPanel === "panel-reports") fetchReports();
      if (targetPanel === "panel-history") fetchLogs();
    });
  });

  // Threshold Slider Listener
  document.getElementById("threshold-slider").addEventListener("input", (e) => {
    document.getElementById("threshold-val").textContent = `${e.target.value}%`;
  });

  // Initial Data Loads
  checkApiHealth();
  fetchDashboardStats();
  fetchWhitelist();

  // --- WHITELIST MANAGEMENT ---
  async function fetchWhitelist() {
    const tableBody = document.getElementById("whitelist-table-body");
    try {
      const res = await fetch(`${currentApiUrl}/api/v1/whitelist`);
      const data = await res.json();
      whitelistCache = data.whitelist || [];
      renderWhitelistTable(whitelistCache);
    } catch (err) {
      tableBody.innerHTML = `<tr><td colspan="4" class="text-center text-red">Failed to connect to Whitelist API backend.</td></tr>`;
    }
  }

  function renderWhitelistTable(items) {
    const tableBody = document.getElementById("whitelist-table-body");
    if (items.length === 0) {
      tableBody.innerHTML = `<tr><td colspan="4" class="text-center">No whitelisted domains found.</td></tr>`;
      return;
    }

    tableBody.innerHTML = "";
    items.forEach(item => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><strong>${item.domain}</strong></td>
        <td><span class="history-tag tag-safe">${item.added_by || "user"}</span></td>
        <td>${item.added_at ? new Date(item.added_at).toLocaleString() : "System"}</td>
        <td><button class="btn-danger-sm" data-domain="${item.domain}">Remove</button></td>
      `;
      tableBody.appendChild(tr);
    });

    // Attach delete listeners
    tableBody.querySelectorAll(".btn-danger-sm").forEach(btn => {
      btn.addEventListener("click", () => {
        const domain = btn.getAttribute("data-domain");
        deleteWhitelistDomain(domain);
      });
    });
  }

  // Filter Whitelist Search Input
  document.getElementById("whitelist-search").addEventListener("input", (e) => {
    const query = e.target.value.toLowerCase();
    const filtered = whitelistCache.filter(item => item.domain.toLowerCase().includes(query));
    renderWhitelistTable(filtered);
  });

  // Add Domain
  document.getElementById("btn-add-domain").addEventListener("click", async () => {
    const domainInput = document.getElementById("new-domain-input");
    const domain = domainInput.value.trim();
    if (!domain) return;

    try {
      const res = await fetch(`${currentApiUrl}/api/v1/whitelist`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain })
      });
      if (res.ok) {
        domainInput.value = "";
        fetchWhitelist();
        fetchDashboardStats();
      }
    } catch (err) {
      alert("Error adding domain to whitelist.");
    }
  });

  async function deleteWhitelistDomain(domain) {
    try {
      const res = await fetch(`${currentApiUrl}/api/v1/whitelist/${domain}`, { method: "DELETE" });
      if (res.ok) {
        fetchWhitelist();
        fetchDashboardStats();
      }
    } catch (err) {
      alert("Error removing domain from whitelist.");
    }
  }

  // Export Whitelist JSON
  document.getElementById("btn-export-whitelist").addEventListener("click", () => {
    const jsonStr = JSON.stringify(whitelistCache, null, 2);
    const blob = new Blob([jsonStr], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "phishguard_whitelist_export.json";
    a.click();
    URL.revokeObjectURL(url);
  });

  // Import Whitelist JSON
  const importFileInput = document.getElementById("import-json-file");
  document.getElementById("btn-import-whitelist").addEventListener("click", () => {
    importFileInput.click();
  });

  importFileInput.addEventListener("change", (e) => {
    const file = e.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = async (event) => {
      try {
        const domainsObj = JSON.parse(event.target.result);
        if (Array.isArray(domainsObj)) {
          for (const item of domainsObj) {
            const domain = item.domain || item;
            if (typeof domain === "string") {
              await fetch(`${currentApiUrl}/api/v1/whitelist`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ domain })
              });
            }
          }
          alert("Whitelist imported successfully!");
          fetchWhitelist();
          fetchDashboardStats();
        }
      } catch (err) {
        alert("Invalid JSON format.");
      }
    };
    reader.readAsText(file);
  });

  // --- REPORTS MANAGEMENT ---
  async function fetchReports() {
    const tableBody = document.getElementById("reports-table-body");
    try {
      const res = await fetch(`${currentApiUrl}/api/v1/reports`);
      const data = await res.json();
      const reports = data.reports || [];

      if (reports.length === 0) {
        tableBody.innerHTML = `<tr><td colspan="6" class="text-center">No user phishing reports submitted yet.</td></tr>`;
        return;
      }

      tableBody.innerHTML = "";
      reports.forEach(item => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td>#${item.id}</td>
          <td><strong>${item.domain}</strong></td>
          <td style="max-width:200px; overflow:hidden; text-overflow:ellipsis;">${item.url}</td>
          <td>${item.user_comments || "N/A"}</td>
          <td>${new Date(item.reported_at).toLocaleString()}</td>
          <td><span class="history-tag tag-phishing">${item.status}</span></td>
        `;
        tableBody.appendChild(tr);
      });
    } catch (err) {
      tableBody.innerHTML = `<tr><td colspan="6" class="text-center text-red">Failed to load reports.</td></tr>`;
    }
  }

  document.getElementById("btn-refresh-reports").addEventListener("click", fetchReports);

  // --- LOGS MANAGEMENT ---
  async function fetchLogs() {
    const tableBody = document.getElementById("logs-table-body");
    try {
      const res = await fetch(`${currentApiUrl}/api/v1/history?limit=50`);
      const data = await res.json();
      const logs = data.history || [];

      if (logs.length === 0) {
        tableBody.innerHTML = `<tr><td colspan="5" class="text-center">No historical scan logs recorded yet.</td></tr>`;
        return;
      }

      tableBody.innerHTML = "";
      logs.forEach(item => {
        const tr = document.createElement("tr");
        const tagClass = item.classification === "Phishing" ? "tag-phishing" : (item.classification === "Suspicious" ? "tag-suspicious" : "tag-safe");
        tr.innerHTML = `
          <td style="max-width:260px; overflow:hidden; text-overflow:ellipsis;">${item.url}</td>
          <td><strong>${item.domain}</strong></td>
          <td>${Math.round(item.risk_score)}%</td>
          <td><span class="history-tag ${tagClass}">${item.classification}</span></td>
          <td>${new Date(item.scanned_at).toLocaleString()}</td>
        `;
        tableBody.appendChild(tr);
      });
    } catch (err) {
      tableBody.innerHTML = `<tr><td colspan="5" class="text-center text-red">Failed to load activity logs.</td></tr>`;
    }
  }

  document.getElementById("btn-refresh-logs").addEventListener("click", fetchLogs);

  // --- CONFIGURATION ---
  document.getElementById("btn-test-api").addEventListener("click", async () => {
    const testUrl = document.getElementById("api-url-input").value.trim();
    const statusMsg = document.getElementById("config-status-msg");
    statusMsg.textContent = "Testing connection...";
    statusMsg.className = "status-msg";

    try {
      const res = await fetch(`${testUrl}/`);
      if (res.ok) {
        statusMsg.textContent = "✅ Successfully connected to FastAPI backend server!";
        statusMsg.className = "status-msg success";
      } else {
        statusMsg.textContent = `❌ Server responded with HTTP status ${res.status}`;
        statusMsg.className = "status-msg error";
      }
    } catch (e) {
      statusMsg.textContent = "❌ Failed to connect to API server. Ensure backend is running.";
      statusMsg.className = "status-msg error";
    }
  });

  document.getElementById("btn-save-config").addEventListener("click", async () => {
    const newUrl = document.getElementById("api-url-input").value.trim();
    const threshold = parseInt(document.getElementById("threshold-slider").value);
    
    await chrome.storage.local.set({ apiUrl: newUrl, warningThreshold: threshold });
    currentApiUrl = newUrl;
    
    const statusMsg = document.getElementById("config-status-msg");
    statusMsg.textContent = "💾 Configuration settings saved successfully!";
    statusMsg.className = "status-msg success";

    checkApiHealth();
    fetchDashboardStats();
  });

  // --- DASHBOARD STATS ---
  async function fetchDashboardStats() {
    try {
      const res = await fetch(`${currentApiUrl}/api/v1/stats`);
      const data = await res.json();
      document.getElementById("stat-total-scans").textContent = data.total_scans || 0;
      document.getElementById("stat-phishing-count").textContent = data.phishing_detected || 0;
      document.getElementById("stat-whitelist-count").textContent = data.whitelisted_domains || 0;
    } catch (err) {
      console.warn("Could not fetch dashboard stats.");
    }
  }

  async function checkApiHealth() {
    const pill = document.getElementById("connection-status-pill");
    try {
      const res = await fetch(`${currentApiUrl}/`);
      if (res.ok) {
        pill.className = "status-pill pill-online";
        pill.innerHTML = `<span class="pill-dot"></span> Backend API Connected`;
      } else {
        pill.className = "status-pill pill-offline";
        pill.innerHTML = `<span class="pill-dot"></span> Backend Disconnected`;
      }
    } catch (e) {
      pill.className = "status-pill pill-offline";
      pill.innerHTML = `<span class="pill-dot"></span> Backend Server Offline`;
    }
  }
});
