// Live Phishing Detection Chrome Extension Background Service Worker (Manifest V3)

const DEFAULT_API_URL = "http://127.0.0.1:8000";

// Retrieve API URL from storage or fallback
async function getApiUrl() {
  const result = await chrome.storage.local.get(["apiUrl"]);
  return result.apiUrl || DEFAULT_API_URL;
}

// Update Extension Badge based on Risk Score & Classification
function updateBadge(tabId, classification, riskScore) {
  let badgeText = "SAFE";
  let badgeColor = "#10B981"; // Emerald Green

  if (classification === "Phishing") {
    badgeText = "RISK";
    badgeColor = "#EF4444"; // Vivid Red
  } else if (classification === "Suspicious") {
    badgeText = "WARN";
    badgeColor = "#F59E0B"; // Amber Yellow
  }

  chrome.action.setBadgeText({ tabId, text: badgeText });
  chrome.action.setBadgeBackgroundColor({ tabId, color: badgeColor });
}

// Analyze URL by sending payload to FastAPI Backend
async function analyzeUrl(url, tabId) {
  if (!url || !url.startsWith("http")) return;

  try {
    const apiUrl = await getApiUrl();
    const response = await fetch(`${apiUrl}/api/v1/predict`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });

    if (!response.ok) {
      console.warn("FastAPI backend error:", response.status);
      return;
    }

    const data = await response.json();

    // Cache latest result for popup UI access
    await chrome.storage.local.set({
      [`scan_${tabId}`]: data,
      lastScan: data
    });

    // Update extension badge
    updateBadge(tabId, data.classification, data.risk_score);

    // If High Phishing Threat detected and domain is not whitelisted, trigger warning overlay
    if (data.classification === "Phishing" && !data.is_whitelisted) {
      // Check if user previously clicked 'Proceed Anyways' for this domain in session
      const sessionBypass = await chrome.storage.session.get([`bypass_${data.domain}`]);
      if (!sessionBypass[`bypass_${data.domain}`]) {
        chrome.tabs.sendMessage(tabId, {
          action: "SHOW_WARNING_OVERLAY",
          data: data
        }).catch(err => console.log("Content script not yet ready for overlay injection:", err.message));
      }
    }

  } catch (err) {
    console.error("Failed to connect to Live Phishing Detection API backend:", err);
    chrome.action.setBadgeText({ tabId, text: "OFF" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#6B7280" });
  }
}

// Listen to Tab URL updates
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url) {
    analyzeUrl(tab.url, tabId);
  }
});

// Listen to Active Tab changes
chrome.tabs.onActivated.addListener(activeInfo => {
  chrome.tabs.get(activeInfo.tabId, tab => {
    if (tab && tab.url) {
      analyzeUrl(tab.url, tab.id);
    }
  });
});

// Listen for message calls from Popup / Options / Content Script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "RESCAN_CURRENT_TAB") {
    chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
      if (tabs[0] && tabs[0].url) {
        analyzeUrl(tabs[0].url, tabs[0].id).then(() => sendResponse({ status: "done" }));
      }
    });
    return true; // Keep message channel open for async response
  }

  if (message.action === "PROCEED_ANYWAYS") {
    const domain = message.domain;
    if (domain) {
      chrome.storage.session.set({ [`bypass_${domain}`]: true });
    }
    sendResponse({ status: "bypassed" });
    return true;
  }
});

console.log("Live Phishing Detection Background Worker Initialized.");
