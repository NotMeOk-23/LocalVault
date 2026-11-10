// LocalVault Background Service Worker (Manifest V3)
const BRIDGE_URL = "http://127.0.0.1:28842";

// Listen for external messages or shortcuts
chrome.runtime.onInstalled.addListener(() => {
  console.log("LocalVault Extension Installed.");
});

// Periodic badge status check
async function updateVaultStatus() {
  try {
    const res = await fetch(`${BRIDGE_URL}/api/status`);
    if (res.ok) {
      const data = await res.json();
      if (data.status === "unlocked") {
        chrome.action.setBadgeText({ text: "" });
        chrome.action.setBadgeBackgroundColor({ color: "#0572ec" });
      } else {
        chrome.action.setBadgeText({ text: "🔒" });
        chrome.action.setBadgeBackgroundColor({ color: "#475569" });
      }
    } else {
      chrome.action.setBadgeText({ text: "!" });
      chrome.action.setBadgeBackgroundColor({ color: "#ef4444" });
    }
  } catch (err) {
    chrome.action.setBadgeText({ text: "off" });
    chrome.action.setBadgeBackgroundColor({ color: "#64748b" });
  }
}

// Check status on startup
updateVaultStatus();
setInterval(updateVaultStatus, 15000);
