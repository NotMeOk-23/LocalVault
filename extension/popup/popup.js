// LocalVault Browser Extension Popup Script with Windows Hello / Master Password Authentication Gate
const BRIDGE_URL = "http://127.0.0.1:28842";
let currentTab = null;
let currentHostname = "";
let authToken = null;

document.addEventListener("DOMContentLoaded", async () => {
  setupTabs();
  setupAuthHandlers();
  setupGenerator();
  setupSearch();

  // Load any active cached session token
  const stored = await chrome.storage.session ? chrome.storage.session.get(["lvault_auth_token"]) : chrome.storage.local.get(["lvault_auth_token"]);
  if (stored && stored.lvault_auth_token) {
    authToken = stored.lvault_auth_token;
  }

  await checkVaultConnection();
});

function setupTabs() {
  const tabs = document.querySelectorAll(".tab-btn");
  tabs.forEach(btn => {
    btn.addEventListener("click", () => {
      tabs.forEach(b => b.classList.remove("active"));
      document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));

      btn.classList.add("active");
      const targetId = btn.getAttribute("data-tab");
      document.getElementById(targetId).classList.add("active");

      if (targetId === "tab-generator") {
        generatePassword();
      }
    });
  });

  document.getElementById("retryConnectionBtn").addEventListener("click", checkVaultConnection);

  const openGuideBtn = document.getElementById("openAppGuideBtn");
  const guideBox = document.getElementById("offlineGuideBox");
  if (openGuideBtn && guideBox) {
    openGuideBtn.addEventListener("click", () => {
      guideBox.style.display = guideBox.style.display === "none" ? "block" : "none";
    });
  }

  document.getElementById("lockSessionBtn").addEventListener("click", async () => {
    await lockExtensionSession();
  });
}

function setupAuthHandlers() {
  const winHelloBtn = document.getElementById("windowsHelloBtn");
  const masterPassBtn = document.getElementById("unlockWithPassBtn");
  const passInput = document.getElementById("masterPasswordInput");
  const errorMsg = document.getElementById("authErrorMsg");

  // Windows Hello / PIN button
  winHelloBtn.addEventListener("click", async () => {
    hideError();
    winHelloBtn.disabled = true;
    winHelloBtn.style.opacity = "0.7";
    winHelloBtn.querySelector("span:last-child").textContent = "Verifying with Windows...";

    try {
      const res = await fetch(`${BRIDGE_URL}/api/auth/windows-hello`, {
        method: "POST",
        headers: { "Content-Type": "application/json" }
      });
      const data = await res.json();

      if (res.ok && data.authenticated && data.auth_token) {
        await saveAuthToken(data.auth_token);
        await checkVaultConnection();
      } else {
        showError(data.error || "Windows Hello verification failed.");
      }
    } catch (err) {
      showError("Could not connect to LocalVault desktop service.");
    } finally {
      winHelloBtn.disabled = false;
      winHelloBtn.style.opacity = "1";
      winHelloBtn.querySelector("span:last-child").textContent = "Use Windows Hello / PIN";
    }
  });

  // Master Password Unlock button
  masterPassBtn.addEventListener("click", () => unlockWithPassword());
  passInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") unlockWithPassword();
  });

  async function unlockWithPassword() {
    hideError();
    const password = passInput.value;
    if (!password) {
      showError("Please enter your Master Password.");
      return;
    }

    masterPassBtn.disabled = true;
    masterPassBtn.textContent = "Verifying...";

    try {
      const res = await fetch(`${BRIDGE_URL}/api/auth/master-password`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password })
      });
      const data = await res.json();

      if (res.ok && data.authenticated && data.auth_token) {
        passInput.value = "";
        await saveAuthToken(data.auth_token);
        await checkVaultConnection();
      } else {
        showError(data.error || "Incorrect Master Password.");
      }
    } catch (err) {
      showError("Could not connect to LocalVault desktop service.");
    } finally {
      masterPassBtn.disabled = false;
      masterPassBtn.textContent = "Unlock Extension";
    }
  }

  function showError(msg) {
    errorMsg.textContent = msg;
    errorMsg.style.display = "block";
  }

  function hideError() {
    errorMsg.style.display = "none";
    errorMsg.textContent = "";
  }
}

async function saveAuthToken(token) {
  authToken = token;
  const storage = chrome.storage.session || chrome.storage.local;
  await storage.set({ lvault_auth_token: token });
}

async function lockExtensionSession() {
  try {
    await fetch(`${BRIDGE_URL}/api/auth/lock`, {
      method: "POST",
      headers: getAuthHeaders()
    });
  } catch (e) {}

  authToken = null;
  const storage = chrome.storage.session || chrome.storage.local;
  await storage.remove(["lvault_auth_token"]);
  await checkVaultConnection();
}

function getAuthHeaders() {
  const headers = { "Content-Type": "application/json" };
  if (authToken) {
    headers["X-Extension-Auth"] = authToken;
    headers["Authorization"] = `Bearer ${authToken}`;
  }
  return headers;
}

async function checkVaultConnection() {
  const badge = document.getElementById("statusBadge");
  const overlay = document.getElementById("lockedOverlay");
  const authScreen = document.getElementById("authScreen");
  const mainNav = document.getElementById("mainNav");
  const mainContent = document.getElementById("mainContent");
  const lockBtn = document.getElementById("lockSessionBtn");

  try {
    const res = await fetch(`${BRIDGE_URL}/api/status`, {
      headers: getAuthHeaders()
    });
    if (!res.ok) throw new Error("Connection failed");

    const data = await res.json();

    if (data.status === "unlocked") {
      overlay.style.display = "none";

      // Check if user has authenticated this extension session
      if (data.is_authenticated) {
        badge.textContent = `● Unlocked (${data.item_count} items)`;
        badge.className = "status-badge unlocked";
        authScreen.style.display = "none";
        mainNav.style.display = "flex";
        mainContent.style.display = "block";
        lockBtn.style.display = "inline-block";
        await loadTabLogins();
      } else {
        // Needs authentication via Windows Hello or Master Password!
        badge.textContent = "● Auth Required";
        badge.className = "status-badge locked";
        authScreen.style.display = "flex";
        mainNav.style.display = "none";
        mainContent.style.display = "none";
        lockBtn.style.display = "none";
      }
    } else {
      // Desktop vault is locked
      badge.textContent = "● Vault Locked";
      badge.className = "status-badge locked";
      // Allow unlocking right from the extension using master password
      authScreen.style.display = "flex";
      mainNav.style.display = "none";
      mainContent.style.display = "none";
      overlay.style.display = "none";
      lockBtn.style.display = "none";
    }
  } catch (err) {
    badge.textContent = "● Desktop Offline";
    badge.className = "status-badge locked";
    overlay.style.display = "flex";
    authScreen.style.display = "none";
    mainNav.style.display = "none";
    mainContent.style.display = "none";
    lockBtn.style.display = "none";
  }
}

async function loadTabLogins() {
  const domainLabel = document.getElementById("currentDomain");
  const listContainer = document.getElementById("loginsList");
  const emptyMsg = document.getElementById("noLoginsMessage");

  listContainer.innerHTML = "";
  emptyMsg.style.display = "none";

  // Get active browser tab
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tabs || tabs.length === 0) return;
    currentTab = tabs[0];

    const url = new URL(currentTab.url);
    currentHostname = url.hostname.replace(/^www\./, "");
    domainLabel.textContent = currentHostname;
  } catch (e) {
    domainLabel.textContent = "Browser page";
    currentHostname = "";
  }

  try {
    const res = await fetch(`${BRIDGE_URL}/api/items?domain=${encodeURIComponent(currentHostname)}`, {
      headers: getAuthHeaders()
    });
    const data = await res.json();

    if (res.status === 401) {
      // Session expired, re-trigger auth
      await lockExtensionSession();
      return;
    }

    if (data.items && data.items.length > 0) {
      data.items.forEach(item => {
        const card = createLoginCard(item);
        listContainer.appendChild(card);
      });
    } else {
      emptyMsg.style.display = "block";
    }
  } catch (err) {
    emptyMsg.style.display = "block";
  }
}

function createLoginCard(item) {
  const card = document.createElement("div");
  card.className = "item-card";

  const header = document.createElement("div");
  header.className = "item-header";

  const title = document.createElement("div");
  title.className = "item-title";
  title.textContent = item.title;
  header.appendChild(title);

  if (item.totp_code) {
    const totp = document.createElement("span");
    totp.className = "btn-pill";
    totp.style.cssText = "background: rgba(16,185,129,0.15); color: #34d399; font-family: monospace;";
    totp.textContent = `2FA: ${item.totp_code}`;
    header.appendChild(totp);
  }

  card.appendChild(header);

  if (item.username) {
    const user = document.createElement("div");
    user.className = "item-user";
    user.textContent = item.username;
    card.appendChild(user);
  }

  const actions = document.createElement("div");
  actions.className = "item-actions";

  // Autofill button
  const fillBtn = document.createElement("button");
  fillBtn.className = "btn-primary";
  fillBtn.textContent = "⚡ Autofill";
  fillBtn.addEventListener("click", () => triggerAutofill(item.username, item.password));
  actions.appendChild(fillBtn);

  // Copy Password button
  const copyPassBtn = document.createElement("button");
  copyPassBtn.className = "btn-pill";
  copyPassBtn.textContent = "Copy Pass";
  copyPassBtn.addEventListener("click", () => copyToClipboard(item.password, copyPassBtn, "Copied!"));
  actions.appendChild(copyPassBtn);

  // Copy User button
  if (item.username) {
    const copyUserBtn = document.createElement("button");
    copyUserBtn.className = "btn-pill";
    copyUserBtn.textContent = "Copy User";
    copyUserBtn.addEventListener("click", () => copyToClipboard(item.username, copyUserBtn, "Copied!"));
    actions.appendChild(copyUserBtn);
  }

  card.appendChild(actions);
  return card;
}

async function triggerAutofill(username, password) {
  if (!currentTab || !currentTab.id) return;

  try {
    await chrome.tabs.sendMessage(currentTab.id, {
      action: "autofill",
      username: username,
      password: password
    });
    window.close();
  } catch (err) {
    console.warn("Could not inject into tab, falling back to clipboard:", err);
    navigator.clipboard.writeText(password);
  }
}

function copyToClipboard(text, btnElement, successText) {
  navigator.clipboard.writeText(text).then(() => {
    const original = btnElement.textContent;
    btnElement.textContent = successText;
    btnElement.style.color = "#34d399";
    setTimeout(() => {
      btnElement.textContent = original;
      btnElement.style.color = "";
    }, 1200);
  });
}

function setupGenerator() {
  const slider = document.getElementById("lengthSlider");
  const lengthVal = document.getElementById("lengthValue");
  const refreshBtn = document.getElementById("refreshGenBtn");
  const copyBtn = document.getElementById("copyGenBtn");

  slider.addEventListener("input", () => {
    lengthVal.textContent = slider.value;
    generatePassword();
  });

  refreshBtn.addEventListener("click", generatePassword);

  copyBtn.addEventListener("click", () => {
    const pass = document.getElementById("generatedPassword").textContent;
    copyToClipboard(pass, copyBtn, "Copied to Clipboard!");
  });
}

async function generatePassword() {
  const length = document.getElementById("lengthSlider").value;
  const display = document.getElementById("generatedPassword");

  try {
    const res = await fetch(`${BRIDGE_URL}/api/generate?length=${length}`);
    const data = await res.json();
    display.textContent = data.password;
  } catch (err) {
    display.textContent = "Fallback-Error-Bridge-Offline";
  }
}

function setupSearch() {
  const input = document.getElementById("searchInput");
  const resultsContainer = document.getElementById("searchResults");

  input.addEventListener("input", async () => {
    const q = input.value.trim();
    if (!q) {
      resultsContainer.innerHTML = "";
      return;
    }

    try {
      const res = await fetch(`${BRIDGE_URL}/api/search?q=${encodeURIComponent(q)}`, {
        headers: getAuthHeaders()
      });
      const data = await res.json();
      resultsContainer.innerHTML = "";

      if (data.results && data.results.length > 0) {
        data.results.forEach(it => {
          const row = document.createElement("div");
          row.className = "item-card";
          row.innerHTML = `
            <div class="item-title">${it.title}</div>
            <div class="item-user">${it.username || it.category}</div>
          `;
          resultsContainer.appendChild(row);
        });
      } else {
        resultsContainer.innerHTML = `<div class="empty-text">No items matching "${q}"</div>`;
      }
    } catch (e) {
      resultsContainer.innerHTML = `<div class="empty-text">Search unavailable</div>`;
    }
  });
}
