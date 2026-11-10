// LocalVault In-Page Autofill Content Script
(function () {
  "use strict";

  // Listen for autofill messages from popup
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "autofill") {
      const success = performAutofill(request.username, request.password);
      sendResponse({ success });
    }
    return true;
  });

  function performAutofill(username, password) {
    let filled = false;

    // Find password fields
    const passwordInputs = Array.from(
      document.querySelectorAll('input[type="password"]')
    ).filter(el => isVisible(el));

    // Find username / email fields
    const usernameInputs = Array.from(
      document.querySelectorAll(
        'input[type="text"], input[type="email"], input[name*="user"], input[name*="login"], input[id*="user"], input[autocomplete="username"], input[autocomplete="email"]'
      )
    ).filter(el => isVisible(el) && el.type !== "password");

    // Fill password
    if (password && passwordInputs.length > 0) {
      const pwdField = passwordInputs[0];
      setInputValue(pwdField, password);
      filled = true;
    }

    // Fill username
    if (username && usernameInputs.length > 0) {
      const userField = usernameInputs[0];
      setInputValue(userField, username);
      filled = true;
    }

    if (filled) {
      showAutofillToast("LocalVault: Credentials filled!");
    }

    return filled;
  }

  function setInputValue(element, value) {
    element.focus();
    element.value = value;
    // Dispatch standard input & change events for modern reactive frameworks (React, Vue, etc.)
    element.dispatchEvent(new Event("input", { bubbles: true }));
    element.dispatchEvent(new Event("change", { bubbles: true }));
    element.dispatchEvent(new KeyboardEvent("keydown", { bubbles: true, key: "a" }));
    element.dispatchEvent(new KeyboardEvent("keyup", { bubbles: true, key: "a" }));
  }

  function isVisible(el) {
    return !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length);
  }

  function showAutofillToast(msg) {
    const existing = document.getElementById("lvault-toast");
    if (existing) existing.remove();

    const toast = document.createElement("div");
    toast.id = "lvault-toast";
    toast.textContent = msg;
    toast.style.cssText = `
      position: fixed;
      bottom: 24px;
      right: 24px;
      background: #0d1726;
      color: #38bdf8;
      border: 1px solid #0572ec;
      border-radius: 8px;
      padding: 10px 18px;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      font-size: 13px;
      font-weight: 600;
      box-shadow: 0 10px 25px rgba(0,0,0,0.5);
      z-index: 2147483647;
      transition: opacity 0.3s ease;
    `;
    document.body.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = "0";
      setTimeout(() => toast.remove(), 300);
    }, 2500);
  }
})();
