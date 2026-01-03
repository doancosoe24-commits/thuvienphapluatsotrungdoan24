/* auth-secure.js
   Phiên bản: Bảo mật client-side tối đa có thể (frontend-only)
   Ghi chú quan trọng:
   - ĐỘC QUYỀN BẢO MẬT thực sự cần thay đổi server-side (HttpOnly cookie, CSP, rate-limit, token rotation).
   - Đây là cải thiện **client logic**: giảm surface attack, giảm rủi ro token leak qua URL/history, hạn chế XSS surface.
*/

"use strict";

const AppAuth = (function () {
  // ======= CONFIG =======
  // Ideal: sử dụng proxy server (không expose API_URL trên client).
  const API_URL = "https://script.google.com/macros/s/AKfycbxe1dxDcrRp5yYz4xNFT4iFqI14XcOzkou8hFOaV0yCgcvCsMjMpYcoyTXAEX4wRAqA/exec";

  // store keys
  const STORAGE_KEY = "app_auth_v1"; // dùng sessionStorage
  const MIN_TOKEN_TTL_SEC = 30; // nếu token thời hạn nhỏ hơn -> coi như expired

  // In-memory cache (cleared on full page reload when not using sessionStorage)
  let inMemory = {
    token: null,
    expiry: null,
    user: null
  };

  // ======= HELPERS =======
  function now() {
    return Date.now();
  }

  function safeAssign(target, props) {
    Object.keys(props).forEach(k => {
      target[k] = props[k];
    });
  }

  function isoExpiryFromSeconds(seconds) {
    return now() + seconds * 1000;
  }

  function isExpired(expiry) {
    if (!expiry) return true;
    return now() > expiry;
  }

  function escapeHtml(str) {
    if (!str) return "";
    return String(str).replace(/[&<>"']/g, c => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;"
    }[c]));
  }

  // stronger sanitizer than before: remove dangerous tags + attributes
function sanitizeHTML(html) {
  if (!html) return "";

  const template = document.createElement("template");
  template.innerHTML = html;

  // ❌ Chỉ remove script + iframe + object
  template.content.querySelectorAll("script, iframe, object").forEach(n => n.remove());

  // ❌ Remove event handlers + javascript:
  template.content.querySelectorAll("*").forEach(el => {
    [...el.attributes].forEach(attr => {
      const name = attr.name.toLowerCase();
      const value = attr.value.toLowerCase();

      if (name.startsWith("on")) {
        el.removeAttribute(attr.name);
      }

      if (
        (name === "href" || name === "src") &&
        value.startsWith("javascript:")
      ) {
        el.removeAttribute(attr.name);
      }
    });
  });

  return template.innerHTML;
}


  // Insert sanitized HTML but avoid evaluating scripts by using DOMParser -> adopt nodes
  function insertSanitizedHTML(container, html) {
    if (!container) return;
    const safe = sanitizeHTML(html);
    // Create fragment from safe HTML and append
    const parser = new DOMParser();
    const doc = parser.parseFromString(`<div>${safe}</div>`, "text/html");
    const frag = document.createDocumentFragment();
    Array.from(doc.body.firstChild.childNodes).forEach(node => {
      frag.appendChild(node.cloneNode(true));
    });
    // Clear container then append
    container.innerHTML = "";
    container.appendChild(frag);
  }

  // secureFetch with timeout, no-referrer, Authorization header, no token in URL
  async function secureFetch(pathOrUrl, { token = null, body = null, timeout = 10000, credentials = "same-origin", mode = "cors" } = {}) {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), timeout);

    // if user passed a full URL use it, else append to API_URL (server should support POST)
    const url = (typeof pathOrUrl === "string" && pathOrUrl.startsWith("http")) ? pathOrUrl : API_URL;

    const headers = {
      "Content-Type": "application/json",
      "Accept": "application/json"
    };
    if (token) headers["Authorization"] = `Bearer ${token}`;

    try {
      const resp = await fetch(url, {
        method: "POST",
        headers,
        body: body ? JSON.stringify(body) : "{}",
        cache: "no-store",
        signal: controller.signal,
        credentials, // allow server to use cookies if using proxy
        mode,
        referrerPolicy: "no-referrer" // avoid leaking origin
      });
      clearTimeout(id);

      const text = await resp.text();
      let parsed;
      try {
        parsed = JSON.parse(text);
      } catch {
        parsed = text;
      }
      return { ok: resp.ok, status: resp.status, data: parsed };
    } catch (err) {
      clearTimeout(id);
      if (err.name === "AbortError") {
        throw new Error("Request timeout");
      }
      throw err;
    }
  }

  // ======= STORAGE HELPERS (sessionStorage + in-memory) =======
  function persistToken(token, expiresInSeconds) {
    if (!token) return;
    const expiry = isoExpiryFromSeconds(expiresInSeconds || 3 * 60 * 60); // default 3h
    const payload = {
      token: token,
      expiry
    };
    // store minimal data in sessionStorage (cleared when tab closed)
    try {
      sessionStorage.setItem(STORAGE_KEY, JSON.stringify(payload));
      safeAssign(inMemory, { token, expiry });
    } catch (e) {
      // if sessionStorage blocked, keep in memory only
      safeAssign(inMemory, { token, expiry });
      console.warn("sessionStorage unavailable, storing token in memory only");
    }
  }

  function clearToken() {
    try {
      sessionStorage.removeItem(STORAGE_KEY);
    } catch (e) { /* ignore */ }
    safeAssign(inMemory, { token: null, expiry: null, user: null });
  }

  function readStoredToken() {
    try {
      const raw = sessionStorage.getItem(STORAGE_KEY);
      if (!raw) return null;
      const parsed = JSON.parse(raw);
      if (!parsed || !parsed.token) return null;
      if (isExpired(parsed.expiry)) {
        clearToken();
        return null;
      }
      // if near expiry (less than MIN_TOKEN_TTL_SEC), treat as expired to avoid race
      const remaining = Math.floor((parsed.expiry - now()) / 1000);
      if (remaining < MIN_TOKEN_TTL_SEC) {
        clearToken();
        return null;
      }
      safeAssign(inMemory, { token: parsed.token, expiry: parsed.expiry });
      return { token: parsed.token, expiry: parsed.expiry };
    } catch (e) {
      // fallback: maybe old format or corrupted
      try { sessionStorage.removeItem(STORAGE_KEY); } catch (_) {}
      return null;
    }
  }

  // parse input (be permissive for format migration)
  function parseLoggedInUser(rawObj) {
    if (!rawObj) return null;
    try {
      // if rawObj is object from storage
      if (rawObj.token) {
        return { token: rawObj.token, username: rawObj.username || null, id: rawObj.id || null, role: rawObj.role || null };
      }
      // if old format (nested user)
      if (rawObj.user && rawObj.user.token) {
        return { token: rawObj.user.token, username: rawObj.user.username || null, id: rawObj.user.id || null, role: rawObj.user.role || null };
      }
      return null;
    } catch {
      return null;
    }
  }

  // ======= PUBLIC UI HELPERS: header/footer loading & userbox =======
async function loadHeaderFooter() {
  const header = document.getElementById("header");
  const footer = document.getElementById("footer");

  const load = async (el, url) => {
    if (!el) return;
    try {
      const r = await fetch(url, { cache: "no-store" });
      const html = await r.text();
      el.innerHTML = sanitizeHTML(html);
    } catch (e) {
      console.error("Load error:", url, e);
    }
  };

  await Promise.all([
    load(header, "header.html"),
    load(footer, "footer.html")
  ]);

  initUserBox();
  initSearch();
  initClearSearch();
}


  async function initUserBox() {
    const userBox = document.getElementById("userBox");
    if (!userBox) return;

    const stored = readStoredToken();

    if (!stored) {
      // show login link
      userBox.innerHTML = ""; // clear
      const a = document.createElement("a");
      a.href = "index.html";
      a.style.color = "#156082";
      a.style.fontWeight = "600";
      a.textContent = "Đăng nhập";
      userBox.appendChild(a);
      return;
    }

    // at this point we have token in memory
    // optionally fetch user info for display (use secureFetch)
    // but don't block UI; show minimal UI immediately
    const span = document.createElement("span");
    span.style.color = "#ccae6e";
    span.style.fontWeight = "600";
    span.textContent = "User"; // fallback
    userBox.innerHTML = "";
    userBox.appendChild(document.createTextNode("Xin chào, "));
    userBox.appendChild(span);

    // try to get username from server (non-blocking)
    (async () => {
      try {
        const r = await secureFetch(API_URL, { token: stored.token, body: { route: "get-user-info" }, timeout: 5000 });
        if (r && r.ok && r.data && r.data.user && r.data.user.username) {
          span.textContent = r.data.user.username;
        }
      } catch (e) {
        // ignore — don't logout user because of transient network
        console.warn("get-user-info failed:", e);
      }
    })();

    // add logout button
    userBox.appendChild(document.createTextNode(" | "));
    const logoutBtn = document.createElement("button");
    logoutBtn.id = "logoutBtn";
    logoutBtn.style.color = "red";
    logoutBtn.style.cursor = "pointer";
    logoutBtn.style.padding = "3px";
    logoutBtn.style.border = "none";
    logoutBtn.style.fontWeight = "600";
    logoutBtn.style.fontSize = "14px";
    logoutBtn.textContent = "Đăng xuất";
    logoutBtn.onclick = () => {
      // call server to revoke token (best effort)
      (async () => {
        try {
          await secureFetch(API_URL, { token: stored.token, body: { route: "revoke-token" }, timeout: 3000 });
        } catch (e) { /* ignore */ }
      })();
      clearToken();
      // use replace to avoid back navigation
      window.location.replace("index.html");
    };
    userBox.appendChild(logoutBtn);
  }

  // ======= SEARCH helpers =======
  function initSearch() {
    const input = document.getElementById("searchInput");
    const btn = document.getElementById("searchBtn");
    if (!input || !btn) return;
    const doSearch = () => {
      const key = input.value.trim();
      if (!key) return;
      // navigate with encode
      window.location.href = `timkiem.html?key=${encodeURIComponent(key)}`;
    };
    btn.onclick = doSearch;
    input.onkeyup = e => e.key === "Enter" && doSearch();
  }

  function initClearSearch() {
    const input = document.getElementById("searchInput");
    if (!input) return;
    const wrap = input.parentElement;
    if (!wrap) return;
    const clear = document.createElement("span");
    clear.id = "clearBtn";
    clear.innerHTML = "×";
    Object.assign(clear.style, {
      position: "absolute",
      right: "40px",
      top: "50%",
      transform: "translateY(-50%)",
      cursor: "pointer",
      color: "white",
      fontSize: "18px",
      fontWeight: "bold",
      display: "none"
    });
    wrap.appendChild(clear);
    input.oninput = () => {
      clear.style.display = input.value ? "inline" : "none";
    };
    clear.onclick = () => {
      input.value = "";
      clear.style.display = "none";
      input.focus();
    };
  }

  // ======= REQUIRE LOGIN (called on protected pages) =======
  // NOTE: This function only blocks access client-side; server must still verify token.
  async function requireLogin({ failOpen = true } = {}) {
    const publicPages = ["index.html", "login.html", "register.html", "forgot.html", ""];
    const page = location.pathname.split("/").pop();
    if (publicPages.includes(page)) return true;

    const stored = readStoredToken();
    if (!stored) {
      window.location.replace("index.html");
      return false;
    }

    // parse logged user minimal
    const parsed = parseLoggedInUser({ token: stored.token });
    if (!parsed || !parsed.token) {
      clearToken();
      window.location.replace("index.html");
      return false;
    }

    // Option: check server validity — don't force fail on network errors if failOpen === true
    try {
      const resp = await secureFetch(API_URL, { token: parsed.token, body: { route: "check-manager" }, timeout: 6000 });
      if (!resp.ok) {
        clearToken();
        window.location.replace("index.html");
        return false;
      }
      return true;
    } catch (err) {
      console.warn("Token validation failed (network):", err);
      if (failOpen) {
        // allow temporary access if server unreachable; for higher security set failOpen=false
        return true;
      } else {
        clearToken();
        window.location.replace("index.html");
        return false;
      }
    }
  }

  // ======= LOGIN helper (example usage) =======
  // THIS function can be used in login page to perform login + persist token + redirect
  async function doLogin({ username, password, redirectTo = "main.html" } = {}) {
    if (!username || !password) throw new Error("Missing credentials");
    // Always send credentials to server via POST (not in URL)
    const body = { route: "login", username: String(username), password: String(password) };
    const resp = await secureFetch(API_URL, { body, timeout: 8000, credentials: "omit" });
    if (!resp.ok) {
      // resp.data may include reason
      const errMsg = (resp.data && resp.data.message) ? resp.data.message : `Login failed (${resp.status})`;
      throw new Error(errMsg);
    }
    const data = resp.data || {};
    if (!data.token) throw new Error("No token returned from server");

    // persist minimal token (server should tell expiresIn)
    const expiresIn = data.expiresIn || (3 * 60 * 60); // fallback 3h
    persistToken(data.token, expiresIn);

    // redirect to main
    window.location.replace(redirectTo);
  }

  // ======= BOOT (call on page load) =======
  async function init() {
    try {
      await loadHeaderFooter();
    } catch (e) {
      console.warn("Header/footer load error:", e);
    }
    // Do not auto requireLogin here; let pages call requireLogin() explicitly
  }

  // Public API
  return {
    init,
    doLogin,
    requireLogin,
    clearToken,
    readStoredToken,
    secureFetch,
    // utility for debugging (not recommended to use in production)
    _unsafe: {
      sanitizeHTML,
      insertSanitizedHTML
    }
  };
})();

// Auto init header/footer (non-blocking)
AppAuth.init();

/* ===== USAGE
  On login page:
    try {
      await AppAuth.doLogin({ username: u, password: p, redirectTo: 'main.html' });
    } catch (e) {
      show error...
    }

  On protected pages (main.html), at top:
    <script> await AppAuth.requireLogin({ failOpen: false }); </script>
    // failOpen=false => more secure (will force redirect if network check fails)

  Notes:
  - Server MUST validate token for every protected API call.
  - For best security, switch to server-set HttpOnly cookie and remove client token storage entirely.
  - Add CSP headers on server, and use HTTPS + HSTS.
*/
