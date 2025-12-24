/****************************************************
 *  CONFIG
 ****************************************************/
const API_URL =
  "https://script.google.com/macros/s/AKfycbxe1dxDcrRp5yYz4xNFT4iFqI14XcOzkou8hFOaV0yCgcvCsMjMpYcoyTXAEX4wRAqA/exec";

/****************************************************
 *  AUTO LOAD HEADER + FOOTER
 ****************************************************/
function loadHeaderFooter() {
  const header = document.getElementById("header");
  const footer = document.getElementById("footer");

  if (header) {
    fetch("header.html")
      .then(r => r.text())
      .then(html => {
        header.innerHTML = html;
        initUserBox();
        initSearch();
        initClearSearch();
      })
      .catch(err => console.error("❌ Load header lỗi:", err));
  }

  if (footer) {
    fetch("footer.html")
      .then(r => r.text())
      .then(html => (footer.innerHTML = html))
      .catch(err => console.error("❌ Load footer lỗi:", err));
  }
}

/****************************************************
 *  ESCAPE HTML
 ****************************************************/
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

/****************************************************
 *  PARSE loggedInUser (đa định dạng)
 ****************************************************/
function parseLoggedInUser(raw) {
  if (!raw) return null;
  try {
    const obj = JSON.parse(raw);
    return {
      token: obj.token || obj?.user?.token || null,
      username: obj?.user?.username || obj.username || null,
      id: obj?.user?.id || obj.id || null,
      role: obj.role || obj?.user?.role || null,
      rawObj: obj
    };
  } catch {
    return { token: null, username: raw, id: null, role: null, rawObj: raw };
  }
}

/****************************************************
 *  USER BOX + CHECK MANAGER (ADMIN + EDITOR)
 ****************************************************/
async function initUserBox() {
  const userBox = document.getElementById("userBox");
  if (!userBox) return;

  const raw = localStorage.getItem("loggedInUser");

  // auto logout sau 3 giờ
  setTimeout(() => {
    localStorage.removeItem("loggedInUser");
  }, 3 * 60 * 60 * 1000);

  if (!raw) {
    userBox.innerHTML = `
      <a href="login.html" style="color:#004aad;font-weight:600">
        Đăng nhập
      </a>`;
    return;
  }

  const parsed = parseLoggedInUser(raw);
  const username = parsed.username || "User";

  if (!parsed.token) {
    renderUserBox(username, false);
    return;
  }

  try {
    const url =
      `${API_URL}?route=check-manager&token=${encodeURIComponent(parsed.token)}`;
    const resp = await fetch(url, { cache: "no-store" });
    const data = await resp.json();

    const isManager = data?.isManager === true;
    const apiUser = data?.user || {};
    const name = apiUser.username || username;
    const role = data?.role || parsed.role || "";

    renderUserBox(name, isManager, role);
  } catch (err) {
    console.error("❌ check-manager lỗi:", err);
    renderUserBox(username, false);
  }
}

/****************************************************
 *  RENDER USER BOX
 ****************************************************/
function renderUserBox(username, isManager, role = "") {
  const userBox = document.getElementById("userBox");
  if (!userBox) return;

  userBox.innerHTML = `
    Xin chào,
    <span style="color:#ccae6e;font-weight:600">
      ${escapeHtml(username)}
    </span>
    ${
      isManager
        ? ` | <a href="quanly.html"
               style="color:#00b300;font-weight:700">
               Quản lý
             </a>`
        : ""
    }
    | <button id="logoutBtn"
             style="color:red;cursor:pointer;padding:3px ;border:none;font-weight:600;font-size:14px">
        Đăng xuất
      </button>
  `;

  setupLogout();
}

/****************************************************
 *  LOGOUT
 ****************************************************/
function setupLogout() {
  const btn = document.getElementById("logoutBtn");
  if (!btn) return;

  btn.onclick = () => {
    localStorage.removeItem("loggedInUser");
    window.location.href = "index.html";
  };
}

/****************************************************
 *  SEARCH
 ****************************************************/
function initSearch() {
  const input = document.getElementById("searchInput");
  const btn = document.getElementById("searchBtn");
  if (!input || !btn) return;

  const doSearch = () => {
    const key = input.value.trim();
    if (!key) return;
    window.location.href =
      `timkiem.html?key=${encodeURIComponent(key)}`;
  };

  btn.onclick = doSearch;
  input.onkeyup = e => e.key === "Enter" && doSearch();
}

/****************************************************
 *  CLEAR SEARCH (×)
 ****************************************************/
function initClearSearch() {
  const input = document.getElementById("searchInput");
  if (!input) return;

  const wrap = input.parentElement;
  if (!wrap) return;

  const clear = document.createElement("span");
  clear.id = "clearBtn";
  clear.innerHTML = "&times;";
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

/****************************************************
 *  REQUIRE LOGIN
 ****************************************************/
function requireLogin() {
  const publicPages = ["index.html", "login.html", "register.html"];
  const page = location.pathname.split("/").pop();

  if (publicPages.includes(page)) return;

  if (!localStorage.getItem("loggedInUser")) {
    location.href = "index.html";
  }
}

/****************************************************
 *  INIT
 ****************************************************/
loadHeaderFooter();
requireLogin();


