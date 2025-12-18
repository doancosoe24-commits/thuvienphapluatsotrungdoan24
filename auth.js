// ------- ADMIN PROTECT GLOBAL -------
const API_URL = "https://script.google.com/macros/s/AKfycbzzDGc2jbzYMQmLF14mb_61oh12MnDd-yE-_WtyCTZWvhpItkOMIZHwpc4gJAU3m_Cq/exec"; // <-- thay URL Apps Script

async function protectAdminPage() {
  try {
    const raw = localStorage.getItem("loggedInUser");
    if (!raw) return window.location.href = "index.html";

    let parsed;
    try { parsed = JSON.parse(raw); } catch(e) { parsed = {}; }

    const token =
      parsed.token ||
      (parsed.user && parsed.user.token) ||
      null;

    if (!token) return window.location.href = "index.html";

    const url = `${API_URL}?route=check-admin&token=${encodeURIComponent(token)}`;
    const resp = await fetch(url);
    const data = await resp.json();

    if (!data || data.status !== "success" || !data.isAdmin) {
      return window.location.href = "index.html";
    }

  } catch (e) {
    return window.location.href = "index.html";
  }
}

protectAdminPage();
