// main.js

// ------------------------- LOAD HEADER + FOOTER -------------------------
function loadHeaderFooter() {
  const headerContainer = document.getElementById("header");
  const footerContainer = document.getElementById("footer");

  // Load header
  fetch("header.html")
    .then(r => r.text())
    .then(html => {
      headerContainer.innerHTML = html;

      // Gắn sự kiện tìm kiếm 1 lần duy nhất
      const searchBtn = document.getElementById("searchBtn");
      const searchInput = document.getElementById("searchInput");

      if(searchBtn && searchInput && !searchBtn.dataset.listenerAttached){
        const searchFn = () => {
          const key = searchInput.value.trim();
          if(!key) return;
          window.location.href = `timkiem.html?key=${encodeURIComponent(key)}`;
        };

        searchBtn.addEventListener("click", searchFn);
        searchInput.addEventListener("keyup", e => {
          if(e.key === "Enter") searchFn();
        });

        // đánh dấu đã gắn listener
        searchBtn.dataset.listenerAttached = "true";
      }
    })
    .catch(err => console.error("❌ Lỗi load header:", err));

  // Load footer
  fetch("footer.html")
    .then(r => r.text())
    .then(html => { footerContainer.innerHTML = html; })
    .catch(err => console.error("❌ Lỗi load footer:", err));
}

// Gọi khi load page
loadHeaderFooter();