const apiURL = "https://script.google.com/macros/s/AKfycbyIN9wn1ewTZDkx4E1fjyMTa35POlfUGFvjHeoPLFvtuEKiPtNa-z3LvE0Rjf0phVTL/exec"; 
let items = [];

// Load dữ liệu Google Sheets 1 lần khi mở trang
const ref = window.location.origin;
async function loadData() {
    try {
        const res = await fetch(`${apiURL}?ref=${encodeURIComponent(ref)}`);
        items = await res.json();
        console.log("Dữ liệu Google Sheets:", items);
    } catch (err) {
        console.error("Lỗi load API", err);
    }
}
loadData();

// Bắt sự kiện Enter trong input tìm kiếm
document.getElementById("searchInput").addEventListener("keydown", function(e){
    if(e.key === "Enter") {
        doSearch();
    }
});

// Click nút tìm kiếm
document.getElementById("searchBtn").addEventListener("click", doSearch);

// Hàm tìm kiếm
function doSearch() {
    const keyword = document.getElementById("searchInput").value.trim();
    if(!keyword) return;

    // Chuyển sang trang timkiem.html, kèm keyword
    window.location.href = `timkiem.html?key=${encodeURIComponent(keyword)}`;
}
