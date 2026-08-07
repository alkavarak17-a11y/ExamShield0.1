// ==========================================
// EXAMSHIELD - REPORTS GENERATOR CLIENT SCRIPT
// ==========================================
// Handles client selection filters, compiles parameter strings,
// and opens dynamic print pages with window trigger hooks.

document.addEventListener("DOMContentLoaded", () => {
    // 1. MOBILE SIDEBAR TOGGLE
    const menuBtn = document.getElementById("mobile-menu-btn");
    const sidebar = document.getElementById("mysidenav");
    const icon = document.getElementById("menu-icon");

    if (menuBtn && sidebar && icon) {
        menuBtn.onclick = function () {
            sidebar.classList.toggle("active");
            
            if (sidebar.classList.contains("active")) {
                icon.classList.remove("fa-bars");
                icon.classList.add("fa-xmark");
            } else {
                icon.classList.remove("fa-xmark");
                icon.classList.add("fa-bars");
            }
        };
    }

    // 2. DYNAMIC REDIRECT LINKS BINDING
    const pdfBtn = document.getElementById("export-pdf-btn");
    const printBtn = document.getElementById("print-report-btn");
    const formInputs = document.querySelectorAll(".compiler-form input[type='checkbox'], #exam_code_select");

    // Helper to calculate target query link
    function getCompiledUrl(isPrintOnly) {
        const select = document.getElementById("exam_code_select");
        if (!select) return "#";
        
        const code = select.value;
        const security = document.getElementById("opt_security").checked ? "1" : "0";
        const blockchain = document.getElementById("opt_blockchain").checked ? "1" : "0";
        const tracking = document.getElementById("opt_tracking").checked ? "1" : "0";
        
        let url = `/print_report?exam_code=${code}&security=${security}&blockchain=${blockchain}&tracking=${tracking}`;
        if (isPrintOnly) {
            url += "&print=1";
        }
        return url;
    }

    // Synchronize link addresses on inputs adjust
    function syncLinks() {
        if (pdfBtn) {
            pdfBtn.href = getCompiledUrl(false);
        }
    }

    // Bind event listeners to checkboxes to sync links in real-time
    formInputs.forEach(input => {
        input.addEventListener("change", syncLinks);
    });

    // Initialize links on page load
    syncLinks();

    // Trigger Print Action
    if (printBtn) {
        printBtn.addEventListener("click", (e) => {
            e.preventDefault();
            // Open print window in a new tab
            const url = getCompiledUrl(true);
            window.open(url, "_blank");
        });
    }
});
