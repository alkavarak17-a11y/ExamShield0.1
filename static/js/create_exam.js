// ==========================================
// EXAMSHIELD - CREATE EXAMINATION CLIENT SCRIPT
// ==========================================
// Configures mobile menus, form input constraints, and real-time
// readiness status bindings reflecting checkbox selections.

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

    // 2. DYNAMIC READINESS STATUS BINDINGS
    // Mapping of security checkbox inputs to their corresponding status items
    const mappings = [
        { checkboxId: "sec_aes", statusId: "status_aes", label: "Encryption" },
        { checkboxId: "sec_ai", statusId: "status_ai", label: "AI Security" },
        { checkboxId: "sec_blockchain", statusId: "status_blockchain", label: "Blockchain" },
        { checkboxId: "sec_qr", statusId: "status_qr", label: "QR System" }
    ];

    mappings.forEach(m => {
        const checkbox = document.getElementById(m.checkboxId);
        const statusItem = document.getElementById(m.statusId);

        if (checkbox && statusItem) {
            const updateReadiness = () => {
                if (checkbox.checked) {
                    statusItem.innerHTML = `<i class="fa-solid fa-circle-check" style="color: #10b981;"></i> ${m.label} Ready`;
                    statusItem.style.opacity = "1";
                    statusItem.style.textDecoration = "none";
                } else {
                    statusItem.innerHTML = `<i class="fa-solid fa-circle-minus" style="color: #64748b;"></i> ${m.label} Bypassed`;
                    statusItem.style.opacity = "0.6";
                    statusItem.style.textDecoration = "line-through";
                }
            };

            // Set initial state
            updateReadiness();

            // Listen for changes
            checkbox.addEventListener("change", updateReadiness);
        }
    });

    // 3. MINIMUM DATE SETTING
    // Restrict date input to today or future dates
    const dateInput = document.querySelector("input[type='date']");
    if (dateInput) {
        const today = new Date().toISOString().split("T")[0];
        dateInput.min = today;
    }
});
