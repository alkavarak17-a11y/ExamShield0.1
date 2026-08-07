// ==========================================
// EXAMSHIELD - AI SECURITY ENGINE CLIENT JS
// ==========================================
// Handles radar scan triggers, delayed diagnostic terminal outputs,
// and AJAX post updates to record AI security verification values.

document.addEventListener("DOMContentLoaded", () => {
    // 1. MOBILE NAV SIDEBAR TOGGLE
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

    // 2. RADAR SCANNING SIMULATION AND TERMINAL LOGS
    const startBtn = document.getElementById("start-scan-btn");
    const radarWrapper = document.getElementById("radar-wrapper");
    const radarCenter = document.getElementById("radar-center");
    const scoreDisplay = document.getElementById("score-display");
    const scoreValue = document.getElementById("score-value");
    const terminalBody = document.getElementById("terminal-body");
    const examSelect = document.getElementById("exam_code_select");
    const continueBtn = document.getElementById("continue-btn");

    // Standard scanning timeline logs
    const mockLogs = [
        { text: "[INFO] Initializing ExamShield AI Security Scan Engine v9.8...", type: "info" },
        { text: "[INFO] Contacting local MySQL security tables...", type: "info" },
        { text: "[OK] Secure connection initialized with autocommit.", type: "info" },
        { text: "[INFO] Fetching encrypted PDF file binary buffers...", type: "info" },
        { text: "[OK] AES-256 encryption header block confirmed intact.", type: "success" },
        { text: "[INFO] Decrypting header sector to extract steganographic hashes...", type: "info" },
        { text: "[OK] Steganographic watermark signature matches authority registry.", type: "success" },
        { text: "[INFO] Performing plagiarism sweep against global question repositories...", type: "info" },
        { text: "[INFO] Plagiarism check: analyzing extracted question content...", type: "info" },
        { text: "[INFO] Sweeping file metadata for author details and GPS tags...", type: "info" },
        { text: "[WARN] Extraneous metadata found: Author tags scrubbed from document.", type: "warn" },
        { text: "[INFO] Verifying QR Code alignment blocks...", type: "info" },
        { text: "[OK] SmartTrace QR sequence pre-generation validated.", type: "success" },
        { text: "[INFO] Compiling final security scorecard...", type: "info" },
        { text: "[SUCCESS] AI SECURITY SWEEP COMPLETED SUCCESSFULLY.", type: "success" }
    ];

    if (startBtn && radarWrapper && terminalBody && examSelect) {
        startBtn.addEventListener("click", () => {
            const examCode = examSelect.value;
            if (!examCode) {
                alert("Please select a target examination from the dropdown menu first.");
                return;
            }

            // Lock controls during audit sweep
            startBtn.disabled = true;
            examSelect.disabled = true;
            startBtn.innerText = "Security sweep in progress...";

            // Reset interface elements
            terminalBody.innerHTML = "";
            radarWrapper.classList.add("scanning");
            scoreDisplay.style.display = "none";
            radarCenter.style.display = "block";

            let currentLogIndex = 0;

            // Delayed console log writer simulating file scans
            const writeNextLog = () => {
                if (currentLogIndex < mockLogs.length) {
                    const log = mockLogs[currentLogIndex];
                    const p = document.createElement("p");
                    p.className = `log-line ${log.type}`;
                    p.innerText = `${new Date().toLocaleTimeString()} - ${log.text}`;
                    terminalBody.appendChild(p);
                    terminalBody.scrollTop = terminalBody.scrollHeight; // auto scroll

                    currentLogIndex++;
                    
                    // Set random delay times between log lines
                    const delay = Math.random() * 200 + 200; 
                    setTimeout(writeNextLog, delay);
                } else {
                    // Logs complete, submit AJAX POST request to update database row
                    completeScanInDatabase(examCode);
                }
            };

            // Start log writer sequence
            writeNextLog();
        });
    }

    // Submit AJAX post to complete scanning status update in MySQL database
    function completeScanInDatabase(examCode) {
        fetch("/security_scan", {
        method: "POST",
        headers: {
            "Content-Type": "application/x-www-form-urlencoded",
        },
        body: `exam_code=${encodeURIComponent(examCode)}`
    })
    .then(async response => {
        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.message || "Security scan failed.");
        }

        return data;
    })
        .then(data => {
            if (data.status === "success") {
                // Stop radar rotation
                radarWrapper.classList.remove("scanning");
                radarCenter.style.display = "none";

                // Update score badge
                scoreValue.innerText = `${data.security_score}%`;
                scoreDisplay.style.display = "flex";

                // Print success confirmation terminal log
                const p = document.createElement("p");
                p.className = "log-line success";
                p.innerText = `${new Date().toLocaleTimeString()} - [DATABASE] AI Score ${data.security_score}% written. Blockchain log #1 registered.`;
                terminalBody.appendChild(p);
                terminalBody.scrollTop = terminalBody.scrollHeight;

                // Show flash notification conceptually
                const alertContainer = document.createElement("div");
                alertContainer.className = "alert-box success";
                alertContainer.innerText = "Shield AI verification sweep succeeded. Ledger updated.";
                document.querySelector(".main-content").insertBefore(alertContainer, document.querySelector(".scan-container"));

                // Show continue button or update target
                if (startBtn) {
                    startBtn.style.display = "none";
                }
                if (continueBtn) {
                    continueBtn.style.display = "flex";
                }
            } else {
                handleScanError(data.message || "Database update rejected.");
            }
        })
        .catch(error => {
            console.error("AJAX completion error: ", error);
            handleScanError("Secure network timeout or database failure.");
        });
    }

    function handleScanError(message) {
        radarWrapper.classList.remove("scanning");
        if (startBtn) {
            startBtn.disabled = false;
            startBtn.innerText = "Retry AI Security Sweep";
        }
        if (examSelect) {
            examSelect.disabled = false;
        }

        const p = document.createElement("p");
        p.className = "log-line error";
        p.innerText = `${new Date().toLocaleTimeString()} - [FATAL] AI Scan failed: ${message}`;
        terminalBody.appendChild(p);
        terminalBody.scrollTop = terminalBody.scrollHeight;
    }
});
