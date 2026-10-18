// ==========================================
// EXAMSHIELD - QR GENERATOR CLIENT SCRIPT
// ==========================================
// Coordinates client-side QR generation, canvas base64 image exports,
// file downloads, and window printing triggers.


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


    // 2. CLIENT-SIDE QR CODE GENERATOR
    const qrOutput = document.getElementById("qrcode");
    const downloadBtn = document.getElementById("download-qr-btn");
    const printBtn = document.getElementById("print-qr-btn");

    function isValidVerificationUrl(url) {
        if (!url || typeof url !== 'string') return false;
        const trimmed = url.trim();
        if (
            trimmed === "" ||
            trimmed === "null" ||
            trimmed.startsWith("null/") ||
            trimmed.startsWith("http://null") ||
            trimmed.startsWith("https://null") ||
            trimmed.includes("://null")
        ) {
            return false;
        }
        try {
            const parsed = new URL(trimmed);
            return parsed.protocol === "http:" || parsed.protocol === "https:";
        } catch (e) {
            return false;
        }
    }

    if (qrOutput) {
        const payload = (typeof EXAM_QR_PAYLOAD !== 'undefined') ? EXAM_QR_PAYLOAD : "";

        if (!isValidVerificationUrl(payload)) {
            qrOutput.innerHTML = `
                <div style="color: #ef4444; font-size: 13px; text-align: center; padding: 25px 15px;">
                    <i class="fa-solid fa-triangle-exclamation" style="font-size: 32px; margin-bottom: 10px; display: block;"></i>
                    <div style="font-weight: 600;">Invalid QR Target URL</div>
                    <div style="font-size: 11px; color: #94a3b8; margin-top: 6px; line-height: 1.4;">
                        Reachable verification URL could not be resolved. Please verify host and network settings.
                    </div>
                </div>
            `;
            if (downloadBtn) {
                downloadBtn.style.pointerEvents = "none";
                downloadBtn.style.opacity = "0.5";
            }
        } else {
            try {
                // Check if QRCode library loaded correctly from CDN or local bundle
                if (typeof QRCode !== 'undefined') {
                    qrOutput.innerHTML = ""; // Clear loader text before drawing QR code
                    
                    // Initialize QR Code inside container
                    const qrcode = new QRCode(qrOutput, {
                        text: payload,
                        width: 190,
                        height: 190,
                        colorDark: "#000000",
                        colorLight: "#ffffff",
                        correctLevel: QRCode.CorrectLevel.M
                    });

                    // Wait briefly for canvas/image to construct, then bind data url to download link
                    setTimeout(() => {
                        const canvas = qrOutput.querySelector("canvas");
                        const img = qrOutput.querySelector("img");

                        if (canvas && downloadBtn) {
                            const labelCanvas = document.createElement("canvas");
                            labelCanvas.width = 500;
                            labelCanvas.height = 650;
                            const ctx = labelCanvas.getContext("2d");

                            // Background
                            ctx.fillStyle = "#ffffff";
                            ctx.fillRect(0, 0, 500, 650);

                            // Title
                            ctx.fillStyle = "#111827";
                            ctx.font = "bold 28px Arial";
                            ctx.fillText("EXAMSHIELD", 140, 50);

                            ctx.font = "18px Arial";
                            ctx.fillStyle = "#2563eb";
                            ctx.fillText("Secure Examination QR Label", 95, 80);

                            // QR
                            ctx.drawImage(canvas, 155, 110, 190, 190);

                            // Details
                            ctx.fillStyle = "#111";
                            ctx.font = "18px Arial";

                            const codeVal = document.getElementById("examCode") ? document.getElementById("examCode").value : "";
                            const authVal = document.getElementById("examAuthority") ? document.getElementById("examAuthority").value : "";
                            const statVal = document.getElementById("examStatus") ? document.getElementById("examStatus").value : "";

                            ctx.fillText("Exam Code : " + codeVal, 50, 350);
                            ctx.fillText("Authority : " + authVal, 50, 390);
                            ctx.fillText("Status : " + statVal, 50, 430);

                            ctx.font = "14px Arial";
                            ctx.fillStyle = "#475569";
                            ctx.fillText("Scan to open SmartTrace Tracking Portal", 50, 480);

                            ctx.font = "11px monospace";
                            ctx.fillStyle = "#2563eb";
                            const displayUrl = payload.length > 55 ? payload.substring(0, 52) + "..." : payload;
                            ctx.fillText(displayUrl, 50, 510);

                            downloadBtn.href = labelCanvas.toDataURL("image/png");
                        } else if (img && downloadBtn) {
                            downloadBtn.href = img.src;
                        }
                    }, 400);

                } else {
                    // Fallback custom renderer using HTML5 Canvas (useful in offline developer mode)
                    renderCanvasFallback(qrOutput, payload);
                }
            } catch (e) {
                console.error("QR Code library init error: ", e);
                renderCanvasFallback(qrOutput, payload);
            }
        }
    }


                    // 3. PRINT TRIGGER
                    if (printBtn) {
                        printBtn.addEventListener("click", () => {
                            window.print();
                        });
                    }
                });


                // Fallback lightweight custom renderer using HTML5 Canvas (useful in offline developer mode)
                function renderCanvasFallback(container, text) {
                    container.innerHTML = ""; // Clear loader
                    const canvas = document.createElement("canvas");
                    canvas.width = 190;
                    canvas.height = 190;
                    container.appendChild(canvas);


                    const ctx = canvas.getContext("2d");
                   
                    // Draw dummy secure QR pattern
                    ctx.fillStyle = "#ffffff";
                    ctx.fillRect(0, 0, 190, 190);
                    ctx.fillStyle = "#000000";
                   
                    // Draw corner anchor blocks
                    ctx.fillRect(10, 10, 50, 50);
                    ctx.fillStyle = "#ffffff";
                    ctx.fillRect(20, 20, 30, 30);
                    ctx.fillStyle = "#000000";
                    ctx.fillRect(25, 25, 20, 20);


                    ctx.fillRect(130, 10, 50, 50);
                    ctx.fillStyle = "#ffffff";
                    ctx.fillRect(140, 20, 30, 30);
                    ctx.fillStyle = "#000000";
                    ctx.fillRect(145, 25, 20, 20);


                    ctx.fillRect(10, 130, 50, 50);
                    ctx.fillStyle = "#ffffff";
                    ctx.fillRect(20, 140, 30, 30);
                    ctx.fillStyle = "#000000";
                    ctx.fillRect(25, 145, 20, 20);


                    // Draw mock dot patterns
                    ctx.fillStyle = "#000000";
                    for (let x = 65; x < 125; x += 10) {
                        for (let y = 15; y < 175; y += 10) {
                            if (Math.random() > 0.4) ctx.fillRect(x, y, 6, 6);
                        }
                    }
                    for (let x = 15; x < 65; x += 10) {
                        for (let y = 65; y < 125; y += 10) {
                            if (Math.random() > 0.4) ctx.fillRect(x, y, 6, 6);
                        }
                    }
                    for (let x = 125; x < 175; x += 10) {
                        for (let y = 65; y < 175; y += 10) {
                            if (Math.random() > 0.4) ctx.fillRect(x, y, 6, 6);
                        }
                    }


                    // Bind data to download link
                    const downloadBtn = document.getElementById("download-qr-btn");
                    if (downloadBtn) {
                        downloadBtn.href = canvas.toDataURL("image/png");
                    }
}
