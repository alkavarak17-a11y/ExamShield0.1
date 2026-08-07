// ==========================================
// EXAMSHIELD - SECURECHAIN CLIENT JS
// ==========================================
// Handles block ledger traversals, staggered sequence verification,
// and AJAX post integrity checkups.


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


    // 2. STAGGERED BLOCK VERIFICATION SWEEP
    const verifyBtn = document.getElementById("verify-chain-btn");
    const examSelect = document.getElementById("exam_code_select");
    const blockCards = document.querySelectorAll(".block-card");
    const blockConnectors = document.querySelectorAll(".block-connector");


    if (verifyBtn && examSelect) {
        verifyBtn.addEventListener("click", () => {
            const examCode = examSelect.value;
            if (!examCode) {
                alert("Please select a target examination from the dropdown menu first.");
                return;
            }


            // Lock controls during validation sweep
            verifyBtn.disabled = true;
            examSelect.disabled = true;
            verifyBtn.innerText = "Verifying hashes...";


            // Clear previous styles
            blockCards.forEach(c => c.classList.remove("valid-sequence"));
            blockConnectors.forEach(c => c.classList.remove("verified"));


            // Submit AJAX request
            fetch("/verify_chain", {
                method: "POST",
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                body: `exam_code=${encodeURIComponent(examCode)}`
            })
            .then(response => response.json())
            .then(data => {
                if (data.status === "success") {
                   
                    // Run a staggered animation highlighting each block step by step
                    let index = 0;
                    const highlightNextBlock = () => {
                        if (index < blockCards.length) {
                            blockCards[index].classList.add("valid-sequence");
                           
                            // Highlight connecting arrow
                            if (index > 0 && blockConnectors[index - 1]) {
                                blockConnectors[index - 1].classList.add("verified");
                            }


                            index++;
                            setTimeout(highlightNextBlock, 300); // 300ms stagger delay
                        } else {
                            // Highlights complete, report integrity secure
                            verifyBtn.innerText = "Chain Verified & Secured";
                            verifyBtn.style.background = "#10b981";
                            verifyBtn.style.color = "white";
                           
                            // Show success banner
                            const alertContainer = document.createElement("div");
                            alertContainer.className = "alert-box success";
                            alertContainer.innerHTML = `<i class="fa-solid fa-circle-check"></i> Cryptographic chain check completed. Verification status: <b>SECURE</b>. Parent hashes match.`;
                            document.querySelector(".main-content").insertBefore(alertContainer, document.querySelector(".dna-card"));


                            // Unlock selector
                            examSelect.disabled = false;


                            // Automatically move to Tracking page after successful verification
                            setTimeout(() => {
                                window.location.href = `/tracking?exam_code=${encodeURIComponent(examCode)}`;
                            }, 1500);
                        }
                    };


                    // Start block traversal animation
                    highlightNextBlock();


                } else {
                    handleVerificationError(data.message || "Hash link mismatch detected.");
                }
            })
            .catch(error => {
                console.error("AJAX validation error: ", error);
                handleVerificationError("Network verification timeout.");
            });
        });
    }


    function handleVerificationError(message) {
        if (verifyBtn) {
            verifyBtn.disabled = false;
            verifyBtn.innerText = "Retry Verification Sweep";
            verifyBtn.style.background = "#ef4444";
        }
        if (examSelect) {
            examSelect.disabled = false;
        }
        alert(`Validation Error: ${message}`);
    }


    // 3. COPY DNA HASH TO CLIPBOARD
    const copyIcon = document.getElementById("copy-dna-icon");
    const dnaHashEl = document.getElementById("dna-hash-text");


    if (copyIcon && dnaHashEl) {
        copyIcon.addEventListener("click", () => {
            const range = document.createRange();
            range.selectNode(dnaHashEl);
            window.getSelection().removeAllRanges();
            window.getSelection().addRange(range);
           
            try {
                document.execCommand("copy");
                alert("SHA-256 Exam DNA copied to clipboard.");
            } catch (err) {
                console.error("Copy failed: ", err);
            }
            window.getSelection().removeAllRanges();
        });
    }
});
   
