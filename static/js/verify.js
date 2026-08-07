// ==========================================
// EXAMSHIELD - 2FA VERIFICATION SCRIPT
// ==========================================
// Handles cursor navigation, auto-focus, paste actions
// and combines the 6 OTP input digits for Flask submission.

document.addEventListener("DOMContentLoaded", () => {
    const otpInputs = document.querySelectorAll(".otp-input");
    const verifyForm = document.querySelector("form");
    
    // Create hidden input dynamically to hold the combined 6-digit OTP code
    const hiddenOtpInput = document.createElement("input");
    hiddenOtpInput.type = "hidden";
    hiddenOtpInput.name = "otp";
    hiddenOtpInput.id = "otp-code";
    verifyForm.appendChild(hiddenOtpInput);

    // Focus on the first input on load
    if (otpInputs.length > 0) {
        otpInputs[0].focus();
    }

    // Loop through each input box
    otpInputs.forEach((input, index) => {
        // Handle input events (typing)
        input.addEventListener("input", (e) => {
            // Ensure only digits are typed
            input.value = input.value.replace(/[^0-9]/g, "");
            
            // Move cursor to the next input box if a value is typed
            if (input.value.length === 1 && index < otpInputs.length - 1) {
                otpInputs[index + 1].focus();
            }
        });

        // Handle keydown events (Backspace, Left/Right arrow keys)
        input.addEventListener("keydown", (e) => {
            if (e.key === "Backspace") {
                // If current input is empty, clear the previous input and focus it
                if (input.value.length === 0 && index > 0) {
                    otpInputs[index - 1].value = "";
                    otpInputs[index - 1].focus();
                } else {
                    input.value = "";
                }
                e.preventDefault();
            } else if (e.key === "ArrowLeft" && index > 0) {
                otpInputs[index - 1].focus();
            } else if (e.key === "ArrowRight" && index < otpInputs.length - 1) {
                otpInputs[index + 1].focus();
            }
        });

        // Handle Paste events
        input.addEventListener("paste", (e) => {
            e.preventDefault();
            // Get pasted data
            const pasteData = (e.clipboardData || window.clipboardData).getData("text").trim();
            
            // Validate that paste data contains digits and check length
            if (/^\d+$/.test(pasteData)) {
                const digits = pasteData.split("");
                
                // Distribute characters into the inputs starting from current index
                let currentIdx = index;
                for (let i = 0; i < digits.length && currentIdx < otpInputs.length; i++) {
                    otpInputs[currentIdx].value = digits[i];
                    currentIdx++;
                }
                
                // Focus the next empty box or the last box
                const focusIndex = Math.min(currentIdx, otpInputs.length - 1);
                otpInputs[focusIndex].focus();
            }
        });
    });

    // Before submit, merge the 6 digits into the single hidden input
    verifyForm.addEventListener("submit", (e) => {
        let combinedCode = "";
        otpInputs.forEach(input => {
            combinedCode += input.value;
        });

        if (combinedCode.length !== 6) {
            e.preventDefault();
            alert("Security Protocol: Please enter the complete 6-digit verification code.");
            return;
        }

        hiddenOtpInput.value = combinedCode;
    });

    // ===== COUNTDOWN TIMER & RESEND OTP FUNCTIONALITY =====
    const countdownTimer = document.getElementById("countdown-timer");
    const resendBtn = document.getElementById("resend-btn");
    const verifyBtn = document.querySelector(".verify-btn");
    
    let timerDuration = 300; // 5 minutes in seconds
    let timerInterval;

    function startTimer() {
        clearInterval(timerInterval);
        timerDuration = 300; // Reset to 300 seconds
        
        // Ensure inputs are enabled and clear
        resendBtn.disabled = true;
        otpInputs.forEach(input => {
            input.disabled = false;
            input.value = "";
        });
        if (otpInputs.length > 0) {
            otpInputs[0].focus();
        }
        verifyBtn.disabled = false;
        
        timerInterval = setInterval(() => {
            const minutes = Math.floor(timerDuration / 60);
            const seconds = timerDuration % 60;
            
            countdownTimer.innerText = 
                `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
            
            if (timerDuration <= 0) {
                clearInterval(timerInterval);
                expireOtp();
            }
            timerDuration--;
        }, 1000);
    }

    function expireOtp() {
        otpInputs.forEach(input => {
            input.disabled = true;
        });
        verifyBtn.disabled = true;
        resendBtn.disabled = false;
        
        // Find or create flash message container dynamically
        let flashContainer = document.querySelector(".flash-messages");
        if (!flashContainer) {
            flashContainer = document.createElement("ul");
            flashContainer.className = "flash-messages";
            const box = document.querySelector(".verification-box");
            box.insertBefore(flashContainer, box.querySelector("form"));
        }
        flashContainer.innerHTML = `
            <li class="flash-message error">
                <i class="fa-solid fa-triangle-exclamation"></i> OTP Expired. Please request a new OTP.
            </li>
        `;
    }

    // Start timer on load
    startTimer();

    // Handle Resend OTP click
    resendBtn.addEventListener("click", () => {
        resendBtn.disabled = true;
        
        fetch("/resend-otp", {
            method: "POST",
            headers: {
                "X-Requested-With": "XMLHttpRequest"
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === "success") {
                // Clear any error messages and show success
                let flashContainer = document.querySelector(".flash-messages");
                if (!flashContainer) {
                    flashContainer = document.createElement("ul");
                    flashContainer.className = "flash-messages";
                    const box = document.querySelector(".verification-box");
                    box.insertBefore(flashContainer, box.querySelector("form"));
                }
                flashContainer.innerHTML = `
                    <li class="flash-message success">
                        <i class="fa-solid fa-circle-check"></i> ${data.message}
                    </li>
                `;
                // Restart timer
                startTimer();
            } else {
                alert("Security Error: " + data.message);
                resendBtn.disabled = false;
            }
        })
        .catch(err => {
            console.error("Resend error:", err);
            alert("Network connection error. Failed to resend verification code.");
            resendBtn.disabled = false;
        });
    });
});
