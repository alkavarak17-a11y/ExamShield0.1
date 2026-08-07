// ==========================================
// EXAMSHIELD - LOGIN MODULE SCRIPT
// ==========================================
// Handles client-side biometric login using browser WebAuthn API,
// remember-me cookies, and redirects.

document.addEventListener("DOMContentLoaded", () => {
    // 1. DYNAMICALLY CREATE AND INJECT BIOMETRIC MODAL
    createModals();
    
    // Select DOM elements
    const bioBtn = document.querySelector(".bio-btn");
    const bioModal = document.getElementById("bio-modal");
    const cancelBioBtn = document.getElementById("cancel-bio");

    // 2. BIOMETRIC LOGIN WITH WEBAUTHN API & FALLBACK SIMULATION
    bioBtn.addEventListener("click", () => {
        // Check if browser supports WebAuthn
        if (!window.PublicKeyCredential) {
            alert("Biometric authentication (WebAuthn) is not supported on this device/browser.");
            return;
        }
        
        bioModal.classList.add("active");
        startBiometricVerify();
    });

    cancelBioBtn.addEventListener("click", () => {
        bioModal.classList.remove("active");
        resetBiometricScan();
    });

    // Close modal on clicking backdrop
    window.addEventListener("click", (e) => {
        if (e.target === bioModal) {
            bioModal.classList.remove("active");
            resetBiometricScan();
        }
    });

    // ===== BIOMETRIC OPERATIONS =====
    let scanTimeout;
    async function startBiometricVerify() {
        const statusText = document.getElementById("bio-status-text");
        const card = document.querySelector(".bio-modal-card");
        
        card.classList.add("scanning");
        statusText.innerText = "Initializing security hardware...";
        statusText.style.color = "#CBD5E1";

        // Inject simulated fallback action button in scan card if not already there
        let fallbackBtn = document.getElementById("bio-fallback-btn");
        if (!fallbackBtn) {
            fallbackBtn = document.createElement("button");
            fallbackBtn.type = "button";
            fallbackBtn.id = "bio-fallback-btn";
            fallbackBtn.className = "action-btn";
            fallbackBtn.style.marginTop = "15px";
            fallbackBtn.style.width = "100%";
            fallbackBtn.style.background = "#2563EB";
            fallbackBtn.style.color = "white";
            fallbackBtn.style.border = "none";
            fallbackBtn.style.borderRadius = "8px";
            fallbackBtn.style.padding = "10px";
            fallbackBtn.style.cursor = "pointer";
            fallbackBtn.innerText = "Simulate Biometric Verification";
            fallbackBtn.addEventListener("click", () => {
                triggerBiometricSuccess("Biometric Verification Successful (Simulation)");
            });
            const cancelBtn = document.getElementById("cancel-bio");
            cancelBtn.parentNode.insertBefore(fallbackBtn, cancelBtn);
        }
        fallbackBtn.style.display = "block";

        try {
            // Attempt standard WebAuthn verification
            statusText.innerText = "Waiting for device biometric response...";
            
            const challenge = new Uint8Array(32);
            window.crypto.getRandomValues(challenge);
            
            const publicKeyCredentialRequestOptions = {
                challenge: challenge,
                timeout: 5000,
                rpId: window.location.hostname,
                userVerification: "required"
            };

            // This triggers the browser native platform prompt (e.g. Windows Hello / TouchID)
            const credential = await navigator.credentials.get({
                publicKey: publicKeyCredentialRequestOptions
            });

            if (credential) {
                triggerBiometricSuccess("Biometric Verification Successful");
            } else {
                throw new Error("Biometric token missing.");
            }
        } catch (err) {
            console.warn("WebAuthn API unavailable or credentials not set. Simulator active.", err);
            statusText.innerText = "Biometric prompt active. Place finger on sensor or click Simulator below.";
        }
    }

    function triggerBiometricSuccess(message) {
        const card = document.querySelector(".bio-modal-card");
        const statusText = document.getElementById("bio-status-text");
        
        clearTimeout(scanTimeout);
        card.classList.remove("scanning");
        statusText.innerText = message;
        statusText.style.color = "#86EFAC";
        
        // Dynamic post back redirect to biometric authorization route
        const form = document.createElement("form");
        form.method = "POST";
        form.action = "/biometric-login";
        
        // Pass government ID if filled in the main form, otherwise backend defaults to testing account
        const mainGovId = document.querySelector('input[name="government_id"]').value;
        if (mainGovId) {
            const input = document.createElement("input");
            input.type = "hidden";
            input.name = "government_id";
            input.value = mainGovId;
            form.appendChild(input);
        }
        
        document.body.appendChild(form);
        setTimeout(() => {
            form.submit();
        }, 1200);
    }

    function resetBiometricScan() {
        clearTimeout(scanTimeout);
        const card = document.querySelector(".bio-modal-card");
        const statusText = document.getElementById("bio-status-text");
        card.classList.remove("scanning");
        statusText.innerText = "Ready to scan.";
        statusText.style.color = "#CBD5E1";
    }
});

// Helper function to inject Biometric Modal into page
function createModals() {
    if (document.getElementById("bio-modal")) return;

    const bioModalHtml = `
        <div id="bio-modal" class="modal-overlay">
            <div class="bio-modal-card">
                <h3 class="bio-title">🛡️ Biometric Identity Verification</h3>
                <div class="scanner-container">
                    <span class="scanner-laser"></span>
                    <i class="fa-solid fa-fingerprint fingerprint-icon"></i>
                </div>
                <p id="bio-status-text" class="bio-status">Ready to scan.</p>
                <button type="button" id="cancel-bio" class="cancel-modal-btn">Cancel</button>
            </div>
        </div>
    `;
    document.body.insertAdjacentHTML("beforeend", bioModalHtml);
}
