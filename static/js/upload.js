// ==========================================
// EXAMSHIELD - UPLOAD QUESTION PAPER CLIENT JS
// ==========================================
// Handles drag-and-drop dropzones, file type constraints validation,
// and file removal triggers.


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


    // 2. DRAG AND DROP HANDLERS
    const dropzone = document.getElementById("dropzone");
    const fileInput = document.getElementById("file-input");
    const fileCard = document.getElementById("file-info-card");
    const fileNameEl = document.getElementById("file-name");
    const fileSizeEl = document.getElementById("file-size");
    const removeBtn = document.getElementById("remove-file-btn");
    const submitBtn = document.getElementById("submit-btn");


    if (dropzone && fileInput) {
       
        // Open file dialog when clicking dropzone
        dropzone.addEventListener("click", () => {
            fileInput.click();
        });


        // Highlights drag-over active state
        const dragEvents = ["dragenter", "dragover"];
        dragEvents.forEach(eventName => {
            dropzone.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
                dropzone.classList.add("dragover");
            }, false);
        });


        const dragLeaveEvents = ["dragleave", "drop"];
        dragLeaveEvents.forEach(eventName => {
            dropzone.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
                dropzone.classList.remove("dragover");
            }, false);
        });


        // Drop file parsing
        dropzone.addEventListener("drop", (e) => {
            const dt = e.dataTransfer;
            const files = dt.files;
           
            if (files.length > 0) {
                fileInput.files = files; // Assign files to hidden input buffer
                validateAndDisplayFile(files[0]);
            }
        });


        // Manual file input select listener
        fileInput.addEventListener("change", (e) => {
            if (fileInput.files.length > 0) {
                validateAndDisplayFile(fileInput.files[0]);
            }
        });
    }


    // Validate size and extensions constraints
    function validateAndDisplayFile(file) {
        const allowedExtensions = [".pdf", ".docx", ".txt", ".png", ".jpg", ".jpeg"];
        const maxSizeBytes = 15 * 1024 * 1024; // 15MB limit
       
        const fileName = file.name;
        const fileExtension = fileName.substring(fileName.lastIndexOf(".")).toLowerCase();
       
        // 1. Validate Extension
        if (!allowedExtensions.includes(fileExtension)) {
            alert(`Format Error: Extension ${fileExtension} is not supported. Please upload a PDF, DOCX, TXT, or Image file.`);
            clearFileBuffer();
            return;
        }


        // 2. Validate Size limit
        if (file.size > maxSizeBytes) {
            alert("File Size Limit Exceeded: Question paper document cannot exceed 15MB.");
            clearFileBuffer();
            return;
        }


        // 3. Update File Card UI details
        if (fileNameEl && fileSizeEl && fileCard && submitBtn) {
            fileNameEl.innerText = file.name;
            fileSizeEl.innerText = formatBytes(file.size);
           
            fileCard.style.display = "flex";
            submitBtn.disabled = false;
        }
    }


    // Reset files selection
    function clearFileBuffer() {
        if (fileInput) fileInput.value = "";
        if (fileCard) fileCard.style.display = "none";
        if (submitBtn) submitBtn.disabled = true;
    }


    // Trigger clear action on removal button click
    if (removeBtn) {
        removeBtn.addEventListener("click", (e) => {
            e.stopPropagation(); // Stop click from triggering file dialog
            clearFileBuffer();
        });
    }


    // Format bytes to human readable string (KB, MB)
    function formatBytes(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const dm = 2;
        const sizes = ['Bytes', 'KB', 'MB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
    }
});


// ==========================================
// EXTRA UI ENHANCEMENTS
// ==========================================


// Auto-hide flash messages after 4 seconds
const alerts = document.querySelectorAll(".alert-box");


alerts.forEach(alert => {
    setTimeout(() => {
        alert.style.transition = "0.5s";
        alert.style.opacity = "0";
        alert.style.transform = "translateY(-10px)";


        setTimeout(() => {
            alert.remove();
        }, 500);


    }, 4000);
});


// Prevent multiple form submissions
const uploadForm = document.querySelector("form");


if (uploadForm && submitBtn) {


    uploadForm.addEventListener("submit", function () {


        submitBtn.disabled = true;


        submitBtn.innerHTML =
            '<i class="fa-solid fa-spinner fa-spin"></i> Uploading Secure Packet...';


    });


}
