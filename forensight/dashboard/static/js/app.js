/* ForenSight Dashboard Client-Side Helper */

document.addEventListener("DOMContentLoaded", () => {
    // Tab Switching
    const tabButtons = document.querySelectorAll(".tab-btn");
    tabButtons.forEach(btn => {
        btn.addEventListener("click", () => {
            const targetId = btn.getAttribute("data-tab");
            
            // Deactivate all
            document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
            document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));

            // Activate chosen
            btn.classList.add("active");
            const pane = document.getElementById(targetId);
            if (pane) pane.classList.add("active");
        });
    });

    // Copy Defanged IOC Helper
    window.copyToClipboard = function(text, btnElement) {
        navigator.clipboard.writeText(text).then(() => {
            const originalText = btnElement.innerText;
            btnElement.innerText = "Copied!";
            btnElement.classList.add("btn-outline");
            setTimeout(() => {
                btnElement.innerText = originalText;
                btnElement.classList.remove("btn-outline");
            }, 1800);
        });
    };

    // Live Integrity Verification Trigger
    const verifyBtn = document.getElementById("btn-verify-integrity");
    if (verifyBtn) {
        verifyBtn.addEventListener("click", async () => {
            const evidenceId = verifyBtn.getAttribute("data-evidence-id");
            verifyBtn.disabled = true;
            verifyBtn.innerText = "Auditing Cryptographic Vault...";

            try {
                const response = await fetch(`/api/v1/evidence/${evidenceId}/verify`, { method: "POST" });
                const result = await response.json();

                const statusBox = document.getElementById("integrity-result-box");
                if (statusBox) {
                    statusBox.style.display = "block";
                    if (result.is_valid) {
                        statusBox.className = "card badge-success";
                        statusBox.innerHTML = `<strong>INTEGRITY VERIFIED:</strong> Live hashes match recorded acquisition digests exactly. Storage boundary intact.`;
                    } else {
                        statusBox.className = "card badge-danger";
                        statusBox.innerHTML = `<strong>INTEGRITY COMPROMISED:</strong> Discrepancy detected: ${result.details}`;
                    }
                }
            } catch (err) {
                alert("Integrity verification request failed: " + err);
            } finally {
                verifyBtn.disabled = false;
                verifyBtn.innerText = "Re-Verify Vault Integrity";
            }
        });
    }
});

