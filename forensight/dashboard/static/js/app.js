/* ============================================================================
   ForenSight // SOC & DFIR Client-Side Workbench Controller
   ============================================================================ */

document.addEventListener("DOMContentLoaded", () => {
    // 1. Live UTC Clock for Forensic Timestamp Correlation
    const clockEl = document.getElementById("soc-utc-clock");
    if (clockEl) {
        const updateClock = () => {
            const now = new Date();
            const iso = now.toISOString().replace("T", " ").substring(0, 19);
            clockEl.textContent = `UTC ${iso}`;
        };
        updateClock();
        setInterval(updateClock, 1000);
    }

    // 2. Workbench Tab Switching
    const tabButtons = document.querySelectorAll(".tab-btn");
    tabButtons.forEach((btn) => {
        btn.addEventListener("click", () => {
            const targetId = btn.getAttribute("data-tab");
            document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
            document.querySelectorAll(".tab-pane").forEach((p) => p.classList.remove("active"));
            btn.classList.add("active");
            const pane = document.getElementById(targetId);
            if (pane) pane.classList.add("active");
        });
    });

    // 3. True Drag-and-Drop + File Selection Ingestion
    const dropzone = document.getElementById("soc-dropzone");
    const fileInput = document.getElementById("file-input");
    const uploadForm = document.getElementById("upload-form");
    const dropzoneLabel = document.getElementById("dropzone-label");

    const submitIngestion = (filename) => {
        if (!uploadForm || !dropzone) return;
        dropzone.classList.add("uploading");
        if (dropzoneLabel) {
            dropzoneLabel.textContent = `Ingesting "${filename}" — Computing SHA-256/SHA-1/MD5 & Running Static Analyzers...`;
        }
        uploadForm.submit();
    };

    if (fileInput && uploadForm) {
        fileInput.addEventListener("change", () => {
            if (fileInput.files && fileInput.files.length > 0) {
                submitIngestion(fileInput.files[0].name);
            }
        });
    }

    if (dropzone && fileInput) {
        ["dragenter", "dragover"].forEach((evt) => {
            dropzone.addEventListener(evt, (e) => {
                e.preventDefault();
                e.stopPropagation();
                dropzone.classList.add("drag-over");
            });
        });

        ["dragleave", "drop"].forEach((evt) => {
            dropzone.addEventListener(evt, (e) => {
                e.preventDefault();
                e.stopPropagation();
                dropzone.classList.remove("drag-over");
            });
        });

        dropzone.addEventListener("drop", (e) => {
            const files = e.dataTransfer && e.dataTransfer.files;
            if (files && files.length > 0) {
                const dt = new DataTransfer();
                dt.items.add(files[0]);
                fileInput.files = dt.files;
                submitIngestion(files[0].name);
            }
        });
    }

    // 4. Case Modal Controls + Escape Key
    window.openNewCaseModal = function () {
        const modal = document.getElementById("new-case-modal");
        if (modal) modal.classList.add("open");
    };
    window.closeNewCaseModal = function () {
        const modal = document.getElementById("new-case-modal");
        if (modal) modal.classList.remove("open");
    };
    document.addEventListener("keydown", (e) => {
        if (e.key === "Escape") window.closeNewCaseModal();
    });

    // 5. Evidence Queue Filter & Search
    const queueSearch = document.getElementById("queue-search");
    const queueFilterChips = document.querySelectorAll('[data-filter-group="queue"] .filter-chip');
    let activeQueueFilter = "ALL";

    const applyQueueFilter = () => {
        const query = queueSearch ? queueSearch.value.trim().toLowerCase() : "";
        document.querySelectorAll(".queue-row").forEach((row) => {
            const type = (row.getAttribute("data-type") || "").toUpperCase();
            const flagged = row.getAttribute("data-flagged") === "true";
            const haystack = row.getAttribute("data-search") || "";

            let matchesType = true;
            if (activeQueueFilter === "FLAGGED") {
                matchesType = flagged;
            } else if (activeQueueFilter === "DOC") {
                matchesType = type.startsWith("DOC");
            } else if (activeQueueFilter !== "ALL") {
                matchesType = type === activeQueueFilter;
            }

            const matchesQuery = !query || haystack.includes(query);
            row.style.display = matchesType && matchesQuery ? "" : "none";
        });
    };

    queueFilterChips.forEach((chip) => {
        chip.addEventListener("click", () => {
            queueFilterChips.forEach((c) => c.classList.remove("active"));
            chip.classList.add("active");
            activeQueueFilter = chip.getAttribute("data-filter") || "ALL";
            applyQueueFilter();
        });
    });
    if (queueSearch) queueSearch.addEventListener("input", applyQueueFilter);

    // 6. Cases Search
    const caseSearch = document.getElementById("case-search");
    if (caseSearch) {
        caseSearch.addEventListener("input", () => {
            const query = caseSearch.value.trim().toLowerCase();
            document.querySelectorAll(".case-row").forEach((row) => {
                const haystack = row.getAttribute("data-search") || "";
                row.style.display = !query || haystack.includes(query) ? "" : "none";
            });
        });
    }

    // 7. Findings Severity Filter
    const findingChips = document.querySelectorAll('[data-filter-group="findings"] .filter-chip');
    findingChips.forEach((chip) => {
        chip.addEventListener("click", () => {
            findingChips.forEach((c) => c.classList.remove("active"));
            chip.classList.add("active");
            const filter = chip.getAttribute("data-filter") || "ALL";

            document.querySelectorAll(".finding-row").forEach((row) => {
                const sev = row.getAttribute("data-severity") || "INFO";
                let show = true;
                if (filter === "CRIT_HIGH") show = sev === "CRITICAL" || sev === "HIGH";
                else if (filter === "MEDIUM") show = sev === "MEDIUM";
                else if (filter === "LOW_INFO") show = sev === "LOW" || sev === "INFO";
                row.style.display = show ? "" : "none";
            });
        });
    });

    // 8. IOC Intelligence Filter, Search & Copy All Defanged
    const iocSearch = document.getElementById("ioc-search");
    const iocChips = document.querySelectorAll('[data-filter-group="iocs"] .filter-chip');
    let activeIocFilter = "ALL";

    const applyIocFilter = () => {
        const query = iocSearch ? iocSearch.value.trim().toLowerCase() : "";
        document.querySelectorAll(".ioc-row").forEach((row) => {
            const iocType = (row.getAttribute("data-ioc-type") || "").toUpperCase();
            const haystack = row.getAttribute("data-search") || "";
            const matchesType =
                activeIocFilter === "ALL" ||
                iocType.includes(activeIocFilter);
            const matchesQuery = !query || haystack.includes(query);
            row.style.display = matchesType && matchesQuery ? "" : "none";
        });
    };

    iocChips.forEach((chip) => {
        chip.addEventListener("click", () => {
            iocChips.forEach((c) => c.classList.remove("active"));
            chip.classList.add("active");
            activeIocFilter = chip.getAttribute("data-filter") || "ALL";
            applyIocFilter();
        });
    });
    if (iocSearch) iocSearch.addEventListener("input", applyIocFilter);

    const copyAllIocsBtn = document.getElementById("btn-copy-all-iocs");
    if (copyAllIocsBtn) {
        copyAllIocsBtn.addEventListener("click", () => {
            const visibleIocs = [];
            document.querySelectorAll(".ioc-row").forEach((row) => {
                if (row.style.display !== "none") {
                    const cell = row.querySelector(".ioc-value-cell");
                    if (cell) visibleIocs.push(cell.textContent.trim());
                }
            });
            if (visibleIocs.length > 0) {
                window.copyToClipboard(visibleIocs.join("\n"), copyAllIocsBtn);
            }
        });
    }

    // 9. Structural Inspector <-> Raw JSON Toggle
    const toggleJsonBtn = document.getElementById("btn-toggle-raw-json");
    if (toggleJsonBtn) {
        toggleJsonBtn.addEventListener("click", () => {
            const tableEl = document.getElementById("structured-inspector");
            const rawEl = document.getElementById("raw-json-terminal");
            if (!tableEl || !rawEl) return;
            const showingRaw = rawEl.style.display !== "none";
            rawEl.style.display = showingRaw ? "none" : "block";
            tableEl.style.display = showingRaw ? "block" : "none";
            toggleJsonBtn.textContent = showingRaw ? "Toggle Raw JSON" : "Toggle Table View";
        });
    }

    // 10. Copy Helper
    window.copyToClipboard = function (text, btnElement) {
        if (!navigator.clipboard) return;
        navigator.clipboard.writeText(text).then(() => {
            const originalText = btnElement.innerText;
            btnElement.innerText = "Copied";
            btnElement.style.borderColor = "var(--success)";
            btnElement.style.color = "var(--success)";
            setTimeout(() => {
                btnElement.innerText = originalText;
                btnElement.style.borderColor = "";
                btnElement.style.color = "";
            }, 1500);
        });
    };

    // 11. Live Cryptographic Vault Integrity Verification
    const verifyBtn = document.getElementById("btn-verify-integrity");
    if (verifyBtn) {
        verifyBtn.addEventListener("click", async () => {
            const evidenceId = verifyBtn.getAttribute("data-evidence-id");
            verifyBtn.disabled = true;
            verifyBtn.innerText = "Auditing Vault...";

            try {
                const response = await fetch(`/api/v1/evidence/${evidenceId}/verify`, { method: "POST" });
                const result = await response.json();

                const statusBox = document.getElementById("integrity-result-box");
                if (statusBox) {
                    const vStatus = result.verification_status || (result.is_valid ? "INTEGRITY VERIFIED" : "EVIDENCE MODIFIED");
                    statusBox.style.display = "block";
                    statusBox.textContent = "";
                    const titleEl = document.createElement("strong");
                    const msgEl = document.createElement("span");

                    if (vStatus === "INTEGRITY VERIFIED") {
                        statusBox.className = "badge-success";
                        titleEl.textContent = `[PASS] ${vStatus}: `;
                        msgEl.textContent = `SHA-256 (${(result.computed_sha256 || "").slice(0, 16)}...) & size (${result.computed_size_bytes} B) matched; Ed25519 manifest & custody chain verified.`;
                    } else if (vStatus === "VERIFICATION INCONCLUSIVE") {
                        statusBox.className = "badge-warning";
                        titleEl.textContent = `[WARN] ${vStatus}: `;
                        msgEl.textContent = result.combined_details || result.details || "Partial verification only.";
                    } else {
                        statusBox.className = "badge-critical";
                        titleEl.textContent = `[ALERT] ${vStatus}: `;
                        msgEl.textContent = result.combined_details || result.details || "Cryptographic or file integrity mismatch.";
                    }
                    statusBox.appendChild(titleEl);
                    statusBox.appendChild(msgEl);
                }
            } catch (err) {
                const statusBox = document.getElementById("integrity-result-box");
                if (statusBox) {
                    statusBox.style.display = "block";
                    statusBox.className = "badge-critical";
                    statusBox.textContent = "Integrity verification request failed: " + (err && err.message ? err.message : String(err));
                }
            } finally {
                verifyBtn.disabled = false;
                verifyBtn.innerText = "Verify Vault Integrity";
            }
        });
    }
});
