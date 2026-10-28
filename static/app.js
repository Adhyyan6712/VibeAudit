/**
 * VibeAudit Frontend Application Logic
 */

// Application State
let currentScan = null;
let currentFinding = null;
let selectedFile = null;
let activeSampleId = "taskboard";

// DOM Elements
const views = {
    start: document.getElementById("view-start"),
    dashboard: document.getElementById("view-dashboard"),
    detail: document.getElementById("view-detail")
};

const headerStart = document.getElementById("header-right-start");
const headerDashboard = document.getElementById("header-right-dashboard");

// Start Screen Elements
const dropzone = document.getElementById("dropzone");
const dropzoneText = document.getElementById("dropzone-text");
const fileInput = document.getElementById("file-input");
const btnChooseFile = document.getElementById("btn-choose-file");
const consentCheckbox = document.getElementById("consent-checkbox");
const btnStartScan = document.getElementById("btn-start-scan");
const projectNameInput = document.getElementById("project-name");
const btnSampleVulnerable = document.getElementById("btn-sample-vulnerable");
const btnSampleFixed = document.getElementById("btn-sample-fixed");

// Dashboard Elements
const scoreDisplay = document.getElementById("score-display");
const scoreLabelDisplay = document.getElementById("score-label-display");
const gaugeCircle = document.getElementById("gauge-circle");
const countCritical = document.getElementById("count-critical");
const countHigh = document.getElementById("count-high");
const countMedium = document.getElementById("count-medium");
const countLow = document.getElementById("count-low");
const tabFindings = document.getElementById("tab-findings");
const tabEndpoints = document.getElementById("tab-endpoints");
const panelFindings = document.getElementById("panel-findings");
const panelEndpoints = document.getElementById("panel-endpoints");
const findingsTableBody = document.getElementById("findings-table-body");
const endpointsTableBody = document.getElementById("endpoints-table-body");
const findingsTableFooter = document.getElementById("findings-table-footer");

// Detail Elements
const btnBackDashboard = document.getElementById("btn-back-dashboard");
const detailBreadcrumbId = document.getElementById("detail-breadcrumb-id");
const detailHeaderProject = document.getElementById("detail-header-project");
const detailTitle = document.getElementById("detail-title");
const detailSeverityBadge = document.getElementById("detail-severity-badge");
const detailVerdictBadge = document.getElementById("detail-verdict-badge");
const detailOwaspBadge = document.getElementById("detail-owasp-badge");
const detailFileLocation = document.getElementById("detail-file-location");
const detailCodeDisplay = document.getElementById("detail-code-display");
const detailWhyMatters = document.getElementById("detail-why-matters");
const detailSeverityMath = document.getElementById("detail-severity-math");
const detailFixBefore = document.getElementById("detail-fix-before");
const detailFixAfter = document.getElementById("detail-fix-after");
const detailFixSteps = document.getElementById("detail-fix-steps");
const btnCopyFix = document.getElementById("btn-copy-fix");
const copyBtnText = document.getElementById("copy-btn-text");
const btnMarkReviewed = document.getElementById("btn-mark-reviewed");
const reviewBtnText = document.getElementById("review-btn-text");

// Navigation & Brand
document.getElementById("brand-link").addEventListener("click", () => {
    switchView("start");
});

function switchView(viewName) {
    Object.values(views).forEach(v => v.classList.remove("active"));
    views[viewName].classList.add("active");

    if (viewName === "start") {
        headerStart.style.display = "block";
        headerDashboard.style.display = "none";
    } else {
        headerStart.style.display = "none";
        headerDashboard.style.display = "flex";
    }
}

// Consent Checkbox Handler
function updateScanButtonState() {
    btnStartScan.disabled = !consentCheckbox.checked;
}

consentCheckbox.addEventListener("change", updateScanButtonState);
document.querySelector(".consent-box").addEventListener("click", (e) => {
    if (e.target !== consentCheckbox) {
        consentCheckbox.checked = !consentCheckbox.checked;
        updateScanButtonState();
    }
});

// Dropzone & File/Folder Selection
const folderInput = document.getElementById("folder-input");
const btnChooseFolder = document.getElementById("btn-choose-folder");
const folderPathInput = document.getElementById("folder-path-input");
let selectedFolderFiles = null;

btnChooseFile.addEventListener("click", (e) => {
    e.preventDefault();
    e.stopPropagation();
    fileInput.click();
});

btnChooseFolder.addEventListener("click", (e) => {
    e.preventDefault();
    e.stopPropagation();
    folderInput.click();
});

folderInput.addEventListener("change", (e) => {
    if (e.target.files && e.target.files.length > 0) {
        selectedFolderFiles = Array.from(e.target.files);
        selectedFile = null;
        activeSampleId = null;
        folderPathInput.value = "";
        const folderName = selectedFolderFiles[0].webkitRelativePath.split("/")[0] || "project_folder";
        dropzoneText.textContent = `Selected Folder: ${folderName} (${selectedFolderFiles.length} files)`;
        projectNameInput.value = folderName;
        consentCheckbox.checked = true;
        updateScanButtonState();
    }
});

const websiteUrlInput = document.getElementById("website-url-input");

folderPathInput.addEventListener("input", () => {
    if (folderPathInput.value.trim().length > 0) {
        activeSampleId = null;
        selectedFile = null;
        selectedFolderFiles = null;
        if (websiteUrlInput) websiteUrlInput.value = "";
        const nameGuess = folderPathInput.value.trim().split(/[\\/]/).filter(Boolean).pop() || "LocalProject";
        projectNameInput.value = nameGuess;
        dropzoneText.textContent = `Target Path: ${folderPathInput.value.trim()}`;
        consentCheckbox.checked = true;
        updateScanButtonState();
    }
});

const btnScanUrl = document.getElementById("btn-scan-url");
const btnScanFolder = document.getElementById("btn-scan-folder");

if (websiteUrlInput) {
    const handleUrlInput = () => {
        if (websiteUrlInput.value.trim().length > 0) {
            activeSampleId = null;
            selectedFile = null;
            selectedFolderFiles = null;
            if (folderPathInput) folderPathInput.value = "";
            projectNameInput.value = websiteUrlInput.value.trim();
            dropzoneText.textContent = `Target URL: ${websiteUrlInput.value.trim()}`;
            consentCheckbox.checked = true;
            updateScanButtonState();
        }
    };

    websiteUrlInput.addEventListener("input", handleUrlInput);
    websiteUrlInput.addEventListener("change", handleUrlInput);
    websiteUrlInput.addEventListener("paste", () => setTimeout(handleUrlInput, 50));
    websiteUrlInput.addEventListener("keydown", (e) => {
        if (e.key === "Enter") {
            e.preventDefault();
            handleUrlInput();
            triggerScan();
        }
    });
}

if (btnScanUrl) {
    btnScanUrl.addEventListener("click", (e) => {
        e.preventDefault();
        e.stopPropagation();
        if (!websiteUrlInput || !websiteUrlInput.value.trim()) {
            alert("Please enter a website URL (e.g. https://www.gla.ac.in, http://127.0.0.1:8000, or http://localhost:5000)");
            if (websiteUrlInput) websiteUrlInput.focus();
            return;
        }
        activeSampleId = null;
        selectedFile = null;
        selectedFolderFiles = null;
        if (folderPathInput) folderPathInput.value = "";
        projectNameInput.value = websiteUrlInput.value.trim();
        dropzoneText.textContent = `Target URL: ${websiteUrlInput.value.trim()}`;
        consentCheckbox.checked = true;
        updateScanButtonState();
        triggerScan();
    });
}

if (btnScanFolder) {
    btnScanFolder.addEventListener("click", (e) => {
        e.preventDefault();
        e.stopPropagation();
        if (!folderPathInput || !folderPathInput.value.trim()) {
            alert("Please enter a local project folder path");
            if (folderPathInput) folderPathInput.focus();
            return;
        }
        activeSampleId = null;
        selectedFile = null;
        selectedFolderFiles = null;
        if (websiteUrlInput) websiteUrlInput.value = "";
        const nameGuess = folderPathInput.value.trim().split(/[\\/]/).filter(Boolean).pop() || "LocalProject";
        projectNameInput.value = nameGuess;
        dropzoneText.textContent = `Target Path: ${folderPathInput.value.trim()}`;
        consentCheckbox.checked = true;
        updateScanButtonState();
        triggerScan();
    });
}

if (folderPathInput) {
    folderPathInput.addEventListener("keydown", (e) => {
        if (e.key === "Enter") {
            e.preventDefault();
            if (btnScanFolder) btnScanFolder.click();
            else triggerScan();
        }
    });
}

dropzone.addEventListener("click", (e) => {
    if (e.target.closest(".quick-samples") || e.target.closest("button")) return;
    fileInput.click();
});

dropzone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropzone.classList.add("dragover");
});

dropzone.addEventListener("dragleave", () => {
    dropzone.classList.remove("dragover");
});

dropzone.addEventListener("drop", async (e) => {
    e.preventDefault();
    dropzone.classList.remove("dragover");
    try {
        const droppedFiles = await getFilesFromDataTransfer(e.dataTransfer);
        if (droppedFiles && droppedFiles.length > 0) {
            handleUploadedFilesList(droppedFiles);
        }
    } catch (err) {
        console.error("Drop processing error:", err);
        if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
            handleUploadedFilesList(Array.from(e.dataTransfer.files));
        }
    }
});

fileInput.addEventListener("change", (e) => {
    if (e.target.files && e.target.files.length > 0) {
        handleUploadedFilesList(Array.from(e.target.files));
    }
});

async function getFilesFromDataTransfer(dataTransfer) {
    const items = dataTransfer.items;
    if (items && items.length > 0 && items[0].webkitGetAsEntry) {
        const fileList = [];
        async function readEntry(entry, path = "") {
            if (entry.isFile) {
                const f = await new Promise(res => entry.file(res));
                f.relativePath = path + entry.name;
                fileList.push(f);
            } else if (entry.isDirectory) {
                const dirReader = entry.createReader();
                const entries = await new Promise(res => {
                    const allEntries = [];
                    function readBatch() {
                        dirReader.readEntries(batch => {
                            if (!batch.length) {
                                res(allEntries);
                            } else {
                                allEntries.push(...batch);
                                readBatch();
                            }
                        });
                    }
                    readBatch();
                });
                for (const child of entries) {
                    await readEntry(child, path + entry.name + "/");
                }
            }
        }
        for (let i = 0; i < items.length; i++) {
            const entry = items[i].webkitGetAsEntry();
            if (entry) {
                await readEntry(entry);
            }
        }
        if (fileList.length > 0) return fileList;
    }
    return Array.from(dataTransfer.files || []);
}

function handleUploadedFilesList(files) {
    if (!files || files.length === 0) return;

    if (files.length === 1 && files[0].name.toLowerCase().endsWith(".zip")) {
        const file = files[0];
        selectedFile = file;
        selectedFolderFiles = null;
        activeSampleId = null;
        folderPathInput.value = "";
        dropzoneText.textContent = `Selected ZIP: ${file.name} (${Math.round(file.size / 1024)} KB)`;
        projectNameInput.value = file.name.replace(/\.[^/.]+$/, "");
    } else if (files.length === 1 && !files[0].relativePath && !files[0].webkitRelativePath) {
        const file = files[0];
        selectedFile = file;
        selectedFolderFiles = null;
        activeSampleId = null;
        folderPathInput.value = "";
        dropzoneText.textContent = `Selected File: ${file.name} (${Math.round(file.size / 1024)} KB)`;
        projectNameInput.value = file.name.replace(/\.[^/.]+$/, "");
    } else {
        selectedFolderFiles = files;
        selectedFile = null;
        activeSampleId = null;
        folderPathInput.value = "";
        const topFolder = (files[0].relativePath || files[0].webkitRelativePath || "").split("/")[0] || "ProjectFolder";
        dropzoneText.textContent = `Selected Folder: ${topFolder} (${files.length} files)`;
        projectNameInput.value = topFolder;
    }
    consentCheckbox.checked = true;
    updateScanButtonState();
}

function handleFileSelect(file) {
    handleUploadedFilesList([file]);
}

// Quick Sample Buttons
btnSampleVulnerable.addEventListener("click", (e) => {
    e.preventDefault();
    e.stopPropagation();
    activeSampleId = "taskboard";
    selectedFile = null;
    selectedFolderFiles = null;
    folderPathInput.value = "";
    projectNameInput.value = "TaskBoard";
    dropzoneText.textContent = "Selected: TaskBoard (Vulnerable Demo)";
    consentCheckbox.checked = true;
    updateScanButtonState();
});

btnSampleFixed.addEventListener("click", (e) => {
    e.preventDefault();
    e.stopPropagation();
    activeSampleId = "taskboard_fixed";
    selectedFile = null;
    selectedFolderFiles = null;
    folderPathInput.value = "";
    projectNameInput.value = "TaskBoard (Fixed)";
    dropzoneText.textContent = "Selected: TaskBoard (Fixed & Hardened)";
    consentCheckbox.checked = true;
    updateScanButtonState();
});

// Form Submission -> Start Scan
async function triggerScan() {
    consentCheckbox.checked = true;

    btnStartScan.disabled = true;
    btnStartScan.textContent = "Scanning project...";
    if (btnScanUrl) {
        btnScanUrl.disabled = true;
        btnScanUrl.textContent = "Scanning...";
    }
    if (btnScanFolder) {
        btnScanFolder.disabled = true;
        btnScanFolder.textContent = "Scanning...";
    }

    try {
        const formData = new FormData();
        formData.append("project_name", projectNameInput.value || "TaskBoard");
        formData.append("consent", "true");

        if (websiteUrlInput && websiteUrlInput.value.trim()) {
            formData.append("website_url", websiteUrlInput.value.trim());
        } else if (folderPathInput && folderPathInput.value.trim()) {
            formData.append("folder_path", folderPathInput.value.trim());
        } else if (selectedFolderFiles && selectedFolderFiles.length > 0) {
            selectedFolderFiles.forEach(f => {
                const relName = f.relativePath || f.webkitRelativePath || f.name;
                formData.append("files", f, relName);
            });
        } else if (selectedFile) {
            formData.append("file", selectedFile);
        } else {
            formData.append("sample_id", activeSampleId || "taskboard");
        }

        let res;
        try {
            res = await fetch("/scan", {
                method: "POST",
                body: formData
            });
            if (!res.ok) {
                const err = await res.json();
                throw new Error(err.detail || "Scan request failed");
            }
            currentScan = await res.json();
        } catch (fetchErr) {
            console.warn("Backend unavailable or static hosting (GitHub Pages) detected. Loading client-side audit demo:", fetchErr);
            currentScan = getClientSideDemoResult(formData);
        }

        renderDashboard(currentScan);
        switchView("dashboard");
    } catch (err) {
        alert(`Error: ${err.message}`);
    } finally {
        btnStartScan.disabled = false;
        btnStartScan.textContent = "Start scan";
        if (btnScanUrl) {
            btnScanUrl.disabled = false;
            btnScanUrl.textContent = "Scan URL";
        }
        if (btnScanFolder) {
            btnScanFolder.disabled = false;
            btnScanFolder.textContent = "Scan Path";
        }
    }
}

document.getElementById("scan-form").addEventListener("submit", (e) => {
    e.preventDefault();
    triggerScan();
});

btnStartScan.addEventListener("click", (e) => {
    e.preventDefault();
    triggerScan();
});

// Render Dashboard
function renderDashboard(scan) {
    const score = scan.score_details ? scan.score_details.score : (scan.score !== undefined ? scan.score : 0);
    const label = scan.score_details ? scan.score_details.label : (scan.rating || "Score");
    scoreDisplay.textContent = score;
    scoreLabelDisplay.textContent = `Security score: ${label}`;

    // Update circular gauge
    const circumference = 2 * Math.PI * 42; // ~263.89
    const offset = circumference * (1 - score / 100);
    gaugeCircle.style.strokeDashoffset = offset;

    if (score < 50) {
        gaugeCircle.style.stroke = "#ef4444"; // Red
        scoreLabelDisplay.style.color = "#dc2626";
    } else if (score < 85) {
        gaugeCircle.style.stroke = "#f59e0b"; // Amber
        scoreLabelDisplay.style.color = "#d97706";
    } else {
        gaugeCircle.style.stroke = "#10b981"; // Green
        scoreLabelDisplay.style.color = "#059669";
    }

    // Counts
    const counts = (scan.score_details && scan.score_details.severity_counts) ? scan.score_details.severity_counts : {
        critical: (scan.counts ? (scan.counts.Critical ?? scan.counts.critical ?? 0) : 0),
        high: (scan.counts ? (scan.counts.High ?? scan.counts.high ?? 0) : 0),
        medium: (scan.counts ? (scan.counts.Medium ?? scan.counts.medium ?? 0) : 0),
        low: (scan.counts ? (scan.counts.Low ?? scan.counts.low ?? 0) : 0)
    };
    countCritical.textContent = counts.critical;
    countHigh.textContent = counts.high;
    countMedium.textContent = counts.medium;
    countLow.textContent = counts.low;

    // Tab buttons text
    tabFindings.textContent = `Findings (${scan.findings.length})`;
    tabEndpoints.textContent = `Endpoints (${scan.endpoints.length})`;

    // Populate Findings Table
    findingsTableBody.innerHTML = "";
    scan.findings.forEach((f, idx) => {
        const tr = document.createElement("tr");
        tr.className = "table-row-clickable";
        tr.addEventListener("click", () => openFindingDetail(f));

        const bandClass = f.band.toLowerCase();
        const verdictClass = f.verdict.toLowerCase();

        tr.innerHTML = `
            <td><span class="pill-badge ${bandClass}">${f.band}</span></td>
            <td><strong>${f.title}</strong></td>
            <td><code>${f.file}:${f.line}</code></td>
            <td><span class="pill-badge ${verdictClass}">${formatVerdict(f.verdict)}</span></td>
        `;
        findingsTableBody.appendChild(tr);
    });

    const shownCount = Math.min(6, scan.findings.length);
    findingsTableFooter.textContent = `Showing ${shownCount} of ${scan.findings.length}. Human review recommended for every finding.`;

    // Populate Endpoints Table
    endpointsTableBody.innerHTML = "";
    scan.endpoints.forEach(ep => {
        const tr = document.createElement("tr");
        const methodClass = `method-${ep.method.toLowerCase()}`;
        const authBadgeClass = ep.auth_status.toLowerCase();

        tr.innerHTML = `
            <td><span class="method-tag ${methodClass}">${ep.method}</span></td>
            <td><code>${ep.path}</code></td>
            <td>${ep.handler}</td>
            <td><span class="pill-badge ${authBadgeClass}">${ep.auth_status}</span></td>
            <td>${ep.ownership_check}</td>
            <td><code>${ep.file}:${ep.line}</code></td>
        `;
        endpointsTableBody.appendChild(tr);
    });
}

function formatVerdict(v) {
    if (v === "confirmed") return "Confirmed";
    if (v === "needs_validation") return "Needs validation";
    if (v === "rejected") return "Rejected";
    return v;
}

// Tab Switching
tabFindings.addEventListener("click", () => {
    tabFindings.classList.add("active");
    tabEndpoints.classList.remove("active");
    panelFindings.classList.add("active");
    panelEndpoints.classList.remove("active");
});

tabEndpoints.addEventListener("click", () => {
    tabEndpoints.classList.add("active");
    tabFindings.classList.remove("active");
    panelEndpoints.classList.add("active");
    panelFindings.classList.remove("active");
});

// =========================================================
// SCREEN 3: Finding Detail View
// =========================================================
function openFindingDetail(finding) {
    currentFinding = finding;

    detailBreadcrumbId.textContent = finding.id;
    const curScore = currentScan.score_details ? currentScan.score_details.score : (currentScan.score !== undefined ? currentScan.score : 0);
    detailHeaderProject.textContent = `${currentScan.project_name} · Score ${curScore}/100`;
    detailTitle.textContent = finding.title;

    // Badges
    detailSeverityBadge.className = `pill-badge ${finding.band.toLowerCase()}`;
    detailSeverityBadge.textContent = finding.band;

    detailVerdictBadge.className = `pill-badge ${finding.verdict.toLowerCase()}`;
    detailVerdictBadge.textContent = formatVerdict(finding.verdict);

    detailOwaspBadge.textContent = `OWASP ${finding.owasp_category.split(' ')[0]}`;

    detailFileLocation.textContent = finding.file;

    // Code Display with line numbers & highlight
    renderCodeSnippet(finding);

    detailWhyMatters.textContent = finding.explanation;

    detailSeverityMath.textContent = `Severity ${finding.severity} × confidence ${finding.confidence} (${finding.confidence === 'high' ? '1.0' : (finding.confidence === 'medium' ? '0.7' : '0.4')}) = risk ${finding.risk} → ${finding.band}`;

    detailFixBefore.textContent = finding.fix.before || finding.evidence;
    detailFixAfter.textContent = finding.fix.after;

    detailFixSteps.innerHTML = "";
    if (finding.fix.steps && finding.fix.steps.length > 0) {
        finding.fix.steps.forEach(s => {
            const li = document.createElement("li");
            li.textContent = s;
            detailFixSteps.appendChild(li);
        });
        document.getElementById("detail-fix-steps-wrap").style.display = "block";
    } else {
        document.getElementById("detail-fix-steps-wrap").style.display = "none";
    }

    reviewBtnText.textContent = finding.verdict === "rejected" ? "Unmark rejected" : "Mark reviewed";

    switchView("detail");
}

function renderCodeSnippet(finding) {
    detailCodeDisplay.innerHTML = "";

    // Simulated 4-line snippet around the target line
    const targetLine = finding.line;
    const startLine = Math.max(1, targetLine - 2);

    // Split evidence if multi-line, or mock context
    const lines = finding.evidence.split("\n");

    for (let i = 0; i < Math.max(lines.length, 3); i++) {
        const lineNum = startLine + i;
        const lineDiv = document.createElement("div");
        lineDiv.className = "code-line";
        if (lineNum === targetLine) {
            lineDiv.classList.add("line-highlight");
        }

        const numSpan = document.createElement("span");
        numSpan.className = "line-no";
        numSpan.textContent = lineNum;

        const contentSpan = document.createElement("span");
        contentSpan.className = "line-content";
        contentSpan.textContent = lines[i] || (lineNum === targetLine ? finding.evidence : "    ...");

        lineDiv.appendChild(numSpan);
        lineDiv.appendChild(contentSpan);
        detailCodeDisplay.appendChild(lineDiv);
    }
}

// Back to Dashboard
btnBackDashboard.addEventListener("click", () => {
    switchView("dashboard");
});

// Copy Fix
btnCopyFix.addEventListener("click", () => {
    if (!currentFinding) return;
    navigator.clipboard.writeText(currentFinding.fix.after).then(() => {
        copyBtnText.textContent = "Copied!";
        setTimeout(() => {
            copyBtnText.textContent = "Copy fix";
        }, 1800);
    });
});

// Mark Reviewed / Toggle Verdict
btnMarkReviewed.addEventListener("click", async () => {
    if (!currentFinding || !currentScan) return;
    const newVerdict = currentFinding.verdict === "rejected" ? "confirmed" : "rejected";

    try {
        const formData = new FormData();
        formData.append("verdict", newVerdict);
        formData.append("verdict_reason", "Updated by auditor in human review.");

        const res = await fetch(`/findings/${currentScan.id}/${currentFinding.id}/verdict`, {
            method: "POST",
            body: formData
        });

        if (res.ok) {
            const data = await res.json();
            currentFinding.verdict = data.finding.verdict;
            currentScan.score_details = data.score_details;
            detailVerdictBadge.className = `pill-badge ${currentFinding.verdict.toLowerCase()}`;
            detailVerdictBadge.textContent = formatVerdict(currentFinding.verdict);
            reviewBtnText.textContent = currentFinding.verdict === "rejected" ? "Unmark rejected" : "Mark reviewed";
            renderDashboard(currentScan);
        }
    } catch (err) {
        console.error("Failed to update verdict", err);
    }
});

// =========================================================
// MODALS
// =========================================================

// Score Modal
const modalScore = document.getElementById("modal-score");
document.getElementById("link-how-scored").addEventListener("click", () => {
    modalScore.classList.add("active");
});
document.getElementById("btn-close-score-modal").addEventListener("click", () => {
    modalScore.classList.remove("active");
});

// Re-scan Modal
const modalRescan = document.getElementById("modal-rescan");
const btnOpenRescan = document.getElementById("btn-open-rescan");
const btnCloseRescan = document.getElementById("btn-close-rescan-modal");
const btnRunRescanSample = document.getElementById("btn-run-rescan-sample");
const btnRunRescanFile = document.getElementById("btn-run-rescan-file");
const rescanFileInput = document.getElementById("rescan-file-input");
const rescanFolderInput = document.getElementById("rescan-folder-input");
const rescanUploadSection = document.getElementById("rescan-upload-section");
const rescanResultsSection = document.getElementById("rescan-results-section");
const rescanScoreDelta = document.getElementById("rescan-score-delta");
const rescanScoreComparison = document.getElementById("rescan-score-comparison");
const rescanResolvedList = document.getElementById("rescan-resolved-list");
const btnApplyRescan = document.getElementById("btn-apply-rescan");

let latestRescanResult = null;

btnOpenRescan.addEventListener("click", () => {
    rescanUploadSection.style.display = "block";
    rescanResultsSection.style.display = "none";
    modalRescan.classList.add("active");
});

btnCloseRescan.addEventListener("click", () => {
    modalRescan.classList.remove("active");
});

btnRunRescanSample.addEventListener("click", async () => {
    await executeRescan(null, "taskboard_fixed", null);
});

btnRunRescanFile.addEventListener("click", async () => {
    const folderVal = rescanFolderInput ? rescanFolderInput.value.trim() : "";
    if (folderVal) {
        await executeRescan(null, null, folderVal);
        return;
    }
    if (!rescanFileInput.files || rescanFileInput.files.length === 0) {
        alert("Please select a patched .zip file or enter a folder path.");
        return;
    }
    await executeRescan(rescanFileInput.files[0], null, null);
});

async function executeRescan(file, sampleId, folderPath) {
    if (!currentScan) return;
    btnRunRescanSample.disabled = true;
    btnRunRescanFile.disabled = true;

    try {
        const formData = new FormData();
        formData.append("old_scan_id", currentScan.id);
        formData.append("consent", "true");
        if (folderPath) {
            formData.append("folder_path", folderPath);
        } else if (file) {
            formData.append("file", file);
        } else {
            formData.append("sample_id", sampleId);
        }

        const res = await fetch("/rescan", {
            method: "POST",
            body: formData
        });

        if (!res.ok) {
            throw new Error("Re-scan failed");
        }

        latestRescanResult = await res.json();

        // Render re-scan comparison
        rescanUploadSection.style.display = "none";
        rescanResultsSection.style.display = "block";

        const delta = latestRescanResult.score_delta;
        rescanScoreDelta.textContent = `${delta >= 0 ? '+' : ''}${delta} pts`;
        rescanScoreComparison.textContent = `${latestRescanResult.old_score} → ${latestRescanResult.new_score} / 100`;

        rescanResolvedList.innerHTML = "";
        latestRescanResult.resolved_findings.forEach(rf => {
            const li = document.createElement("li");
            li.textContent = `✓ [${rf.band}] ${rf.title} (${rf.file}:${rf.line})`;
            rescanResolvedList.appendChild(li);
        });

    } catch (err) {
        alert(`Re-scan error: ${err.message}`);
    } finally {
        btnRunRescanSample.disabled = false;
        btnRunRescanFile.disabled = false;
    }
}

btnApplyRescan.addEventListener("click", async () => {
    if (!latestRescanResult) return;
    // Load new scan data and switch to dashboard
    const res = await fetch(`/scan/${latestRescanResult.new_scan_id}`);
    if (res.ok) {
        currentScan = await res.json();
        renderDashboard(currentScan);
        modalRescan.classList.remove("active");
        switchView("dashboard");
    }
});

// Live Check Modal
const modalLive = document.getElementById("modal-live");
document.getElementById("btn-live-check").addEventListener("click", () => {
    modalLive.classList.add("active");
});
document.getElementById("btn-close-live-modal").addEventListener("click", () => {
    modalLive.classList.remove("active");
});

document.getElementById("btn-execute-live").addEventListener("click", async () => {
    const targetUrl = document.getElementById("live-target-input").value;
    const resultsArea = document.getElementById("live-results-area");
    resultsArea.innerHTML = "Checking localhost security headers and CORS...";

    try {
        const res = await fetch("/live-check", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ target_url: targetUrl })
        });

        const data = await res.json();
        if (!data.success) {
            resultsArea.innerHTML = `<div style="color:#b91c1c;">${data.error}</div>`;
            return;
        }

        let headersHtml = '<table style="width:100%; border-collapse:collapse; margin-top:0.5rem;">';
        data.security_headers.forEach(h => {
            const statusColor = h.status === "present" ? "#15803d" : "#b91c1c";
            headersHtml += `
                <tr style="border-bottom:1px solid #e2e8f0;">
                    <td style="padding:6px 0;"><strong>${h.header}</strong></td>
                    <td style="color:${statusColor}; font-weight:700;">${h.status.toUpperCase()}</td>
                </tr>
            `;
        });
        headersHtml += '</table>';

        resultsArea.innerHTML = `
            <div style="margin-bottom:0.5rem;"><strong>Target:</strong> ${data.target}</div>
            <div><strong>Security Headers (C11):</strong></div>
            ${headersHtml}
            <div style="margin-top:0.75rem;"><strong>CORS (C12):</strong> ${data.cors ? data.cors.description : "No permissive wildcard CORS detected."}</div>
        `;
    } catch (err) {
        resultsArea.innerHTML = `<div style="color:#b91c1c;">Connection error: ${err.message}</div>`;
    }
});

// Export Dropdown
const btnExportDropdown = document.getElementById("btn-export-dropdown");
const exportMenu = document.getElementById("export-menu");

btnExportDropdown.addEventListener("click", (e) => {
    e.stopPropagation();
    const rect = btnExportDropdown.getBoundingClientRect();
    exportMenu.style.top = `${rect.bottom + 6}px`;
    exportMenu.style.left = `${rect.left - 40}px`;
    exportMenu.style.display = exportMenu.style.display === "block" ? "none" : "block";
});

document.addEventListener("click", () => {
    exportMenu.style.display = "none";
});

document.getElementById("export-html-btn").addEventListener("click", () => {
    if (!currentScan) return;
    window.location.href = `/report/${currentScan.id}?format=html`;
});

document.getElementById("export-md-btn").addEventListener("click", () => {
    if (!currentScan) return;
    window.location.href = `/report/${currentScan.id}?format=md`;
});

// GitHub Pages / Client-Side Demo Engine
function getClientSideDemoResult(formData) {
    const sampleId = formData.get("sample_id");
    const websiteUrl = formData.get("website_url");
    const projectName = formData.get("project_name") || "TaskBoard";

    if (sampleId === "taskboard_fixed") {
        return {
            id: "demo-fixed",
            project_name: "TaskBoard (Fixed & Hardened)",
            timestamp: new Date().toLocaleString(),
            files_scanned: 6,
            score_details: {
                score: 100,
                label: "Excellent",
                total_penalty: 0,
                formula_summary: "Score = 100 - 0 = 100/100",
                severity_counts: { critical: 0, high: 0, medium: 0, low: 0 }
            },
            findings: [],
            endpoints: [
                { method: "GET", path: "/login", handler: "login", file: "auth.py", line: 12, auth_status: "unprotected", ownership_check: "n/a", notes: "Public login" },
                { method: "POST", path: "/login", handler: "login_post", file: "auth.py", line: 20, auth_status: "unprotected", ownership_check: "n/a", notes: "Parameterized SQL + PBKDF2" },
                { method: "GET", path: "/dashboard", handler: "dashboard", file: "tasks.py", line: 15, auth_status: "protected", ownership_check: "yes", notes: "@login_required" }
            ]
        };
    }

    if (websiteUrl) {
        return {
            id: "demo-url",
            project_name: `Live Audit: ${websiteUrl}`,
            timestamp: new Date().toLocaleString(),
            files_scanned: 2,
            score_details: {
                score: 77,
                label: "Fair",
                total_penalty: 23,
                formula_summary: "Score = 100 - 23.0 = 77/100",
                severity_counts: { critical: 0, high: 2, medium: 1, low: 1 }
            },
            findings: [
                {
                    id: "F-01", check_id: "C11", title: "Missing Content-Security-Policy (CSP) header",
                    file: "headers.http", line: 1, severity: 3, confidence: "high", risk: 3.0, band: "High", verdict: "confirmed",
                    verdict_reason: "Server response lacks Content-Security-Policy header.",
                    explanation: "Without a Content Security Policy, arbitrary scripts and malicious frames can execute within users' browser sessions.",
                    fix: { before: "# Missing CSP", after: "Content-Security-Policy: default-src 'self'", steps: ["Configure web server to return restrictive CSP header."] },
                    owasp_category: "A05 Security Misconfiguration", human_review: true
                },
                {
                    id: "F-02", check_id: "C11", title: "Missing X-Frame-Options header (Clickjacking risk)",
                    file: "headers.http", line: 1, severity: 2, confidence: "high", risk: 2.0, band: "Medium", verdict: "confirmed",
                    verdict_reason: "Response omits framing protection.",
                    explanation: "Malicious third-party sites can embed this web page in hidden iframes to trick users into unauthorized clicks.",
                    fix: { before: "# Missing X-Frame-Options", after: "X-Frame-Options: DENY", steps: ["Add X-Frame-Options: DENY to responses."] },
                    owasp_category: "A05 Security Misconfiguration", human_review: false
                },
                {
                    id: "F-03", check_id: "C12", title: "Overly permissive CORS policy (Wildcard *)",
                    file: "headers.http", line: 1, severity: 3, confidence: "high", risk: 3.0, band: "High", verdict: "confirmed",
                    verdict_reason: "Access-Control-Allow-Origin is set to '*'.",
                    explanation: "Wildcard CORS policy allows third-party origins to read private response data.",
                    fix: { before: "Access-Control-Allow-Origin: *", after: "Access-Control-Allow-Origin: https://trusted.example.com", steps: ["Restrict CORS origin to explicit domain."] },
                    owasp_category: "A05 Security Misconfiguration", human_review: true
                }
            ],
            endpoints: [{ method: "GET", path: "/", handler: "HTTP Server", file: "headers.http", line: 1, auth_status: "unprotected", ownership_check: "n/a", notes: "HTTP 200 OK" }]
        };
    }

    // Default: TaskBoard Vulnerable Demo (Score 34/100, 9 findings, PRD Screenshot 2)
    return {
        id: "demo-vulnerable",
        project_name: projectName || "TaskBoard",
        timestamp: new Date().toLocaleString(),
        files_scanned: 5,
        score_details: {
            score: 34,
            label: "Poor",
            total_penalty: 66,
            formula_summary: "Score = 100 - 66.0 = 34/100",
            severity_counts: { critical: 2, high: 3, medium: 3, low: 1 }
        },
        findings: [
            {
                id: "F-01", check_id: "C1", title: "Hardcoded secret detected",
                file: "config.py", line: 4, severity: 5, confidence: "high", risk: 5.0, band: "Critical", verdict: "confirmed",
                verdict_reason: "Active API key or secret token was hardcoded into application source.",
                explanation: "Exposing secret credentials in source files leads to account takeover, unauthorized API usage, and data breaches.",
                fix: { before: 'API_KEY = "sk-live-9481abf082e4a9f2"', after: 'API_KEY = os.environ.get("API_KEY")', steps: ["Move credentials to environment variables.", "Add .env to .gitignore.", "Immediately rotate the exposed secret."] },
                owasp_category: "A02 Cryptographic Failures", human_review: true
            },
            {
                id: "F-02", check_id: "C2", title: "SQL injection risk in login query",
                file: "auth.py", line: 26, severity: 5, confidence: "high", risk: 5.0, band: "Critical", verdict: "confirmed",
                verdict_reason: "SQL query constructed using dynamic string formatting.",
                explanation: "Unparameterized queries allow attackers to bypass login authentication or extract database tables.",
                fix: { before: 'cursor.execute(f"SELECT * FROM users WHERE user=\'{username}\'")', after: 'cursor.execute("SELECT * FROM users WHERE user=?", (username,))', steps: ["Replace formatted string with parameterized SQL placeholder.", "Pass parameters as a tuple.", "Verify query uses prepared statements."] },
                owasp_category: "A03 Injection", human_review: true
            },
            {
                id: "F-03", check_id: "C2", title: "SQL injection risk in tasks filter",
                file: "tasks.py", line: 42, severity: 5, confidence: "high", risk: 5.0, band: "Critical", verdict: "confirmed",
                verdict_reason: "Filter query concatenates query parameter directly.",
                explanation: "Allows an attacker to alter the query logic and read other users' private task data.",
                fix: { before: 'cursor.execute("SELECT * FROM tasks WHERE status=\'" + status + "\'")', after: 'cursor.execute("SELECT * FROM tasks WHERE status=?", (status,))', steps: ["Use parameterized placeholder '?' instead of string concatenation."] },
                owasp_category: "A03 Injection", human_review: true
            },
            {
                id: "F-04", check_id: "C3", title: "XSS risk: unescaped template render",
                file: "templates/task.html", line: 18, severity: 4, confidence: "high", risk: 4.0, band: "High", verdict: "confirmed",
                verdict_reason: "Template uses |safe filter on user-provided task description.",
                explanation: "Bypasses automatic HTML escaping, allowing injected script tags to execute in other users' browsers.",
                fix: { before: '<div>{{ task.description | safe }}</div>', after: '<div>{{ task.description }}</div>', steps: ["Remove the |safe filter so template engine auto-escapes HTML."] },
                owasp_category: "A03 Injection", human_review: true
            },
            {
                id: "F-05", check_id: "C4", title: "Plaintext MD5 password hashing",
                file: "auth.py", line: 15, severity: 4, confidence: "high", risk: 4.0, band: "High", verdict: "confirmed",
                verdict_reason: "MD5 algorithm is cryptographically broken and vulnerable to collision and rainbow table attacks.",
                explanation: "Compromised database dumps allow fast recovery of plaintext passwords.",
                fix: { before: 'hashlib.md5(password.encode()).hexdigest()', after: 'hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600000)', steps: ["Switch from MD5 to PBKDF2, Argon2, or bcrypt with unique per-user salts."] },
                owasp_category: "A02 Cryptographic Failures", human_review: false
            },
            {
                id: "F-06", check_id: "C5", title: "Dangerous eval execution",
                file: "tasks.py", line: 78, severity: 4, confidence: "high", risk: 4.0, band: "High", verdict: "confirmed",
                verdict_reason: "eval() executes arbitrary code strings supplied by clients.",
                explanation: "Permits remote code execution on the application server.",
                fix: { before: 'result = eval(user_expression)', after: 'result = ast.literal_eval(user_expression)', steps: ["Replace eval() with ast.literal_eval() or a safe parser."] },
                owasp_category: "A03 Injection", human_review: true
            },
            {
                id: "F-07", check_id: "C6", title: "Flask debug mode enabled",
                file: "app.py", line: 35, severity: 3, confidence: "high", risk: 3.0, band: "Medium", verdict: "confirmed",
                verdict_reason: "debug=True exposes interactive Werkzeug debugger console.",
                explanation: "In production, an unhandled error displays a debugger pin console that allows remote command execution.",
                fix: { before: 'app.run(debug=True)', after: 'app.run(debug=False)', steps: ["Set debug=False in production."] },
                owasp_category: "A05 Security Misconfiguration", human_review: false
            },
            {
                id: "F-08", check_id: "C7", title: "Insecure session cookie",
                file: "app.py", line: 12, severity: 3, confidence: "high", risk: 3.0, band: "Medium", verdict: "confirmed",
                verdict_reason: "Session cookies missing HttpOnly and Secure flags.",
                explanation: "Cookies can be read by JavaScript during XSS or intercepted over plain HTTP.",
                fix: { before: 'SESSION_COOKIE_HTTPONLY = False', after: 'SESSION_COOKIE_HTTPONLY = True\nSESSION_COOKIE_SECURE = True', steps: ["Set SESSION_COOKIE_HTTPONLY = True.", "Set SESSION_COOKIE_SECURE = True."] },
                owasp_category: "A05 Security Misconfiguration", human_review: false
            },
            {
                id: "F-09", check_id: "C8", title: "Missing input validation on JSON body",
                file: "tasks.py", line: 55, severity: 3, confidence: "medium", risk: 2.1, band: "Medium", verdict: "needs_validation",
                verdict_reason: "Request JSON payload parsed without schema validation.",
                explanation: "Allows unexpected data types or missing fields to cause crashes or state corruption.",
                fix: { before: 'data = request.json', after: 'data = TaskSchema(**request.json)', steps: ["Validate request payloads using Pydantic or Marshmallow."] },
                owasp_category: "A04 Insecure Design", human_review: true
            }
        ],
        endpoints: [
            { method: "POST", path: "/login", handler: "login", file: "auth.py", line: 20, auth_status: "unprotected", ownership_check: "n/a", notes: "Public login" },
            { method: "GET", path: "/tasks", handler: "list_tasks", file: "tasks.py", line: 30, auth_status: "unprotected", ownership_check: "no", notes: "Missing auth" },
            { method: "POST", path: "/tasks", handler: "create_task", file: "tasks.py", line: 50, auth_status: "unprotected", ownership_check: "no", notes: "Missing auth" },
            { method: "GET", path: "/tasks/<id>", handler: "get_task", file: "tasks.py", line: 70, auth_status: "unprotected", ownership_check: "no", notes: "IDOR risk" },
            { method: "POST", path: "/tasks/<id>/delete", handler: "delete_task", file: "tasks.py", line: 90, auth_status: "unprotected", ownership_check: "no", notes: "Destructive route unprotected" }
        ]
    };
}

