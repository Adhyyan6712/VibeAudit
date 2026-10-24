import os
import uuid
import datetime
import asyncio
from typing import Dict, Any, Optional, List
from dotenv import load_dotenv

load_dotenv()
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, PlainTextResponse, FileResponse

from backend.models import (
    ScanResult, RescanResult, ScanScore, Finding, LiveCheckRequest
)
from backend.file_loader import load_zip_bytes, load_folder, is_text_file, _strip_single_root_folder
from backend.rule_engine.registry import RuleEngine
from backend.scoring import compute_score
from backend.gemini_service import enrich_finding_with_ai
from backend.live_scanner import scan_live_localhost, audit_website_url
from backend.report_generator import generate_markdown_report, generate_html_report

app = FastAPI(title="VibeAudit API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage for active scan sessions
SCANS_DB: Dict[str, ScanResult] = {}
rule_engine = RuleEngine()

@app.get("/api/health")
def health_check():
    return {"status": "ok", "service": "VibeAudit Security Auditor"}

@app.get("/api/samples")
def list_samples():
    """Lists built-in demo targets for 1-click testing."""
    return [
        {
            "id": "taskboard",
            "name": "TaskBoard (Vulnerable Demo)",
            "description": "Flask app containing planted vulnerabilities (SQLi, IDOR, unauthenticated admin, hardcoded secrets, MD5). Expected score: ~34/100."
        },
        {
            "id": "taskboard_fixed",
            "name": "TaskBoard (Fixed & Hardened)",
            "description": "Hardened version with parameterized queries, auth decorators, secure cookies, and PBKDF2. Expected score: ~88-100/100."
        }
    ]

@app.post("/scan", response_model=ScanResult)
async def scan_project(
    project_name: str = Form("TaskBoard"),
    consent: bool = Form(...),
    sample_id: Optional[str] = Form(None),
    folder_path: Optional[str] = Form(None),
    website_url: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
    files: Optional[List[UploadFile]] = File(None)
):
    """Initiates static analysis and route auditing on uploaded ZIP, folder, sample, or website URL (FR-1, FR-2, FR-11)."""
    # FR-1: Mandatory consent gate
    if not consent:
        raise HTTPException(status_code=400, detail="Consent required: You must confirm authorization to audit this application.")

    file_map: Dict[str, str] = {}
    findings: List[Finding] = []
    endpoints: List[Endpoint] = []
    is_live_url_scan = False

    # Option 0: Live Website / Application Inspection (Passive GET/HEAD per FR-11, FR-12)
    if website_url and isinstance(website_url, str) and website_url.strip():
        clean_url = website_url.strip()
        try:
            findings, endpoints, file_map = await asyncio.to_thread(audit_website_url, clean_url)
            project_name = f"Live Audit: {clean_url}"
            is_live_url_scan = True
        except ValueError as ve:
            raise HTTPException(status_code=400, detail=str(ve))

    # Option 1: Local folder path on disk (Full access)
    elif folder_path and isinstance(folder_path, str) and folder_path.strip():
        clean_path = os.path.expanduser(folder_path.strip().strip('"').strip("'"))
        if os.path.exists(clean_path):
            if os.path.isdir(clean_path):
                file_map = load_folder(clean_path)
            elif os.path.isfile(clean_path):
                if clean_path.lower().endswith(".zip"):
                    with open(clean_path, "rb") as fp:
                        file_map = load_zip_bytes(fp.read())
                else:
                    with open(clean_path, "rb") as fp:
                        raw = fp.read()
                    fname = os.path.basename(clean_path)
                    try:
                        file_map[fname] = raw.decode("utf-8")
                    except Exception:
                        file_map[fname] = raw.decode("latin-1")
            if not file_map:
                raise HTTPException(status_code=400, detail=f"No readable code files found in: {clean_path}")
        else:
            raise HTTPException(status_code=400, detail=f"Path does not exist on disk: {clean_path}")

    # Option 2: Built-in sample
    elif sample_id:
        if sample_id == "taskboard_fixed":
            base_dir = os.path.join(os.path.dirname(__file__), "..", "demo_apps", "taskboard_fixed")
        else:
            base_dir = os.path.join(os.path.dirname(__file__), "..", "demo_apps", "taskboard")
        file_map = load_folder(os.path.abspath(base_dir))

    # Option 3: Browser folder or multiple files upload
    elif files and len(files) > 0 and files[0].filename:
        for uploaded in files:
            name = uploaded.filename.replace("\\", "/")
            if any(ig in name for ig in [".git/", "node_modules/", "__pycache__/", ".venv/", "venv/", "dist/", "build/"]):
                continue
            try:
                raw = await uploaded.read()
                if name.lower().endswith(".zip") and len(files) == 1:
                    file_map.update(load_zip_bytes(raw))
                    break
                if not is_text_file(name, raw):
                    continue
                try:
                    file_map[name] = raw.decode("utf-8")
                except Exception:
                    file_map[name] = raw.decode("latin-1")
            except Exception:
                continue
        file_map = _strip_single_root_folder(file_map)

    # Option 4: Single file or ZIP upload
    elif file and file.filename:
        content = await file.read()
        if file.filename.lower().endswith(".zip"):
            file_map = load_zip_bytes(content)
            if not file_map:
                raise HTTPException(status_code=400, detail="Uploaded ZIP is empty or contained only binary/unsupported files.")
        else:
            clean_name = os.path.basename(file.filename.replace("\\", "/"))
            if is_text_file(clean_name, content):
                try:
                    file_map[clean_name] = content.decode("utf-8")
                except UnicodeDecodeError:
                    file_map[clean_name] = content.decode("latin-1")
            else:
                raise HTTPException(status_code=400, detail=f"File {clean_name} is binary or unsupported.")
    else:
        # Default fallback to TaskBoard demo
        base_dir = os.path.join(os.path.dirname(__file__), "..", "demo_apps", "taskboard")
        file_map = load_folder(os.path.abspath(base_dir))

    if not file_map:
        raise HTTPException(
            status_code=400,
            detail="No readable code files found. Please ensure your folder or archive contains supported text/code files (.py, .js, .html, .env, etc.)."
        )

    # Run static rule checks (C1-C8) and route parser (C9-C10) for source code scans
    if not is_live_url_scan:
        findings, endpoints = rule_engine.run_all(file_map)

    # Optional Gemini AI enrichment (parallelized for sub-second/fast response & cache)
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=5) as executor:
        list(executor.map(enrich_finding_with_ai, findings))

    # Calculate final score based on findings and verdicts
    score_details = compute_score(findings)

    scan_id = str(uuid.uuid4())[:8]
    scan_result = ScanResult(
        id=scan_id,
        project_name=project_name,
        timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        score_details=score_details,
        findings=findings,
        endpoints=endpoints,
        files_scanned=len(file_map),
        consent_given=consent
    )

    SCANS_DB[scan_id] = scan_result
    return scan_result

@app.get("/scan/{scan_id}", response_model=ScanResult)
def get_scan(scan_id: str):
    """Retrieves an existing scan result."""
    if scan_id not in SCANS_DB:
        raise HTTPException(status_code=404, detail="Scan ID not found")
    return SCANS_DB[scan_id]

@app.post("/rescan", response_model=RescanResult)
async def rescan_project(
    old_scan_id: str = Form(...),
    consent: bool = Form(...),
    sample_id: Optional[str] = Form(None),
    folder_path: Optional[str] = Form(None),
    website_url: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
    files: Optional[List[UploadFile]] = File(None)
):
    """Re-scans a patched application and computes score delta and resolved findings (FR-10)."""
    if old_scan_id not in SCANS_DB:
        raise HTTPException(status_code=404, detail="Previous scan not found")

    old_scan = SCANS_DB[old_scan_id]

    # Perform new scan
    new_scan = await scan_project(
        project_name=f"{old_scan.project_name} (Patched)",
        consent=consent,
        sample_id=sample_id,
        folder_path=folder_path,
        website_url=website_url,
        file=file,
        files=files
    )

    # Compare old findings vs new findings
    new_keys = {(f.check_id, f.file, f.line) for f in new_scan.findings}
    old_keys = {(f.check_id, f.file, f.line) for f in old_scan.findings}

    resolved = [f for f in old_scan.findings if (f.check_id, f.file, f.line) not in new_keys]
    remaining = [f for f in new_scan.findings if (f.check_id, f.file, f.line) in old_keys]
    new_findings = [f for f in new_scan.findings if (f.check_id, f.file, f.line) not in old_keys]

    score_delta = new_scan.score_details.score - old_scan.score_details.score

    summary = (
        f"Score changed from {old_scan.score_details.score} to {new_scan.score_details.score} "
        f"({'+' if score_delta >= 0 else ''}{score_delta} pts). "
        f"{len(resolved)} finding(s) resolved, {len(remaining)} remaining, {len(new_findings)} new."
    )

    return RescanResult(
        old_scan_id=old_scan_id,
        new_scan_id=new_scan.id,
        old_score=old_scan.score_details.score,
        new_score=new_scan.score_details.score,
        score_delta=score_delta,
        resolved_findings=resolved,
        remaining_findings=remaining,
        new_findings=new_findings,
        comparison_summary=summary
    )

@app.post("/findings/{scan_id}/{finding_id}/verdict")
def update_verdict(
    scan_id: str,
    finding_id: str,
    verdict: str = Form(...),
    verdict_reason: Optional[str] = Form(None)
):
    """Allows reviewer to update verdict label (confirmed, needs_validation, rejected) or mark reviewed (FR-13)."""
    if scan_id not in SCANS_DB:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan = SCANS_DB[scan_id]

    target_finding = None
    for f in scan.findings:
        if f.id == finding_id:
            target_finding = f
            break

    if not target_finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    if verdict not in ["confirmed", "needs_validation", "rejected"]:
        raise HTTPException(status_code=400, detail="Invalid verdict")

    target_finding.verdict = verdict # type: ignore
    if verdict_reason:
        target_finding.verdict_reason = verdict_reason

    # Recompute score dynamically
    scan.score_details = compute_score(scan.findings)
    return {
        "finding": target_finding,
        "score_details": scan.score_details
    }

@app.get("/report/{scan_id}")
def export_report(scan_id: str, format: str = Query("html", pattern="^(md|html)$")):
    """Generates and downloads report in Markdown or HTML (FR-11)."""
    if scan_id not in SCANS_DB:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan = SCANS_DB[scan_id]

    if format == "md":
        content = generate_markdown_report(scan)
        return Response(
            content=content,
            media_type="text/markdown",
            headers={"Content-Disposition": f"attachment; filename=vibeaudit_report_{scan.project_name}_{scan_id}.md"}
        )
    else:
        content = generate_html_report(scan)
        return Response(
            content=content,
            media_type="text/html",
            headers={"Content-Disposition": f"attachment; filename=vibeaudit_report_{scan.project_name}_{scan_id}.html"}
        )

@app.post("/live-check")
def live_check(req: LiveCheckRequest):
    """Runs passive localhost headers and CORS check (FR-12, C11, C12)."""
    return scan_live_localhost(req.target_url)

# Mount static files directory
STATIC_DIR = os.path.join(os.path.dirname(__file__), "..", "static")
if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

@app.get("/")
def serve_index():
    index_file = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"message": "VibeAudit backend running. Static UI not yet created."}
