"""VibeAudit API (FastAPI).

Run:  uvicorn app.main:app --reload --port 8000
"""
import asyncio
import os
from pathlib import Path
import uuid
from datetime import datetime, timezone

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles

from . import __version__, config, gemini_client, report
from .live_checks import run_live_checks, validate_target
from .loader import SourceFile, is_github_url, load_dict, load_folder, load_github_repo, load_zip
from .models import Comparison, FindingPatch, PasteScanRequest, ScanResult


from .rules import CHECKS
from .scanner import assign_ids, run_static_scan
from .scoring import FORMULA, finalize
from .store import STORE

app = FastAPI(title="VibeAudit", version=__version__,
              description="Authorized, non-destructive security auditor for AI-generated web apps.")
app.add_middleware(CORSMiddleware, allow_origins=config.ALLOWED_ORIGINS, allow_methods=["GET", "POST", "PATCH"],
                   allow_headers=["Content-Type"])
_TASKS: set[asyncio.Task] = set()
CONSENT_ERROR = "Please confirm that you own this application or are authorized to test it."


@app.middleware("http")
async def security_headers(request, call_next):
    """Our own auditor should pass its own audit."""
    resp = await call_next(request)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("Cache-Control", "no-store")
    if not request.url.path.startswith(("/docs", "/openapi", "/redoc")):
        resp.headers.setdefault("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:")
    return resp


def _get(scan_id: str) -> ScanResult:
    scan = STORE.get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found or expired. Scans are kept for one hour.")
    return scan


async def _read_upload(file: UploadFile) -> bytes:
    data = bytearray()
    while chunk := await file.read(1024 * 1024):
        data += chunk
        if len(data) > config.MAX_UPLOAD_BYTES:
            raise HTTPException(413, f"Upload is larger than {config.MAX_UPLOAD_BYTES // (1024 * 1024)} MB.")
    return bytes(data)


async def _enrich(scan: ScanResult, triage: bool) -> None:
    try:
        stats = await gemini_client.enrich_findings(scan.findings, triage=triage, on_progress=lambda: finalize(scan))
        scan.ai_status = (f"done: {stats['enriched']}/{stats['total']} explained "
                          f"({stats['cached']} cached, {stats['failed']} used the static fallback)")
    except Exception:  # noqa: BLE001
        scan.ai_status = "failed: static explanations are shown"
    finally:
        finalize(scan)
        scan.status = "complete"


async def _run_scan(files: list[SourceFile], load_notes: list[str], project_name: str,
                    use_gemini: bool, live_url: str | None) -> ScanResult:
    if not files:
        raise HTTPException(400, "No scannable source files were found in the upload.")
    if live_url:
        try:
            validate_target(live_url)          # fail fast, before doing any work
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
    findings, endpoints, notes = await run_in_threadpool(run_static_scan, files)
    scan = ScanResult(scan_id=uuid.uuid4().hex, project_name=project_name.strip()[:80] or "project",
                      created_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"), files_scanned=len(files),
                      findings=findings, endpoints=endpoints, notes=load_notes + notes)
    if live_url:
        live, msg = await run_live_checks(live_url, endpoints)
        assign_ids(live, len(scan.findings) + 1)
        scan.findings += live
        scan.live_checked = msg
    finalize(scan)
    ai = use_gemini and gemini_client.available() and bool(scan.findings)
    scan.status = "enriching" if ai else "complete"
    scan.ai_status = "running" if ai else ("disabled: no GEMINI_API_KEY, static explanations used" if use_gemini else "disabled")
    STORE.put(scan)
    if ai:
        task = asyncio.create_task(_enrich(scan, triage=True))
        _TASKS.add(task)
        task.add_done_callback(_TASKS.discard)
    return scan


@app.get("/health")
def health():
    return {"status": "ok", "version": __version__, "gemini_configured": gemini_client.available(), "model": config.GEMINI_MODEL}


@app.get("/checks")
def checks():
    return [{"id": c.id, "title": c.title, "severity": c.severity, "owasp": c.owasp, "kind": c.kind} for c in CHECKS]


@app.get("/scoring")
def scoring():
    return {"formula": FORMULA}


@app.post("/scan", response_model=ScanResult)
async def scan_zip(
    file: UploadFile | None = File(None),
    consent: bool = Form(False),
    project_name: str = Form("project"),
    use_gemini: bool = Form(True),
    live_url: str | None = Form(None),
    website_url: str | None = Form(None),
    sample_id: str | None = Form(None),
    folder_path: str | None = Form(None),
    files: list[UploadFile] | None = File(None),
):
    if not consent:
        raise HTTPException(400, CONSENT_ERROR)

    # Check if target is a GitHub repo URL (e.g. https://github.com/owner/repo)
    gh_target = None
    if website_url and is_github_url(website_url):
        gh_target = website_url.strip()
    elif folder_path and is_github_url(folder_path):
        gh_target = folder_path.strip()

    if gh_target:
        try:
            files_loaded, notes = await run_in_threadpool(load_github_repo, gh_target)
            if project_name == "project":
                project_name = gh_target.split("github.com/")[-1].replace(".git", "").strip("/")
            return await _run_scan(files_loaded, notes, project_name, use_gemini, None)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc

    target_live = live_url or (website_url if (website_url and not is_github_url(website_url)) else None)
    if live_url:
        try:
            validate_target(live_url)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc



    if file and file.filename:
        try:
            files_loaded, notes = await run_in_threadpool(load_zip, await _read_upload(file))
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
    elif sample_id:
        is_fixed = sample_id in ("taskboard_fixed", "fixed")
        base = Path(__file__).resolve().parent.parent / "demo" / ("taskboard_fixed" if is_fixed else "taskboard")
        files_loaded, notes = await run_in_threadpool(load_folder, str(base))
        if project_name == "project":
            project_name = "TaskBoard (Fixed)" if is_fixed else "TaskBoard"
    elif folder_path and folder_path.strip():
        clean_p = folder_path.strip().strip('"').strip("'")
        if not os.path.exists(clean_p):
            raise HTTPException(400, f"Path does not exist on disk: {clean_p}")
        files_loaded, notes = await run_in_threadpool(load_folder, clean_p)
    elif files and len(files) > 0 and files[0].filename:
        loaded = []
        for uf in files:
            name = (uf.filename or "file.txt").replace("\\", "/")
            raw = await uf.read()
            text = raw.decode("utf-8", errors="replace")
            loaded.append(SourceFile(name, text))
        files_loaded, notes = loaded, [f"Loaded {len(loaded)} uploaded files."]
    else:
        base = Path(__file__).resolve().parent.parent / "demo" / "taskboard"
        files_loaded, notes = await run_in_threadpool(load_folder, str(base))
        if project_name == "project":
            project_name = "TaskBoard"

    return await _run_scan(files_loaded, notes, project_name, use_gemini, target_live)


@app.post("/scan/paste", response_model=ScanResult)
async def scan_paste(body: PasteScanRequest):
    if not body.consent:
        raise HTTPException(400, CONSENT_ERROR)
    files, notes = load_dict(body.files)
    return await _run_scan(files, notes, body.project_name, body.use_gemini, body.live_url)


@app.get("/scan/{scan_id}", response_model=ScanResult)
def get_scan(scan_id: str):
    return _get(scan_id)


@app.patch("/scan/{scan_id}/findings/{finding_id}", response_model=ScanResult)
def patch_finding(scan_id: str, finding_id: str, patch: FindingPatch):
    """Human review: mark reviewed or override the verdict. Overrides are never replaced by AI."""
    scan = _get(scan_id)
    f = next((x for x in scan.findings if x.id == finding_id), None)
    if not f:
        raise HTTPException(404, "Finding not found.")
    if patch.reviewed is not None:
        f.reviewed = patch.reviewed
    if patch.verdict is not None:
        f.verdict, f.user_override = patch.verdict, True
        f.verdict_reason = patch.verdict_reason or "Verdict set by a human reviewer."
    finalize(scan)
    return scan


@app.post("/findings/{scan_id}/{finding_id}/verdict", response_model=ScanResult)
def post_finding_verdict(scan_id: str, finding_id: str, verdict: str = Form(...), verdict_reason: str = Form("")):
    return patch_finding(scan_id, finding_id, FindingPatch(verdict=verdict, verdict_reason=verdict_reason, reviewed=True))


@app.get("/findings/{scan_id}")
def get_findings_list(scan_id: str):
    return _get(scan_id)


@app.post("/rescan", response_model=ScanResult)
async def rescan(previous_scan_id: str = Form(...), file: UploadFile | None = File(None), consent: bool = Form(False),
                 use_gemini: bool = Form(True), sample_id: str | None = Form(None)):
    """Scan a patched version and compare it with a previous scan (the before/after demo moment)."""
    if not consent:
        raise HTTPException(400, CONSENT_ERROR)
    old = _get(previous_scan_id)
    if file and file.filename:
        try:
            files, notes = await run_in_threadpool(load_zip, await _read_upload(file))
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
    else:
        base = Path(__file__).resolve().parent.parent / "demo" / "taskboard_fixed"
        files, notes = await run_in_threadpool(load_folder, str(base))
    new = await _run_scan(files, notes, old.project_name, use_gemini, None)
    old_fp = {f.fingerprint: f for f in old.findings if f.source == "static" and f.verdict != "rejected"}
    new_fp = {f.fingerprint: f for f in new.findings if f.verdict != "rejected"}
    new.comparison = Comparison(
        previous_scan_id=old.scan_id, old_score=old.score, new_score=new.score, delta=new.score - old.score,
        resolved=[f for k, f in old_fp.items() if k not in new_fp],
        new=[f for k, f in new_fp.items() if k not in old_fp],
        unchanged_count=len(set(old_fp) & set(new_fp)))
    return new



@app.get("/report/{scan_id}")
def get_report(scan_id: str, format: str = "md", download: bool = False):
    scan = _get(scan_id)
    if format == "md":
        body, media = report.to_markdown(scan), "text/markdown; charset=utf-8"
    elif format == "html":
        body, media = report.to_html(scan), "text/html; charset=utf-8"
    else:
        raise HTTPException(400, "format must be 'md' or 'html'.")
    headers = {"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'"}
    if download:
        headers["Content-Disposition"] = f'attachment; filename="vibeaudit-{scan.scan_id[:8]}.{format}"'
    return Response(body, media_type=media, headers=headers)


if config.FRONTEND_DIR.is_dir():          # optional: serve the UI from the same server
    app.mount("/", StaticFiles(directory=config.FRONTEND_DIR, html=True), name="ui")
