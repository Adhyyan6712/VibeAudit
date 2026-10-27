import io
import json
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import config
from app.live_checks import validate_target
from app.loader import load_folder, load_zip
from app.main import app
from app.models import Finding, ScanResult
from app.scanner import run_static_scan
from app.scoring import band_of, finalize, risk_of

ROOT = Path(__file__).resolve().parent.parent
VULN, FIXED = ROOT / "demo" / "taskboard", ROOT / "demo" / "taskboard_fixed"
SECRETS = ["9f3a7c1d5e8b", "hunter2pass", "admin123"]


def scan_folder(path):
    files, notes = load_folder(str(path))
    findings, endpoints, more = run_static_scan(files)
    result = ScanResult(scan_id="t", project_name="t", created_at="", files_scanned=len(files),
                        findings=findings, endpoints=endpoints, notes=notes + more)
    finalize(result)
    return result


def zip_of(path) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for p in Path(path).rglob("*"):
            if p.is_file():
                z.write(p, f"{Path(path).name}/{p.relative_to(path)}")
    return buf.getvalue()


# ------------------------------------------------------------ detection
def test_vulnerable_app_triggers_every_mvp_check():
    ids = {f.check_id for f in scan_folder(VULN).findings}
    assert {"C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "C10"} <= ids


def test_fixed_app_has_no_findings():
    r = scan_folder(FIXED)
    assert r.findings == [], [(f.check_id, f.file, f.line) for f in r.findings]
    assert r.score >= 85


def test_vulnerable_score_is_low_and_before_after_improves():
    bad, good = scan_folder(VULN), scan_folder(FIXED)
    assert 25 <= bad.score <= 50
    assert good.score - bad.score >= 40


def test_secrets_are_never_exposed():
    r = scan_folder(VULN)
    blob = r.model_dump_json() + "".join(f.context for f in r.findings)
    for s in SECRETS:
        assert s not in blob
    assert any("••••" in f.evidence for f in r.findings if f.check_id == "C1")


def test_endpoint_inventory_flags_unprotected_admin_routes():
    eps = {e.path: e for e in scan_folder(VULN).endpoints}
    assert eps["/admin/users"].auth_status == "unprotected"
    assert eps["/admin/delete/<int:user_id>"].auth_status == "unprotected"
    assert eps["/health"].public and eps["/tasks/<int:task_id>"].ownership_check == "no"
    fixed = {e.path: e for e in scan_folder(FIXED).endpoints}
    assert fixed["/admin/users"].auth_status == "protected"
    assert fixed["/tasks/<int:task_id>"].ownership_check == "yes"


@pytest.mark.parametrize("code,check", [
    ('cur.execute("SELECT * FROM t WHERE a=%s" % a)', "C2"),
    ('el.innerHTML = "<b>" + name', "C3"),
    ("subprocess.run(cmd, shell=True)", "C5"),
    ("const q = `SELECT * FROM users WHERE id=${id}`; db.query(q)", "C2"),
])
def test_individual_patterns(code, check):
    ext = ".js" if ("const" in code or "el." in code) else ".py"
    findings, _, _ = run_static_scan(load_zip(zip_bytes({f"x{ext}": code}))[0])
    assert check in {f.check_id for f in findings}


@pytest.mark.parametrize("code", [
    'cur.execute("SELECT * FROM t WHERE a = ?", (a,))',
    "model.eval()", "re.compile(x).exec(s)", "app.run(debug=False)", 'el.innerHTML = "<b>static</b>"',
    'API_KEY = os.environ["API_KEY"]', 'password_field = "password"', 'token = "your_token_here"',
])
def test_safe_code_is_not_flagged(code):
    findings, _, _ = run_static_scan(load_zip(zip_bytes({"safe.py": code}))[0])
    assert findings == []


def test_express_routes_are_inventoried():
    js = ('app.get("/admin/users", (req, res) => res.json(db.all()));\n'
          'app.get("/me", authenticate, (req, res) => res.json(req.user));\n')
    _, eps, _ = run_static_scan(load_zip(zip_bytes({"server.js": js}))[0])
    status = {e.path: e.auth_status for e in eps}
    assert status == {"/admin/users": "unprotected", "/me": "protected"}


# ------------------------------------------------------------ scoring
def test_scoring_math():
    assert risk_of(5, "high") == 5 and risk_of(4, "medium") == 2.8
    assert [band_of(x) for x in (4, 3, 2, 1.9)] == ["Critical", "High", "Medium", "Low"]
    r = ScanResult(scan_id="x", project_name="x", created_at="", files_scanned=1, findings=[
        Finding(check_id="C1", title="t", file="a", line=1, evidence="e", severity=5, confidence="high", verdict="rejected")])
    finalize(r)
    assert r.score == 100 and r.counts.Critical == 0     # rejected findings do not count


def zip_bytes(files: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for n, t in files.items():
            z.writestr(n, t)
    return buf.getvalue()


# ------------------------------------------------------------ loader safety
def test_zip_slip_binary_and_dependencies_are_skipped():
    data = zip_bytes({"../evil.py": "eval(x)", "/abs.py": "x=1", "node_modules/a.js": "eval(x)",
                      "ok/app.py": "x = 1", "img.bin": "\x00\x01"})
    files, _ = load_zip(data)
    paths = {f.path for f in files}
    assert not any(".." in x or x.startswith("/") for x in paths)
    assert "evil.py" not in paths and not any("node_modules" in x for x in paths) and "img.bin" not in paths


def test_invalid_zip_is_rejected():
    with pytest.raises(ValueError):
        load_zip(b"not a zip")


# ------------------------------------------------------------ live-check guard
@pytest.mark.parametrize("url", ["http://example.com", "http://10.0.0.5:8000", "http://localhost@evil.com",
                                 "http://evil.com/localhost", "ftp://localhost", "localhost:5000", "http://169.254.169.254"])
def test_live_checks_refuse_non_local_targets(url):
    with pytest.raises(ValueError):
        validate_target(url)


@pytest.mark.parametrize("url,out", [("http://localhost:5000/x", "http://localhost:5000"),
                                     ("http://127.0.0.1:8000", "http://127.0.0.1:8000"), ("http://[::1]:3000", "http://[::1]:3000")])
def test_live_checks_accept_localhost(url, out):
    assert validate_target(url) == out


# ------------------------------------------------------------ API
@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setattr(config, "GEMINI_API_KEY", "")
    return TestClient(app)


def test_consent_is_mandatory(client):
    r = client.post("/scan", files={"file": ("a.zip", zip_of(VULN))}, data={"consent": "false"})
    assert r.status_code == 400 and "authorized" in r.json()["detail"]


def test_remote_live_url_is_rejected_before_scanning(client):
    r = client.post("/scan", files={"file": ("a.zip", zip_of(VULN))},
                    data={"consent": "true", "live_url": "https://example.com"})
    assert r.status_code == 400 and "localhost" in r.json()["detail"]


def test_full_flow_scan_patch_rescan_report(client):
    r = client.post("/scan", files={"file": ("a.zip", zip_of(VULN))}, data={"consent": "true", "project_name": "TaskBoard"})
    assert r.status_code == 200
    scan = r.json()
    assert scan["status"] == "complete" and "context" not in scan["findings"][0]
    assert scan["ai_status"].startswith("disabled")
    sid, fid = scan["scan_id"], scan["findings"][0]["id"]

    p = client.patch(f"/scan/{sid}/findings/{fid}", json={"verdict": "rejected", "reviewed": True})
    assert p.status_code == 200 and p.json()["score"] > scan["score"]

    rs = client.post("/rescan", files={"file": ("b.zip", zip_of(FIXED))}, data={"consent": "true", "previous_scan_id": sid})
    cmp = rs.json()["comparison"]
    assert rs.json()["score"] >= 85 and cmp["delta"] > 0 and len(cmp["resolved"]) > 5 and cmp["new"] == []

    md = client.get(f"/report/{sid}?format=md")
    assert md.status_code == 200 and "## Endpoint inventory" in md.text and "9f3a7c1d5e8b" not in md.text
    assert "<script" not in client.get(f"/report/{sid}?format=html").text
    assert client.get(f"/report/{sid}?format=pdf").status_code == 400
    assert client.get("/scan/doesnotexist").status_code == 404


def test_paste_scan_and_headers(client):
    r = client.post("/scan/paste", json={"consent": True, "files": {"app.py": "app.run(debug=True)"}})
    assert r.status_code == 200 and r.json()["findings"][0]["check_id"] == "C6"
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["x-frame-options"] == "DENY"


def test_upload_limit(client, monkeypatch):
    monkeypatch.setattr(config, "MAX_UPLOAD_BYTES", 100)
    r = client.post("/scan", files={"file": ("a.zip", zip_of(VULN))}, data={"consent": "true"})
    assert r.status_code == 413


# ------------------------------------------------------------ Gemini enrichment (mocked, no network)
def test_gemini_enrichment_cache_fallback_and_overrides(monkeypatch, tmp_path):
    import asyncio
    from app import gemini_client as g
    monkeypatch.setattr(config, "CACHE_FILE", tmp_path / "cache.json")
    monkeypatch.setattr(g, "_cache", {}); monkeypatch.setattr(g, "_cache_loaded", True)
    calls = []

    async def fake(f):
        calls.append(f.id)
        if f.check_id == "C6":
            raise RuntimeError("boom")
        return g._Out(verdict="rejected", verdict_reason="Looks like a test fixture.", explanation="AI says hi. sk-live-9f3a7c1d5e8b2a4c6d0e1f23a9f2",
                      fix=g._FixOut(before="a", after="b", steps=["one", "two", "three", "four"]))
    monkeypatch.setattr(g, "_call", fake)
    monkeypatch.setattr(config, "GEMINI_TIMEOUT_S", 2)

    r = scan_folder(VULN)
    overridden = r.findings[0]
    overridden.verdict, overridden.user_override = "confirmed", True
    stats = asyncio.run(g.enrich_findings(r.findings))
    debug = next(f for f in r.findings if f.check_id == "C6")

    assert stats["failed"] == 1 and not debug.ai_enriched and debug.explanation      # static fallback kept
    assert overridden.verdict == "confirmed" and overridden.ai_enriched               # human override wins
    ai = next(f for f in r.findings if f.check_id == "C2")
    assert ai.verdict == "rejected" and len(ai.fix.steps) == 3 and "9f3a7c1d5e8b" not in ai.explanation

    n = len(calls)
    asyncio.run(g.enrich_findings(scan_folder(VULN).findings))                        # second run hits the cache
    assert len(calls) - n == 2                                                       # only the 2 failed C6-type findings retried (x2 attempts)


def test_prompt_contains_only_masked_snippets():
    from app import gemini_client as g
    for f in scan_folder(VULN).findings:
        prompt = g.build_prompt(f)
        assert all(s not in prompt for s in SECRETS) and "untrusted_code" in prompt
