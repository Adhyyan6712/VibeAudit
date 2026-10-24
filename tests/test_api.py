"""Integration tests for FastAPI endpoints."""
import pytest
from starlette.testclient import TestClient
from backend.app import app

client = TestClient(app)

def test_health():
    res = client.get("/api/health")
    assert res.status_code == 200
    assert res.json()["status"] == "ok"

def test_samples():
    res = client.get("/api/samples")
    assert res.status_code == 200
    samples = res.json()
    assert len(samples) >= 2
    ids = [s["id"] for s in samples]
    assert "taskboard" in ids
    assert "taskboard_fixed" in ids

def test_scan_consent_required():
    # Calling scan without consent must be rejected (FR-1)
    res = client.post("/scan", data={"project_name": "Test", "consent": "false"})
    assert res.status_code == 400
    assert "Consent required" in res.json()["detail"]

def test_scan_taskboard_demo():
    res = client.post("/scan", data={
        "project_name": "TaskBoard",
        "consent": "true",
        "sample_id": "taskboard"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["project_name"] == "TaskBoard"
    assert "score_details" in data
    assert data["score_details"]["score"] >= 20 and data["score_details"]["score"] <= 45
    assert len(data["findings"]) >= 8
    assert len(data["endpoints"]) >= 10

    scan_id = data["id"]

    # Test report export
    res_html = client.get(f"/report/{scan_id}?format=html")
    assert res_html.status_code == 200
    assert "VibeAudit" in res_html.text

    res_md = client.get(f"/report/{scan_id}?format=md")
    assert res_md.status_code == 200
    assert "VibeAudit Security Assessment Report" in res_md.text

    # Test re-scan flow
    res_rescan = client.post("/rescan", data={
        "old_scan_id": scan_id,
        "consent": "true",
        "sample_id": "taskboard_fixed"
    })
    assert res_rescan.status_code == 200
    rescan_data = res_rescan.json()
    assert rescan_data["score_delta"] > 0
    assert rescan_data["new_score"] > rescan_data["old_score"]
    assert len(rescan_data["resolved_findings"]) > 0

def test_live_check_localhost_allowlist():
    # Allowed localhost
    res_ok = client.post("/live-check", json={"target_url": "http://127.0.0.1:5000"})
    assert res_ok.status_code == 200
    data_ok = res_ok.json()
    # Even if port is not running, host was accepted by allowlist
    assert "Security restriction" not in data_ok.get("error", "")

    # Disallowed external target rejected strictly (FR-12)
    res_forbidden = client.post("/live-check", json={"target_url": "http://example.com"})
    assert res_forbidden.status_code == 200
    assert "Security restriction" in res_forbidden.json()["error"]

def test_scan_local_folder_path(tmp_path):
    # Create arbitrary folder with some code
    p = tmp_path / "custom_app"
    p.mkdir()
    (p / "main.py").write_text("import sqlite3\n\nconn = sqlite3.connect('test.db')\nuser = 'test'\nconn.execute(f'SELECT * FROM users WHERE name = {user}')\n")
    (p / ".env").write_text("DATABASE_PASSWORD=production_secret_998877\n")

    res = client.post("/scan", data={
        "project_name": "CustomFolderApp",
        "consent": "true",
        "folder_path": str(p)
    })
    assert res.status_code == 200
    data = res.json()
    assert data["files_scanned"] >= 2
    assert len(data["findings"]) >= 2

def test_scan_local_folder_path_with_quotes(tmp_path):
    p = tmp_path / "quoted_app"
    p.mkdir()
    (p / "app.py").write_text("import os\nos.system('echo hello')\n")

    # Pass path enclosed in Windows quotes
    res = client.post("/scan", data={
        "project_name": "QuotedFolderApp",
        "consent": "true",
        "folder_path": f'"{str(p)}"'
    })
    assert res.status_code == 200
    data = res.json()
    assert data["files_scanned"] >= 1

def test_scan_single_code_file_upload():
    code = b"import sqlite3\nquery = f'SELECT * FROM t WHERE id={id}'\nconn.execute(query)\n"
    res = client.post("/scan", data={
        "project_name": "SingleFileApp",
        "consent": "true"
    }, files={
        "file": ("app.py", code, "text/x-python")
    })
    assert res.status_code == 200
    data = res.json()
    assert data["files_scanned"] == 1
    assert any(f["check_id"] == "C2" for f in data["findings"])

def test_scan_multiple_files_folder_upload():
    files = [
        ("files", ("my_app/app.py", b"import os\nos.system('rm -rf /')", "text/x-python")),
        ("files", ("my_app/config.py", b"JWT_SECRET = 'super_secret_jwt_token_12345'", "text/x-python")),
        ("files", ("my_app/templates/index.html", b"<div>{{ content | safe }}</div>", "text/html"))
    ]
    res = client.post("/scan", data={
        "project_name": "BrowserFolderUpload",
        "consent": "true"
    }, files=files)
    assert res.status_code == 200
    data = res.json()
    assert data["files_scanned"] == 3
    assert len(data["findings"]) >= 2

def test_scan_zip_file_upload():
    import os
    zip_path = os.path.join(os.path.dirname(__file__), "..", "sample_zips", "TaskBoard.zip")
    with open(zip_path, "rb") as fp:
        zip_bytes = fp.read()
    res = client.post("/scan", data={
        "project_name": "TaskBoardZip",
        "consent": "true"
    }, files={
        "file": ("TaskBoard.zip", zip_bytes, "application/zip")
    })
    assert res.status_code == 200
    data = res.json()
    assert data["files_scanned"] >= 5
    assert data["score_details"]["score"] == 34
    assert len(data["findings"]) == 9

def test_scan_website_url_invalid():
    res = client.post("/scan", data={
        "consent": "true",
        "website_url": "http://invalid_host_that_does_not_exist_9999.test"
    })
    assert res.status_code == 400

def test_scan_website_url_offline_port():
    # Offline port returns clear connection error
    res = client.post("/scan", data={
        "consent": "true",
        "website_url": "http://127.0.0.1:59999"
    })
    assert res.status_code == 400
    assert "Could not connect" in res.json()["detail"]

def test_scan_website_url_success(monkeypatch):
    import requests
    class MockResponse:
        status_code = 200
        text = "<html><body><h1>Dashboard</h1><script>document.getElementById('out').innerHTML = location.hash;</script></body></html>"
        headers = {
            "Content-Type": "text/html",
            "Access-Control-Allow-Origin": "*"
        }
    
    def mock_get(*args, **kwargs):
        url = args[1] if len(args) > 1 and hasattr(args[0], "get") else args[0]
        if str(url).endswith("/.env") or str(url).endswith("/.git/HEAD"):
            r = MockResponse()
            r.status_code = 404
            r.text = ""
            return r
        return MockResponse()

    monkeypatch.setattr(requests, "get", mock_get)
    monkeypatch.setattr(requests.Session, "get", mock_get)

    res = client.post("/scan", data={
        "consent": "true",
        "website_url": "http://localhost:3000"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["files_scanned"] >= 1
    assert len(data["endpoints"]) == 1
    assert data["endpoints"][0]["handler"] == "HTTP Server"
    assert any(f["check_id"] == "C11" for f in data["findings"])
    assert any(f["check_id"] == "C12" for f in data["findings"])




