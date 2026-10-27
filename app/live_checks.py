"""Passive, non-destructive live checks. LOCALHOST ONLY, GET/HEAD only, redirects never followed."""
import re
from urllib.parse import urlparse

import httpx

from . import config
from .models import Endpoint, Finding
from .routes import SENSITIVE_PATH
from .rules import CHECK_BY_ID, Match
from .scanner import make_finding

DESTRUCTIVE = re.compile(r"(?i)(delete|remove|destroy|drop|reset|logout|clear|purge|kill|shutdown|wipe|truncate)")
HEADERS = {
    "content-security-policy": "Content-Security-Policy",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
}


def validate_target(url: str) -> str:
    """Return a normalised base URL or raise ValueError. This is enforced in code, not just in the UI."""
    u = urlparse(url.strip())
    if u.scheme not in ("http", "https") or not u.hostname:
        raise ValueError("Live checks need a full http(s) URL such as http://localhost:5000.")
    if u.username or u.password:
        raise ValueError("Credentials in the URL are not allowed.")
    if u.hostname.lower() not in config.LIVE_ALLOWED_HOSTS:
        raise ValueError("Live checks are restricted to localhost, 127.0.0.1 and ::1. Remote targets are refused.")
    host = f"[{u.hostname}]" if ":" in u.hostname else u.hostname
    return f"{u.scheme}://{host}" + (f":{u.port}" if u.port else "")


async def run_live_checks(base_url: str, endpoints: list[Endpoint]) -> tuple[list[Finding], str]:
    base = validate_target(base_url)
    findings: list[Finding] = []
    async with httpx.AsyncClient(follow_redirects=False, timeout=5.0, headers={"User-Agent": "VibeAudit-passive/1.0"}) as client:
        try:
            r = await client.get(base + "/")
        except httpx.HTTPError:
            return [], f"Could not reach {base}. Is the demo app running?"
        have = {k.lower() for k in r.headers}
        missing = [name for key, name in HEADERS.items() if key not in have]
        if base.startswith("https") and "strict-transport-security" not in have:
            missing.append("Strict-Transport-Security")
        if missing:
            findings.append(make_finding(CHECK_BY_ID["C11"], base + "/", Match(
                0, "Missing: " + ", ".join(missing), "high", "Standard browser protections are absent"),
                context=f"GET {base}/ -> {r.status_code}", source="live"))
        try:
            c = await client.get(base + "/", headers={"Origin": "http://untrusted.example"})
            acao = c.headers.get("access-control-allow-origin", "")
            creds = c.headers.get("access-control-allow-credentials", "").lower() == "true"
            if acao == "*" or (acao == "http://untrusted.example" and creds):
                findings.append(make_finding(CHECK_BY_ID["C12"], base + "/", Match(
                    0, f"Access-Control-Allow-Origin: {acao}" + (" with credentials" if creds else ""),
                    "high", "CORS accepts untrusted origins"), context="GET with Origin: http://untrusted.example", source="live"))
        except httpx.HTTPError:
            pass
        probed = 0
        for e in endpoints:
            if probed >= 10:
                break
            if (e.auth_status != "unprotected" or e.public or "GET" not in e.method.split(",") or "{" in e.path
                    or "<" in e.path or ":" in e.path or DESTRUCTIVE.search(e.path) or not SENSITIVE_PATH.search(e.path)):
                continue
            probed += 1
            try:
                p = await client.get(base + e.path)
            except httpx.HTTPError:
                continue
            if p.status_code == 200:
                findings.append(make_finding(CHECK_BY_ID["C13"], base + e.path, Match(
                    0, f"GET {e.path} -> 200 OK ({len(p.content)} bytes, no credentials sent)", "high",
                    "Anonymous request succeeded"), context=f"Static finding at {e.file}:{e.line}", source="live"))
    return findings, f"Passive checks completed against {base} ({probed} endpoints probed, GET/HEAD only)."
