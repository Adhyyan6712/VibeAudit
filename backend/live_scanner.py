"""Passive live localhost scanner (FR-12, C11, C12).

Checks security headers and CORS on localhost only.
Enforces strict host allowlist: localhost, 127.0.0.1, [::1].
GET and HEAD requests only; no payloads, no fuzzing.
"""
from urllib.parse import urlparse
from typing import Dict, Any, List
import requests
from backend.models import LiveCheckFinding, Finding, FixModel, Endpoint

ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]"}

RECOMMENDED_HEADERS = {
    "Content-Security-Policy": "Restricts external scripts and frames to mitigate XSS and clickjacking.",
    "X-Frame-Options": "Prevents clickjacking by controlling if the page can be embedded in an iframe (DENY or SAMEORIGIN).",
    "X-Content-Type-Options": "Prevents MIME-type sniffing (nosniff).",
    "Strict-Transport-Security": "Enforces HTTPS connections for supported hosts (HSTS).",
    "Referrer-Policy": "Controls how much referrer information is sent with requests."
}

def scan_live_localhost(target_url: str) -> Dict[str, Any]:
    """Runs non-destructive passive header and CORS checks on localhost."""
    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url

    parsed = urlparse(target_url)
    hostname = (parsed.hostname or "").lower()

    if hostname not in ALLOWED_HOSTS:
        return {
            "success": False,
            "error": f"Security restriction: Live scans are strictly limited to localhost allowlist ({', '.join(sorted(ALLOWED_HOSTS))}). Host '{hostname}' is rejected."
        }

    try:
        # Passive HEAD request
        head_resp = requests.head(target_url, timeout=3, allow_redirects=True)
        headers = {k.lower(): v for k, v in head_resp.headers.items()}
    except Exception as e:
        # Fallback to GET if HEAD method is not supported by target server
        try:
            get_resp = requests.get(target_url, timeout=3, allow_redirects=True)
            headers = {k.lower(): v for k, v in get_resp.headers.items()}
        except Exception as e_get:
            return {
                "success": False,
                "error": f"Failed to connect to {target_url}: {str(e_get)}"
            }

    header_findings: List[Dict[str, Any]] = []

    # C11: Check standard security headers
    for hdr_name, recommendation in RECOMMENDED_HEADERS.items():
        lower_hdr = hdr_name.lower()
        if lower_hdr in headers:
            header_findings.append({
                "header": hdr_name,
                "status": "present",
                "value": headers[lower_hdr],
                "description": "Header is active."
            })
        else:
            header_findings.append({
                "header": hdr_name,
                "status": "missing",
                "value": None,
                "description": recommendation
            })

    # C12: Check Permissive CORS
    cors_origin = headers.get("access-control-allow-origin")
    cors_issue = None
    if cors_origin == "*":
        cors_issue = {
            "status": "insecure",
            "value": "*",
            "description": "Access-Control-Allow-Origin is set to wildcard '*' which may allow unauthorized websites to read private responses if credentials are used."
        }
    elif cors_origin:
        cors_issue = {
            "status": "present",
            "value": cors_origin,
            "description": f"CORS origin configured to: {cors_origin}"
        }

    return {
        "success": True,
        "target": target_url,
        "security_headers": header_findings,
        "cors": cors_issue
    }

def audit_website_url(target_url: str):
    """Performs passive non-destructive security inspection of any live website or web app (FR-11, FR-12)."""
    import re
    clean_target = target_url.strip()
    if not clean_target.startswith(("http://", "https://")):
        clean_target = "https://" + clean_target if not clean_target.startswith("localhost") and not clean_target.startswith("127.") else "http://" + clean_target

    parsed = urlparse(clean_target)
    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise ValueError(f"Invalid website URL provided: '{target_url}'")

    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9"
    })

    resp = None
    urls_to_try = [clean_target]
    if clean_target.startswith("http://"):
        urls_to_try.append(clean_target.replace("http://", "https://", 1))
    elif clean_target.startswith("https://"):
        urls_to_try.append(clean_target.replace("https://", "http://", 1))

    last_err = None
    for u in urls_to_try:
        try:
            resp = session.get(u, timeout=10, allow_redirects=True, verify=True)
            clean_target = u
            parsed = urlparse(clean_target)
            break
        except Exception:
            try:
                import urllib3
                urllib3.disable_warnings()
                resp = session.get(u, timeout=10, allow_redirects=True, verify=False)
                clean_target = u
                parsed = urlparse(clean_target)
                break
            except Exception as e:
                last_err = e

    if resp is None:
        raise ValueError(f"Could not connect to website URL {clean_target}: {str(last_err)}")

    headers = {k.lower(): v for k, v in resp.headers.items()}
    findings: List[Finding] = []
    endpoints: List[Endpoint] = [
        Endpoint(
            method="GET",
            path=parsed.path or "/",
            handler="HTTP Server",
            file="headers.http",
            line=1,
            auth_status="unprotected" if resp.status_code == 200 else "unknown",
            ownership_check="n/a",
            notes=f"HTTP {resp.status_code} ({len(resp.text)} bytes)"
        )
    ]
    file_map: Dict[str, str] = {
        "headers.http": "\n".join(f"{k.title()}: {v}" for k, v in resp.headers.items()),
        "index.html": resp.text[:30000] if resp.text else "<!-- Empty response body -->"
    }

    finding_counter = 1

    # 1. Content-Security-Policy (C11)
    csp_header = headers.get("content-security-policy", "")
    if not csp_header:
        findings.append(Finding(
            id=f"F-{finding_counter:02d}",
            check_id="C11",
            title="Missing Content-Security-Policy (CSP) header",
            file="headers.http",
            line=1,
            evidence="Content-Security-Policy header is missing in server response",
            severity=3,
            confidence="high",
            risk=3.0,
            band="High",
            verdict="confirmed",
            verdict_reason="Application does not define a Content-Security-Policy, allowing arbitrary external scripts and framing.",
            explanation="A missing Content Security Policy allows attackers to execute injected cross-site scripts or load unauthorized external assets.",
            fix=FixModel(
                before="# Missing Content-Security-Policy header",
                after="Content-Security-Policy: default-src 'self'; script-src 'self'",
                steps=[
                    "Add a restrictive Content-Security-Policy header to HTTP responses.",
                    "Restrict script execution to your own origin ('self').",
                    "Use Content-Security-Policy-Report-Only to test policies before enforcing."
                ]
            ),
            owasp_category="A05 Security Misconfiguration",
            human_review=True
        ))
        finding_counter += 1
    else:
        lower_csp = csp_header.lower()
        if "'unsafe-inline'" in lower_csp or "'unsafe-eval'" in lower_csp:
            reasons = []
            if "'unsafe-inline'" in lower_csp: reasons.append("'unsafe-inline'")
            if "'unsafe-eval'" in lower_csp: reasons.append("'unsafe-eval'")
            findings.append(Finding(
                id=f"F-{finding_counter:02d}",
                check_id="C11",
                title=f"Weak Content-Security-Policy: allows {' and '.join(reasons)}",
                file="headers.http",
                line=1,
                evidence=csp_header[:140] + ("..." if len(csp_header) > 140 else ""),
                severity=3,
                confidence="high",
                risk=2.5,
                band="Medium",
                verdict="confirmed",
                verdict_reason=f"Content-Security-Policy includes dangerous keywords ({', '.join(reasons)}) which undermine XSS protections.",
                explanation="Using 'unsafe-inline' or 'unsafe-eval' in script-src allows an attacker who finds an injection flaw to execute arbitrary JavaScript.",
                fix=FixModel(
                    before=csp_header[:80],
                    after="script-src 'self' 'nonce-RANDOM' https://trusted.cdn.com",
                    steps=[
                        "Remove 'unsafe-inline' and use cryptographic nonces or SHA hashes for inline scripts.",
                        "Refactor code to eliminate 'unsafe-eval' and avoid eval()."
                    ]
                ),
                owasp_category="A05 Security Misconfiguration",
                human_review=True
            ))
            finding_counter += 1

    # 2. Missing X-Frame-Options (C11 Clickjacking)
    if "x-frame-options" not in headers and "frame-ancestors" not in csp_header.lower():
        findings.append(Finding(
            id=f"F-{finding_counter:02d}",
            check_id="C11",
            title="Missing X-Frame-Options header (Clickjacking risk)",
            file="headers.http",
            line=1,
            evidence="X-Frame-Options header is absent",
            severity=2,
            confidence="high",
            risk=2.0,
            band="Medium",
            verdict="confirmed",
            verdict_reason="Application lacks framing protection, making it vulnerable to UI redress and clickjacking attacks.",
            explanation="Without X-Frame-Options: DENY or SAMEORIGIN, malicious third-party pages can frame your web application inside a hidden iframe.",
            fix=FixModel(
                before="# Missing X-Frame-Options",
                after="X-Frame-Options: DENY",
                steps=[
                    "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN' to all HTTP responses.",
                    "Alternatively, declare frame-ancestors 'none' in Content-Security-Policy."
                ]
            ),
            owasp_category="A05 Security Misconfiguration",
            human_review=False
        ))
        finding_counter += 1

    # 3. Missing X-Content-Type-Options: nosniff (C11 MIME Sniffing)
    if headers.get("x-content-type-options", "").lower() != "nosniff":
        findings.append(Finding(
            id=f"F-{finding_counter:02d}",
            check_id="C11",
            title="Missing X-Content-Type-Options: nosniff header",
            file="headers.http",
            line=1,
            evidence="X-Content-Type-Options is missing or not set to nosniff",
            severity=1,
            confidence="high",
            risk=1.0,
            band="Low",
            verdict="confirmed",
            verdict_reason="Absence of nosniff allows browsers to MIME-sniff response bodies and execute uploaded content as scripts.",
            explanation="When X-Content-Type-Options: nosniff is omitted, browsers may try to sniff the MIME type of files.",
            fix=FixModel(
                before="# Missing nosniff header",
                after="X-Content-Type-Options: nosniff",
                steps=["Configure web server to return 'X-Content-Type-Options: nosniff' header."]
            ),
            owasp_category="A05 Security Misconfiguration",
            human_review=False
        ))
        finding_counter += 1

    # 4. Permissive Wildcard CORS (C12)
    cors_hdr = headers.get("access-control-allow-origin")
    if cors_hdr == "*":
        findings.append(Finding(
            id=f"F-{finding_counter:02d}",
            check_id="C12",
            title="Overly permissive CORS policy (Wildcard Access-Control-Allow-Origin: *)",
            file="headers.http",
            line=1,
            evidence="Access-Control-Allow-Origin: *",
            severity=3,
            confidence="high",
            risk=3.0,
            band="High",
            verdict="confirmed",
            verdict_reason="Wildcard CORS allows any third-party origin to read private API responses.",
            explanation="An open wildcard CORS policy permits untrusted websites to make cross-origin requests and read sensitive response data on behalf of users.",
            fix=FixModel(
                before="Access-Control-Allow-Origin: *",
                after="Access-Control-Allow-Origin: https://trusted.example.com",
                steps=[
                    "Restrict CORS origins to explicit trusted domain names.",
                    "Never return wildcard '*' when responses contain user-specific data."
                ]
            ),
            owasp_category="A05 Security Misconfiguration",
            human_review=True
        ))
        finding_counter += 1

    # 5. Missing Permissions-Policy (C11)
    if "permissions-policy" not in headers and "feature-policy" not in headers:
        findings.append(Finding(
            id=f"F-{finding_counter:02d}",
            check_id="C11",
            title="Missing Permissions-Policy header",
            file="headers.http",
            line=1,
            evidence="Permissions-Policy header is absent",
            severity=1,
            confidence="medium",
            risk=1.0,
            band="Low",
            verdict="confirmed",
            verdict_reason="Without Permissions-Policy, embedded iframes and third-party scripts can access camera, microphone, and geolocation APIs.",
            explanation="The Permissions-Policy HTTP header allows website owners to explicitly enable or disable browser features and device hardware APIs.",
            fix=FixModel(
                before="# Missing Permissions-Policy",
                after="Permissions-Policy: camera=(), microphone=(), geolocation=()",
                steps=["Add Permissions-Policy: camera=(), microphone=(), geolocation=() to responses."]
            ),
            owasp_category="A05 Security Misconfiguration",
            human_review=False
        ))
        finding_counter += 1

    # 6. Insecure Cookies (C7)
    for cookie_str in resp.headers.get("set-cookie", "").split(","):
        if cookie_str and ("httponly" not in cookie_str.lower() or "secure" not in cookie_str.lower()):
            findings.append(Finding(
                id=f"F-{finding_counter:02d}",
                check_id="C7",
                title="Insecure cookie missing HttpOnly or Secure flag",
                file="headers.http",
                line=1,
                evidence=cookie_str.strip()[:100],
                severity=3,
                confidence="medium",
                risk=2.0,
                band="Medium",
                verdict="confirmed",
                verdict_reason="Cookie is accessible to JavaScript or sent over unencrypted connections.",
                explanation="Without HttpOnly, any cross-site scripting flaw can be used to steal session tokens. Without Secure, cookies can be intercepted over unencrypted HTTP.",
                fix=FixModel(
                    before=cookie_str.strip()[:60],
                    after=f"{cookie_str.strip()[:40]}; Secure; HttpOnly; SameSite=Lax",
                    steps=[
                        "Add HttpOnly to prevent JavaScript access via document.cookie.",
                        "Add Secure flag to ensure cookies are only transmitted over HTTPS.",
                        "Set SameSite=Lax or SameSite=Strict to protect against CSRF."
                    ]
                ),
                owasp_category="A07 Identification and Authentication Failures",
                human_review=True
            ))
            finding_counter += 1
            break

    # 7. Sensitive file probe (C1)
    base_target = f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
    try:
        env_probe = session.get(base_target + "/.env", timeout=3, allow_redirects=False)
        if env_probe.status_code == 200 and ("=" in env_probe.text or "KEY" in env_probe.text.upper()):
            file_map[".env"] = env_probe.text[:5000]
            masked_env = mask_snippet(env_probe.text[:120])
            findings.append(Finding(
                id=f"F-{finding_counter:02d}",
                check_id="C1",
                title="Exposed sensitive file: /.env is publicly downloadable",
                file="/.env",
                line=1,
                evidence=masked_env,
                severity=5,
                confidence="high",
                risk=5.0,
                band="Critical",
                verdict="confirmed",
                verdict_reason="Web server directly serves application environment file containing active secrets.",
                explanation="The running web server is configured without file extension restrictions, allowing anyone on the network to download the .env file.",
                fix=FixModel(
                    before="# Publicly serving /.env",
                    after="# In web server: forbid access to hidden dotfiles\nif path.startswith('/.'): abort(403)",
                    steps=[
                        "Configure the web server to deny access to all hidden files and dotfiles.",
                        "Move .env outside of the web root folder.",
                        "Immediately rotate any credentials exposed in the public .env file."
                    ]
                ),
                owasp_category="A01 Broken Access Control",
                human_review=True
            ))
            finding_counter += 1
    except Exception:
        pass

    # 8. Check client HTML and scripts for Subresource Integrity and DOM XSS sinks (C3)
    if resp.text:
        cdn_script_regex = re.compile(r'<script\b[^>]*src=[\'"](https?://[^>"\']+)[\'"][^>]*>', re.IGNORECASE)
        for line_no, line in enumerate(resp.text.splitlines(), start=1):
            m = cdn_script_regex.search(line)
            if m:
                script_url = m.group(1)
                if ("cdnjs" in script_url or "cdn" in script_url or "unpkg" in script_url) and "integrity=" not in line.lower():
                    findings.append(Finding(
                        id=f"F-{finding_counter:02d}",
                        check_id="C11",
                        title="Third-party script loaded without Subresource Integrity (SRI)",
                        file="index.html",
                        line=line_no,
                        evidence=line.strip()[:110],
                        severity=2,
                        confidence="high",
                        risk=1.5,
                        band="Low",
                        verdict="confirmed",
                        verdict_reason="External CDN script is included without an integrity cryptographic hash.",
                        explanation="If a third-party CDN is compromised, an attacker can manipulate the hosted JavaScript file to inject malicious payloads into all visiting browsers.",
                        fix=FixModel(
                            before=line.strip()[:70],
                            after=f'{line.strip()[:-1]} integrity="sha384-..." crossorigin="anonymous">',
                            steps=[
                                "Generate a cryptographic SHA-384 hash of the external library file.",
                                "Add the 'integrity' and 'crossorigin=\"anonymous\"' attributes to the <script> tag."
                            ]
                        ),
                        owasp_category="A08 Software and Data Integrity Failures",
                        human_review=False
                    ))
                    finding_counter += 1
                    break

        dom_xss_regex = re.compile(r'(\.innerHTML\s*=\s*[^;\n]+)', re.IGNORECASE)
        for line_no, line in enumerate(resp.text.splitlines(), start=1):
            m = dom_xss_regex.search(line)
            if m and any(kw in line.lower() for kw in ["location", "hash", "params", "search", "url", "input", "value"]):
                findings.append(Finding(
                    id=f"F-{finding_counter:02d}",
                    check_id="C3",
                    title="Client-side DOM XSS sink in frontend script",
                    file="index.html",
                    line=line_no,
                    evidence=line.strip()[:100],
                    severity=3,
                    confidence="medium",
                    risk=2.5,
                    band="Medium",
                    verdict="needs_validation",
                    verdict_reason="Client script assigns user-controlled URL/input properties directly to innerHTML.",
                    explanation="Direct assignment of dynamic or user-controlled input to innerHTML allows malicious actors to inject client-side script tags.",
                    fix=FixModel(
                        before=line.strip()[:60],
                        after=line.replace(".innerHTML", ".textContent").strip()[:60],
                        steps=[
                            "Use element.textContent or element.innerText instead of innerHTML.",
                            "Sanitize dynamic content using DOMPurify before inserting."
                        ]
                    ),
                    owasp_category="A03 Injection",
                    human_review=True
                ))
                finding_counter += 1
                break

    return findings, endpoints, file_map

