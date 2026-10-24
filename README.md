# VibeAudit 🛡️

**A safe, explainable security auditor for AI-generated web applications.**  
Built for Tech Yuva × GDG Gurugram Build-A-Thon 2026 (Problem Statement PS-12).

[![GitHub Repo](https://img.shields.io/badge/GitHub-Adhyyan6712%2FVibeAudit-blue?logo=github)](https://github.com/Adhyyan6712/VibeAudit)
[![Tests Passing](https://img.shields.io/badge/Tests-26%2F26%20Passed-brightgreen)](https://github.com/Adhyyan6712/VibeAudit)
[![Gemini AI](https://img.shields.io/badge/Powered%20By-Google%20Gemini%202.5-orange?logo=google)](https://aistudio.google.com/)

---

### 🌐 Quick Links & Live Showcase
- **GitHub Repository**: [https://github.com/Adhyyan6712/VibeAudit](https://github.com/Adhyyan6712/VibeAudit)
- **GitHub Pages Live App**: [https://adhyyan6712.github.io/VibeAudit/](https://adhyyan6712.github.io/VibeAudit/)
- **Live Tunnel Demo Link**: [https://every-singers-camp.loca.lt](https://every-singers-camp.loca.lt) *(Password if prompted: `121.244.146.154`)*
- **Local Application Link**: `http://127.0.0.1:8000`

---

## 1. Overview
AI coding assistants allow builders to write applications in minutes, but AI-generated code frequently contains exposed endpoints, hardcoded secrets, weak input validation, or missing access checks. **VibeAudit** is an authorized, non-destructive static and route auditor designed to catch these issues before deployment.

- **Deterministic static detection:** Python AST + precision regex rules (never delegates vulnerability discovery to AI).
- **Gemini explainability & remediation:** Uses Gemini API (with JSON schema enforcement) to explain risks in plain language and generate minimal before/after patches.
- **Endpoint Inventory:** Maps routes and automatically flags missing authentication decorators (`@login_required`) and ownership checks.
- **Repeatable Before-and-After Demo:** Shows immediate score improvement from ~34/100 to ~88-100/100 after applying fixes.

---

## 2. Check Catalog
| Check ID | Title | OWASP Category | Severity | Detection Mechanism |
|---|---|---|---|---|
| **C1** | Hardcoded secrets | A02 Cryptographic Failures | 5 | API keys (`sk-...`, `AKIA...`), tokens, committed `.env` files with secret masking |
| **C2** | SQL injection risk | A03 Injection | 5 | String concatenation, f-strings, or % formatting passed to `execute()` |
| **C3** | XSS risk | A03 Injection | 4 / 2 | `innerHTML`, dynamic `render_template_string`, and unescaped `\|safe` filter in Jinja templates |
| **C4** | Weak password handling | A02 Cryptographic Failures | 4 / 5 | MD5 / SHA-1 hashing or plaintext password comparisons |
| **C5** | Dangerous functions | A03 Injection | 4 / 5 | `eval()`, `exec()`, `os.system()`, `subprocess` with `shell=True` |
| **C6** | Debug mode enabled | A05 Security Misconfiguration | 3 | `app.run(..., debug=True)` or active interactive debuggers |
| **C7** | Insecure session/cookie config | A05 Security Misconfiguration | 3 | Missing `HttpOnly`, `Secure`, `SameSite`, or weak/default `SECRET_KEY` |
| **C8** | Missing input validation | A04 Insecure Design | 3 | Handlers parsing `request.json` without schema or validation constraints |
| **C9** | Unprotected sensitive route | A01 Broken Access Control | 5 | Administrative or destructive routes without authentication decorators |
| **C10** | Possible IDOR (Stretch) | A01 Broken Access Control | 4 | Routes taking ID parameters without user ownership verification |
| **C11** | Security headers (Live) | A05 Security Misconfiguration | 2 | Passive check for CSP, X-Frame-Options, HSTS, X-Content-Type-Options on localhost |
| **C12** | Permissive CORS (Live) | A05 Security Misconfiguration | 3 | Passive check for `Access-Control-Allow-Origin: *` on localhost |

---

## 3. Scoring Formula
VibeAudit scores applications transparently according to PRD Section 7:
- **Severity $s \in \{1, 2, 3, 4, 5\}$**
- **Confidence multiplier $c$:** low = 0.4, medium = 0.7, high = 1.0
- **$\text{Risk} = s \times c$**
- **Risk band:** Critical if $\text{risk} \ge 4.0$, High if $\ge 3.0$, Medium if $\ge 2.0$, else Low
- **Penalty per finding:** $\text{Risk} \times 3$
  - Findings marked `needs_validation` count at half penalty ($50\%$).
  - Findings marked `rejected` count as zero penalty ($0\%$).
- **$\text{Security score} = \max(0, 100 - \sum \text{penalties})$**

---

## 4. Safety Guardrails & Compliance
1. **Mandatory Authorization:** Scan button is disabled until the user checks *"I own this application or am authorized to test it."*
2. **Non-Destructive & Safe:** Uploaded code is read statically in memory; it is never executed or imported.
3. **Localhost Allowlist Only:** Live passive inspections (GET/HEAD only) are strictly restricted to `localhost`, `127.0.0.1`, and `::1` enforced in the backend code.
4. **Secret Masking:** All secrets (tokens, connection strings, passwords) are masked in UI, reports, logs, and AI requests (e.g. `sk-••••a9f2`).
5. **Human in the Loop:** Every finding carries a *"Human review recommended"* label.

---

## 5. Quick Start

### Installation
```bash
# Clone and enter workspace
cd "Tech Yuva"

# Install requirements
pip install -r requirements.txt
```

### Running the Application
```bash
python run.py
```
Open **[http://127.0.0.1:8000](http://127.0.0.1:8000)** in your browser.

### Running Unit & Integration Tests
```bash
pytest -v
```

### Environment Variables (Optional)
- `GEMINI_API_KEY`: Google Gemini API key (optional; system includes static fallback templates for zero-dependency local runs).
- `GEMINI_MODEL`: Model name (default: `gemini-2.5-flash`).

---

## 6. Demo Guide (3-Minute Flow)
1. **Initial Scan:** Click **TaskBoard (vulnerable)** on the landing page, check authorization, and click **Start scan**.
2. **Dashboard Overview:** Observe the **34/100 (Poor)** score with 9 prioritized findings across Critical, High, Medium, and Low.
3. **Endpoint Inventory:** Switch to the **Endpoints (11)** tab to highlight unauthenticated administrative endpoints.
4. **Deep Dive:** Click into `F-02: SQL injection risk in login query`. View masked evidence with highlighted line numbers, plain explanation, and before/after remediation with **Copy fix**.
5. **Re-scan:** Click **Re-scan**, select **TaskBoard (Fixed & Hardened)**, and witness the score jump from **34 to 88-100/100** with resolved findings listed.
6. **Report Export:** Download the complete audit report in HTML or Markdown.

---

## 7. Limitations & Credits
- **Limitations:** VibeAudit is a static and passive review tool built for AI-assisted code safety reviews. It is not an exploit framework, does not conduct penetration testing, and cannot guarantee absence of undiscovered vulnerabilities.
- **Credit:** Verdict model inspired by Cloudflare's open-source security-audit-skill (MIT).
