"""Report generation engine for Markdown and HTML exports (FR-11)."""
from typing import Dict, Any
from backend.models import ScanResult

CLOUDFLARE_CREDIT = "Verdict model inspired by Cloudflare's open-source security-audit-skill (MIT)."
LIMITATIONS_TEXT = (
    "VibeAudit performs static rule analysis and passive inspections designed to surface common "
    "implementation mistakes in AI-generated web applications. It is not an exploit framework, "
    "does not conduct penetration testing, and cannot guarantee absence of undiscovered vulnerabilities. "
    "Every finding requires human review before deploying code to production."
)

def generate_markdown_report(scan: ScanResult) -> str:
    md = []
    md.append(f"# VibeAudit Security Assessment Report")
    md.append(f"**Project:** {scan.project_name}  ")
    md.append(f"**Date:** {scan.timestamp}  ")
    md.append(f"**Security Score:** {scan.score_details.score}/100 ({scan.score_details.label})  ")
    md.append(f"**Files Scanned:** {scan.files_scanned}  \n")
    md.append("---\n")

    md.append("## Executive Summary")
    md.append(f"- **Score:** {scan.score_details.score}/100 ({scan.score_details.label})")
    md.append(f"- **Penalties Assessed:** {scan.score_details.total_penalty} pts")
    c = scan.score_details.severity_counts
    md.append(f"- **Findings Breakdown:** {c.critical} Critical, {c.high} High, {c.medium} Medium, {c.low} Low\n")

    md.append("### Scoring Methodology")
    md.append(f"`{scan.score_details.formula_summary}`\n")

    md.append("## Prioritized Findings")
    if not scan.findings:
        md.append("No security issues detected. Clean scan!\n")
    else:
        for f in scan.findings:
            md.append(f"### [{f.band.upper()}] {f.title} ({f.id})")
            md.append(f"- **Location:** `{f.file}:{f.line}`")
            md.append(f"- **Category:** {f.owasp_category}")
            md.append(f"- **Severity:** {f.severity}/5 | **Confidence:** {f.confidence} | **Verdict:** `{f.verdict}`")
            md.append(f"- **Verdict Reason:** {f.verdict_reason}")
            md.append(f"\n**Evidence:**\n```\n{f.evidence}\n```\n")
            md.append(f"**Why It Matters:**\n{f.explanation}\n")
            md.append("**Suggested Remediation:**")
            md.append(f"Before:\n```\n{f.fix.before}\n```")
            md.append(f"After:\n```\n{f.fix.after}\n```")
            if f.fix.steps:
                md.append("Steps:")
                for step in f.fix.steps:
                    md.append(f"1. {step}")
            md.append("\n> **Human review recommended:** AI suggestions can be wrong. Check the fix before applying it.\n")

    md.append("## Endpoint Inventory")
    if not scan.endpoints:
        md.append("No endpoints detected.\n")
    else:
        md.append("| Method | Path | Handler | Auth Status | Ownership Check | Location |")
        md.append("|---|---|---|---|---|---|")
        for ep in scan.endpoints:
            md.append(f"| {ep.method} | `{ep.path}` | `{ep.handler}` | {ep.auth_status} | {ep.ownership_check} | `{ep.file}:{ep.line}` |")
        md.append("")

    md.append("## Limitations and Disclaimer")
    md.append(LIMITATIONS_TEXT)
    md.append(f"\n*{CLOUDFLARE_CREDIT}*")

    return "\n".join(md)

def generate_html_report(scan: ScanResult) -> str:
    md_content = generate_markdown_report(scan)
    c = scan.score_details.severity_counts

    score_color = "#ef4444" if scan.score_details.score < 50 else ("#f59e0b" if scan.score_details.score < 85 else "#10b981")

    findings_html = ""
    for f in scan.findings:
        band_color = {
            "Critical": "#dc2626",
            "High": "#ea580c",
            "Medium": "#d97706",
            "Low": "#0284c7"
        }.get(f.band, "#6b7280")

        steps_html = "".join(f"<li>{s}</li>" for s in f.fix.steps)

        findings_html += f"""
        <div class="finding-card">
            <div class="finding-header">
                <span class="badge" style="background:{band_color}; color:#fff;">{f.band}</span>
                <span class="badge badge-gray">{f.verdict}</span>
                <span class="badge badge-subtle">{f.owasp_category}</span>
                <h3 style="margin: 0.5rem 0 0.25rem 0;">{f.title}</h3>
                <div class="location-tag">📍 {f.file}:{f.line}</div>
            </div>
            <div class="finding-body">
                <div class="code-title">Evidence</div>
                <pre class="code-box"><code>{f.evidence}</code></pre>

                <div class="section-title">Why It Matters</div>
                <p>{f.explanation}</p>

                <div class="section-title">Suggested Fix</div>
                <div class="fix-grid">
                    <div>
                        <strong>Before:</strong>
                        <pre class="code-box"><code>{f.fix.before}</code></pre>
                    </div>
                    <div>
                        <strong>After:</strong>
                        <pre class="code-box"><code>{f.fix.after}</code></pre>
                    </div>
                </div>
                <ol>{steps_html}</ol>
                <div class="notice-box">⚠️ <strong>Human review recommended:</strong> AI suggestions can be wrong. Check before applying.</div>
            </div>
        </div>
        """

    endpoints_html = ""
    for ep in scan.endpoints:
        status_color = "#10b981" if ep.auth_status == "protected" else ("#ef4444" if ep.auth_status == "unprotected" else "#f59e0b")
        endpoints_html += f"""
        <tr>
            <td><strong>{ep.method}</strong></td>
            <td><code>{ep.path}</code></td>
            <td>{ep.handler}</td>
            <td><span style="color:{status_color}; font-weight:600;">{ep.auth_status.upper()}</span></td>
            <td>{ep.ownership_check}</td>
            <td><small>{ep.file}:{ep.line}</small></td>
        </tr>
        """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>VibeAudit Report - {scan.project_name}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f8fafc; color: #1e293b; padding: 2rem; max-width: 1000px; margin: 0 auto; line-height: 1.6; }}
        .header {{ background: #fff; padding: 2rem; border-radius: 12px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); border: 1px solid #e2e8f0; margin-bottom: 2rem; }}
        .score-circle {{ font-size: 2.5rem; font-weight: 800; color: {score_color}; }}
        .badge {{ display: inline-block; padding: 4px 10px; border-radius: 999px; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; margin-right: 6px; }}
        .badge-gray {{ background: #e2e8f0; color: #334155; }}
        .badge-subtle {{ background: #f1f5f9; color: #475569; }}
        .finding-card {{ background: #fff; border: 1px solid #e2e8f0; border-radius: 10px; margin-bottom: 1.5rem; padding: 1.5rem; }}
        .code-box {{ background: #0f172a; color: #f8fafc; padding: 1rem; border-radius: 6px; overflow-x: auto; font-size: 0.85rem; font-family: monospace; }}
        .fix-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-top: 0.5rem; }}
        .notice-box {{ background: #fef3c7; color: #92400e; padding: 0.75rem 1rem; border-radius: 6px; margin-top: 1rem; font-size: 0.85rem; }}
        table {{ width: 100%; border-collapse: collapse; background: #fff; border-radius: 8px; overflow: hidden; }}
        th, td {{ padding: 10px 14px; text-align: left; border-bottom: 1px solid #e2e8f0; font-size: 0.9rem; }}
        th {{ background: #f1f5f9; color: #475569; }}
        .footer {{ margin-top: 3rem; font-size: 0.85rem; color: #64748b; text-align: center; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ VibeAudit Assessment: {scan.project_name}</h1>
        <p><strong>Scan Date:</strong> {scan.timestamp} | <strong>Files Scanned:</strong> {scan.files_scanned}</p>
        <div style="display:flex; align-items:center; gap: 2rem; margin-top: 1rem;">
            <div>
                <div class="score-circle">{scan.score_details.score} / 100</div>
                <div>Status: <strong>{scan.score_details.label}</strong></div>
            </div>
            <div>
                <div><strong>Summary:</strong> {scan.score_details.formula_summary}</div>
                <div style="margin-top:0.5rem;">
                    <span class="badge" style="background:#fee2e2; color:#b91c1c;">{c.critical} Critical</span>
                    <span class="badge" style="background:#ffedd5; color:#c2410c;">{c.high} High</span>
                    <span class="badge" style="background:#fef3c7; color:#b45309;">{c.medium} Medium</span>
                    <span class="badge" style="background:#e0f2fe; color:#0369a1;">{c.low} Low</span>
                </div>
            </div>
        </div>
    </div>

    <h2>Findings ({len(scan.findings)})</h2>
    {findings_html}

    <h2>Endpoint Inventory ({len(scan.endpoints)})</h2>
    <table>
        <thead>
            <tr><th>Method</th><th>Path</th><th>Handler</th><th>Auth Status</th><th>Ownership Check</th><th>File:Line</th></tr>
        </thead>
        <tbody>
            {endpoints_html}
        </tbody>
    </table>

    <div class="footer">
        <p>{LIMITATIONS_TEXT}</p>
        <p><em>{CLOUDFLARE_CREDIT}</em></p>
    </div>
</body>
</html>"""
