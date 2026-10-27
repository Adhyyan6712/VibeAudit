"""Markdown and HTML report export. Everything shown is already masked."""
import html

from .models import ScanResult

LIMITS = ("VibeAudit uses pattern-based static checks and optional AI explanations. It can produce false positives "
          "and false negatives, it is not a substitute for a professional penetration test, and every finding "
          "should be reviewed by a human before action is taken.")
CREDIT = "Verdict model inspired by Cloudflare's open-source security-audit-skill (MIT)."


def to_markdown(r: ScanResult) -> str:
    out = [f"# VibeAudit report: {r.project_name}", "",
           f"**Score:** {r.score}/100 ({r.rating}) · **Findings:** {r.counts.Critical} Critical, {r.counts.High} High, "
           f"{r.counts.Medium} Medium, {r.counts.Low} Low · **Files scanned:** {r.files_scanned} · **Date:** {r.created_at}", "",
           f"*How the score works:* {r.formula}", ""]
    if r.comparison:
        c = r.comparison
        out += [f"**Re-scan:** {c.old_score} -> {c.new_score} ({c.delta:+d}); {len(c.resolved)} resolved, {len(c.new)} new.", ""]
    out += ["## Endpoint inventory", "", "| Method | Path | Auth | Ownership | File | Notes |", "|---|---|---|---|---|---|"]
    out += [f"| {e.method} | `{e.path}` | {e.auth_status} | {e.ownership_check} | {e.file}:{e.line} | {e.notes} |" for e in r.endpoints]
    out += ["", "## Findings", ""]
    for f in r.findings:
        out += [f"### {f.id} · {f.title} ({f.band})", "",
                f"`{f.file}:{f.line}` · severity {f.severity} × confidence {f.confidence} = risk {f.risk} · verdict **{f.verdict}** · {f.owasp_category}",
                "", f"> {f.verdict_reason}" if f.verdict_reason else "", "", "```", f.evidence, "```", "", f.explanation, "",
                "**Suggested fix**", "", "Before:", "```", f.fix.before, "```", "After:", "```", f.fix.after, "```", ""]
        out += [f"{n}. {s}" for n, s in enumerate(f.fix.steps, 1)]
        out += ["", "*Human review recommended.*", ""]
    out += ["## Limitations", "", LIMITS, "", CREDIT]
    return "\n".join(out)


def to_html(r: ScanResult) -> str:
    e = html.escape
    rows = "".join(f"<tr><td>{e(x.method)}</td><td><code>{e(x.path)}</code></td><td>{e(x.auth_status)}</td><td>{e(x.ownership_check)}</td><td>{e(x.file)}:{x.line}</td></tr>" for x in r.endpoints)
    cards = "".join(
        f"<section class='f {e(f.band.lower())}'><h3>{e(f.id)} · {e(f.title)} <span class='b'>{e(f.band)}</span></h3>"
        f"<p class='m'><code>{e(f.file)}:{f.line}</code> · risk {f.risk} · verdict <b>{e(f.verdict)}</b> · {e(f.owasp_category)}</p>"
        f"<pre>{e(f.evidence)}</pre><p>{e(f.explanation)}</p><p><b>Before</b></p><pre>{e(f.fix.before)}</pre><p><b>After</b></p><pre>{e(f.fix.after)}</pre>"
        f"<ol>{''.join(f'<li>{e(s)}</li>' for s in f.fix.steps)}</ol><p class='m'>Human review recommended.</p></section>" for f in r.findings)
    return (f"<!doctype html><html lang='en'><meta charset='utf-8'><title>VibeAudit: {e(r.project_name)}</title>"
            "<style>body{font:16px/1.5 system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;background:#faf6ec;color:#2b2118}"
            "table{border-collapse:collapse;width:100%}td,th{border:1px solid #d9cdb4;padding:6px;text-align:left}pre{background:#2b2118;color:#f3ead7;padding:10px;border-radius:8px;overflow:auto;white-space:pre-wrap}"
            ".f{background:#fff;border:1px solid #d9cdb4;border-radius:12px;padding:1rem;margin:1rem 0}.b{font-size:.75rem;background:#e9dfcb;border-radius:99px;padding:2px 10px}.m{color:#5b4b3a;font-size:.9rem}</style>"
            f"<h1>VibeAudit report: {e(r.project_name)}</h1><h2>Score {r.score}/100 ({e(r.rating)})</h2>"
            f"<p>{r.counts.Critical} Critical · {r.counts.High} High · {r.counts.Medium} Medium · {r.counts.Low} Low · {r.files_scanned} files · {e(r.created_at)}</p>"
            f"<p class='m'>{e(r.formula)}</p><h2>Endpoint inventory</h2><table><tr><th>Method</th><th>Path</th><th>Auth</th><th>Ownership</th><th>Location</th></tr>{rows}</table>"
            f"<h2>Findings</h2>{cards}<h2>Limitations</h2><p>{e(LIMITS)}</p><p class='m'>{e(CREDIT)}</p></html>")
