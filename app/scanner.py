"""Orchestrates the static scan: rule engine + endpoint inventory -> findings."""
import hashlib
import re

from .loader import SourceFile
from .masking import mask_text
from .models import Endpoint, Finding, Fix
from .routes import analyze_routes
from .rules import CHECKS, CHECK_BY_ID, Match, CheckDef
from .scoring import band_of, risk_of


def context_for(f: SourceFile, line: int, radius: int = 3) -> str:
    lo, hi = max(0, line - 1 - radius), min(len(f.lines), line + radius)
    return mask_text("\n".join(f"{n + 1}: {f.lines[n][:200]}" for n in range(lo, hi)))


def fingerprint(check_id: str, file: str, evidence: str) -> str:
    norm = re.sub(r"\s+", "", evidence)
    return hashlib.sha1(f"{check_id}|{file}|{norm}".encode()).hexdigest()[:16]


def make_finding(check: CheckDef, file: str, m: Match, context: str = "", source: str = "static") -> Finding:
    sev = m.severity or check.severity
    evidence = mask_text(m.snippet)[:300]
    risk = risk_of(sev, m.confidence)
    low = m.confidence == "low"
    return Finding(
        check_id=check.id, title=check.title, file=file, line=m.line, evidence=evidence, severity=sev,
        confidence=m.confidence, risk=risk, band=band_of(risk),
        verdict="needs_validation" if low else "confirmed",
        verdict_reason=(m.note + " Confidence is low, so a human should confirm.") if low else m.note,
        explanation=check.explanation,
        fix=Fix(before=check.fix_before, after=check.fix_after, steps=list(check.steps)),
        owasp_category=check.owasp, source=source, context=mask_text(context),
        fingerprint=fingerprint(check.id, file, evidence))


def run_static_scan(files: list[SourceFile]) -> tuple[list[Finding], list[Endpoint], list[str]]:
    by_path = {f.path: f for f in files}
    findings: list[Finding] = []
    for f in files:
        for check in CHECKS:
            if check.detector:
                for m in check.detector(f):
                    findings.append(make_finding(check, f.path, m, context_for(f, m.line)))
    endpoints, route_matches = analyze_routes(files)
    for cid, path, m in route_matches:
        findings.append(make_finding(CHECK_BY_ID[cid], path, m, context_for(by_path[path], m.line)))
    seen, unique = set(), []
    for fd in findings:
        key = (fd.check_id, fd.file, fd.line)
        if key not in seen:
            seen.add(key)
            unique.append(fd)
    unique.sort(key=lambda x: (-x.risk, x.check_id, x.file, x.line))
    assign_ids(unique)
    notes = []
    if not any(f.ext in {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"} for f in files):
        notes.append("No Python or JavaScript source files were found, so most checks had nothing to analyse.")
    return unique, endpoints, notes


def assign_ids(findings: list[Finding], start: int = 1) -> None:
    for n, fd in enumerate(findings, start):
        if not fd.id:
            fd.id = f"F-{n:02d}"
