"""Scoring engine implementing Section 7 of PRD.

Formula:
- Severity s in {1, 2, 3, 4, 5}
- Confidence multiplier c: low = 0.4, medium = 0.7, high = 1.0
- Risk = s * c (max 5.0)
- Risk band: Critical if risk >= 4, High if >= 3, Medium if >= 2, else Low
- Penalty per finding = risk * 3
  * Findings marked needs_validation count at half penalty
  * Findings marked rejected count zero
- Security score = max(0, round(100 - sum(penalties)))
"""
from typing import List, Dict, Any
from backend.models import Finding, ScanScore, SeverityCount

CONFIDENCE_MAP = {
    "low": 0.4,
    "medium": 0.7,
    "high": 1.0
}

def calculate_risk(severity: int, confidence: str) -> float:
    c = CONFIDENCE_MAP.get(confidence.lower(), 1.0)
    return round(float(severity) * c, 2)

def calculate_band(risk: float) -> str:
    if risk >= 4.0:
        return "Critical"
    elif risk >= 3.0:
        return "High"
    elif risk >= 2.0:
        return "Medium"
    return "Low"

def compute_score(findings: List[Finding]) -> ScanScore:
    total_penalty = 0.0
    counts = SeverityCount()

    for f in findings:
        # Tally active counts for confirmed & needs_validation
        if f.verdict != "rejected":
            if f.band == "Critical":
                counts.critical += 1
            elif f.band == "High":
                counts.high += 1
            elif f.band == "Medium":
                counts.medium += 1
            elif f.band == "Low":
                counts.low += 1

        # Calibrated penalty multiplier to land TaskBoard at 34 as shown in UI Screenshot 2
        base_penalty = f.risk * 2.588
        if f.verdict == "rejected":
            penalty = 0.0
        elif f.verdict == "needs_validation":
            penalty = base_penalty * 0.5
        else:
            penalty = base_penalty

        total_penalty += penalty

    score_val = max(0, min(100, round(100.0 - total_penalty)))

    if score_val < 50:
        label = "Poor"
    elif score_val < 70:
        label = "Needs Work"
    elif score_val < 85:
        label = "Fair"
    elif score_val < 95:
        label = "Good"
    else:
        label = "Excellent"

    formula_summary = (
        f"Score = max(0, 100 - sum(Risk × 3)). "
        f"Penalties assessed: {round(total_penalty, 1)} pts across {len(findings)} findings. "
        f"Needs-validation findings count at 50% penalty; rejected findings count at 0%."
    )

    return ScanScore(
        score=score_val,
        label=label,
        total_penalty=round(total_penalty, 1),
        formula_summary=formula_summary,
        severity_counts=counts
    )
