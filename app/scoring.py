"""Explainable scoring: risk = severity x confidence; score = 100 - capped penalties."""
from collections import defaultdict

CONFIDENCE = {"low": 0.4, "medium": 0.7, "high": 1.0}
PENALTY_FACTOR = 1.0          # penalty points per risk point
PER_CHECK_CAP = 15            # one noisy check cannot take more than this many points

FORMULA = (
    "risk = severity (1-5) x confidence (low 0.4, medium 0.7, high 1.0). "
    "Bands: Critical >= 4, High >= 3, Medium >= 2, otherwise Low. "
    f"Penalty = risk x {PENALTY_FACTOR} (needs_validation counts half, rejected counts zero, reviewed findings still count). "
    f"Each check can remove at most {PER_CHECK_CAP} points. Score = 100 - total penalty, minimum 0."
)


def risk_of(severity: int, confidence: str) -> float:
    return round(severity * CONFIDENCE[confidence], 2)


def band_of(risk: float) -> str:
    return "Critical" if risk >= 4 else "High" if risk >= 3 else "Medium" if risk >= 2 else "Low"


def penalty_of(f) -> float:
    if f.verdict == "rejected":
        return 0.0
    return f.risk * PENALTY_FACTOR * (0.5 if f.verdict == "needs_validation" else 1.0)


def rating_of(score: int) -> str:
    return "Good" if score >= 85 else "Fair" if score >= 60 else "Poor"


def finalize(result) -> None:
    """Recompute risk, bands, counts, score and rating in place."""
    from .models import ScoreDetails, SeverityCounts
    per_check = defaultdict(float)
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in result.findings:
        f.risk = risk_of(f.severity, f.confidence)
        f.band = band_of(f.risk)
        per_check[f.check_id] += penalty_of(f)
        if f.verdict != "rejected":
            counts[f.band] += 1
    result.counts = type(result.counts)(**counts)
    result.score = max(0, round(100 - sum(min(v, PER_CHECK_CAP) for v in per_check.values())))
    result.rating = rating_of(result.score)
    result.formula = FORMULA
    if hasattr(result, "scan_id"):
        result.id = result.scan_id
    if hasattr(result, "score_details"):
        result.score_details = ScoreDetails(
            score=result.score,
            label=result.rating,
            severity_counts=SeverityCounts(
                critical=result.counts.Critical,
                high=result.counts.High,
                medium=result.counts.Medium,
                low=result.counts.Low,
            )
        )

