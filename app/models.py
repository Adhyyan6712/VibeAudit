"""Pydantic data models shared by the whole backend."""
from typing import Literal, Optional
from pydantic import BaseModel, Field

Confidence = Literal["low", "medium", "high"]
Verdict = Literal["confirmed", "needs_validation", "rejected"]
Band = Literal["Critical", "High", "Medium", "Low"]
AuthStatus = Literal["protected", "unprotected", "unknown"]


class Fix(BaseModel):
    before: str = ""
    after: str = ""
    steps: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    id: str = ""
    check_id: str
    title: str
    file: str
    line: int
    evidence: str                       # always masked
    severity: int = Field(ge=1, le=5)
    confidence: Confidence
    risk: float = 0
    band: Band = "Low"
    verdict: Verdict = "confirmed"
    verdict_reason: str = ""
    explanation: str = ""
    fix: Fix = Field(default_factory=Fix)
    owasp_category: str = ""
    human_review: bool = True           # every finding needs a human look
    reviewed: bool = False
    user_override: bool = False
    ai_enriched: bool = False
    source: Literal["static", "live"] = "static"
    fingerprint: str = ""
    context: str = Field(default="", exclude=True)   # masked code context, never sent to clients


class Endpoint(BaseModel):
    method: str
    path: str
    handler: str
    file: str
    line: int
    auth_status: AuthStatus
    ownership_check: Literal["yes", "no", "n/a"] = "n/a"
    public: bool = False
    notes: str = ""


class Counts(BaseModel):
    Critical: int = 0
    High: int = 0
    Medium: int = 0
    Low: int = 0


class SeverityCounts(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class ScoreDetails(BaseModel):
    score: int = 100
    label: str = "Good"
    severity_counts: SeverityCounts = Field(default_factory=SeverityCounts)


class Comparison(BaseModel):
    previous_scan_id: str
    old_score: int
    new_score: int
    delta: int
    resolved: list[Finding]
    new: list[Finding]
    unchanged_count: int


class ScanResult(BaseModel):
    scan_id: str
    id: str = ""
    project_name: str
    status: Literal["enriching", "complete"] = "complete"
    created_at: str
    files_scanned: int
    score: int = 100
    rating: str = "Good"
    counts: Counts = Field(default_factory=Counts)
    score_details: Optional[ScoreDetails] = None
    findings: list[Finding] = Field(default_factory=list)
    endpoints: list[Endpoint] = Field(default_factory=list)
    formula: str = ""
    notes: list[str] = Field(default_factory=list)
    live_checked: Optional[str] = None
    ai_status: str = "disabled"
    comparison: Optional[Comparison] = None



class PasteScanRequest(BaseModel):
    project_name: str = "pasted-project"
    consent: bool = False
    files: dict[str, str]
    use_gemini: bool = True
    live_url: Optional[str] = None


class FindingPatch(BaseModel):
    reviewed: Optional[bool] = None
    verdict: Optional[Verdict] = None
    verdict_reason: Optional[str] = Field(default=None, max_length=300)
