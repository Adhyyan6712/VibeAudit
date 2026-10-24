"""Pydantic data models for VibeAudit."""
from typing import List, Optional, Dict, Any, Literal
from pydantic import BaseModel, Field

class FixModel(BaseModel):
    before: str
    after: str
    steps: List[str] = Field(default_factory=list)

class Finding(BaseModel):
    id: str
    check_id: str
    title: str
    file: str
    line: int
    evidence: str
    severity: int = Field(ge=1, le=5)
    confidence: Literal["low", "medium", "high"] = "high"
    risk: float
    band: Literal["Critical", "High", "Medium", "Low"]
    verdict: Literal["confirmed", "needs_validation", "rejected"] = "confirmed"
    verdict_reason: str = ""
    explanation: str = ""
    fix: FixModel
    owasp_category: str
    human_review: bool = True

class Endpoint(BaseModel):
    method: str
    path: str
    handler: str
    file: str
    line: int
    auth_status: Literal["protected", "unprotected", "unknown"]
    ownership_check: Literal["yes", "no", "n/a"] = "n/a"
    notes: str = ""

class SeverityCount(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0

class ScanScore(BaseModel):
    score: int
    label: str # "Poor" | "Needs Work" | "Fair" | "Good" | "Excellent"
    total_penalty: float
    formula_summary: str
    severity_counts: SeverityCount

class ScanResult(BaseModel):
    id: str
    project_name: str
    timestamp: str
    score_details: ScanScore
    findings: List[Finding]
    endpoints: List[Endpoint]
    files_scanned: int
    consent_given: bool = True

class RescanResult(BaseModel):
    old_scan_id: str
    new_scan_id: str
    old_score: int
    new_score: int
    score_delta: int
    resolved_findings: List[Finding]
    remaining_findings: List[Finding]
    new_findings: List[Finding]
    comparison_summary: str

class LiveCheckRequest(BaseModel):
    target_url: str = "http://127.0.0.1:5000"

class LiveCheckFinding(BaseModel):
    header_name: str
    status: Literal["missing", "insecure", "present"]
    recommendation: str
