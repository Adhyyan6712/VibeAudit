"""Base classes for VibeAudit static rule engine."""
from typing import NamedTuple, List, Optional, Dict, Any

class RawMatch(NamedTuple):
    file: str
    line: int
    snippet: str
    context: str # ~5 lines around the line for AI context
    confidence: str # "low" | "medium" | "high"
    title: Optional[str] = None
    custom_verdict: Optional[str] = None # "confirmed" | "needs_validation" | "rejected"
    custom_verdict_reason: Optional[str] = None

class BaseCheck:
    id: str = "C0"
    title: str = "Base Check"
    severity: int = 3
    owasp_category: str = "A00 Unknown"

    def detect(self, files: Dict[str, str]) -> List[RawMatch]:
        """Runs check across all files and returns raw matches."""
        raise NotImplementedError

    def get_static_fallback(self, match: RawMatch) -> Dict[str, Any]:
        """Provides static explanation and before/after remediation when AI is unavailable."""
        raise NotImplementedError
