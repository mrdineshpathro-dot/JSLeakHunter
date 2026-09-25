from dataclasses import dataclass, field, asdict
from typing import Any
import hashlib

@dataclass
class Finding:
    secret_type: str
    category: str
    severity: str
    confidence: int
    source: str
    line: int
    value: str
    context: str = ""
    entropy: float = 0.0
    detector: str = ""
    occurrences: int = 1
    fingerprint: str = field(init=False)
    def __post_init__(self):
        self.fingerprint = hashlib.sha256(self.value.encode()).hexdigest()
    def masked(self, show=False, redact=False):
        if show and not redact: return self.value
        if len(self.value) <= 8: return "*" * len(self.value)
        return self.value[:4] + "*" * min(18, len(self.value)-8) + self.value[-4:]
    def to_dict(self, show=False, redact=False):
        d = asdict(self); d["value"] = self.masked(show, redact); return d

@dataclass
class ScanSummary:
    targets: int = 0; files: int = 0; urls: int = 0; findings: int = 0
    elapsed: float = 0.0
    severities: dict[str,int] = field(default_factory=dict)
