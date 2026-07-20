"""Core data models — same dataclass pattern used throughout this portfolio."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    module: str
    title: str
    severity: Severity
    target: str
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    reference: str = ""
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "module": self.module, "title": self.title, "severity": self.severity.value,
            "target": self.target, "description": self.description, "evidence": self.evidence,
            "remediation": self.remediation, "reference": self.reference, "extra": self.extra,
        }
