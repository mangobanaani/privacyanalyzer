"""Data models for privacy findings."""

from datetime import datetime
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field, ConfigDict


class PIIType(str, Enum):
    """Types of personally identifiable information."""

    # Generic identifiers
    EMAIL = "EMAIL"
    PHONE_NUMBER = "PHONE_NUMBER"
    PERSON = "PERSON"
    LOCATION = "LOCATION"
    ORGANIZATION = "ORGANIZATION"
    DATE_OF_BIRTH = "DATE_OF_BIRTH"
    IP_ADDRESS = "IP_ADDRESS"
    URL = "URL"

    # US identifiers
    SSN = "SSN"

    # Nordic country identifiers
    FINNISH_SSN = "FINNISH_SSN"
    SWEDISH_SSN = "SWEDISH_SSN"
    NORWEGIAN_SSN = "NORWEGIAN_SSN"
    DANISH_CPR = "DANISH_CPR"

    # EU/UK identifiers
    UK_NINO = "UK_NINO"
    EU_VAT = "EU_VAT"

    # Financial
    CREDIT_CARD = "CREDIT_CARD"
    IBAN = "IBAN"
    BIC_SWIFT = "BIC_SWIFT"

    # Documents
    PASSPORT = "PASSPORT"
    DRIVER_LICENSE = "DRIVER_LICENSE"
    MEDICAL_LICENSE = "MEDICAL_LICENSE"

    # Crypto
    CRYPTO_ADDRESS = "CRYPTO_ADDRESS"

    # Other
    OTHER = "OTHER"


class Severity(str, Enum):
    """Severity levels for findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class GDPRArticle(str, Enum):
    """Relevant GDPR articles."""

    ART_5 = "Art. 5 - Principles relating to processing"
    ART_6 = "Art. 6 - Lawfulness of processing"
    ART_7 = "Art. 7 - Conditions for consent"
    ART_9 = "Art. 9 - Processing of special categories"
    ART_12 = "Art. 12 - Transparent information"
    ART_13 = "Art. 13 - Information to be provided"
    ART_15 = "Art. 15 - Right of access"
    ART_16 = "Art. 16 - Right to rectification"
    ART_17 = "Art. 17 - Right to erasure"
    ART_25 = "Art. 25 - Data protection by design"
    ART_32 = "Art. 32 - Security of processing"
    ART_33 = "Art. 33 - Notification of breach"
    ART_35 = "Art. 35 - Data protection impact assessment"


class Finding(BaseModel):
    """Represents a single privacy finding."""

    model_config = ConfigDict(use_enum_values=True)

    id: str = Field(..., description="Unique identifier for the finding")
    source: str = Field(..., description="Source of the data (file, database, URL)")
    location: str = Field(..., description="Specific location within source")
    pii_type: PIIType = Field(..., description="Type of PII detected")

    # Content (redacted in production)
    content: str = Field("[REDACTED]", description="Detected content (redacted)")
    context: str = Field(..., description="Surrounding context")

    # Scoring
    confidence: float = Field(..., ge=0.0, le=1.0, description="Detection confidence")
    severity: Severity = Field(..., description="Severity level")

    # GDPR
    gdpr_articles: List[str] = Field(default_factory=list, description="Violated GDPR articles")
    gdpr_reasoning: Optional[str] = Field(None, description="GDPR violation reasoning")

    # Recommendations
    recommendation: str = Field(..., description="Remediation recommendation")
    anonymization_strategy: Optional[str] = Field(
        None, description="Suggested anonymization approach"
    )

    # Metadata
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    analyzer_version: str = Field("1.0.0", description="Analyzer version")

    # Additional context
    line_number: Optional[int] = Field(None, description="Line number if applicable")
    column_number: Optional[int] = Field(None, description="Column number if applicable")
    page_number: Optional[int] = Field(None, description="Page number if applicable")

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return self.model_dump()

    def redact(self) -> "Finding":
        """Return a copy with content redacted."""
        data = self.model_dump()
        data["content"] = "[REDACTED]"
        return Finding(**data)


class ScanResult(BaseModel):
    """Result of a complete scan operation."""

    model_config = ConfigDict(use_enum_values=True)

    scan_id: str = Field(..., description="Unique scan identifier")
    source: str = Field(..., description="Scanned source")
    source_type: str = Field(..., description="Type of source (document, database, web)")

    # Results
    findings: List[Finding] = Field(default_factory=list)
    total_findings: int = Field(0)

    # Statistics
    findings_by_severity: dict = Field(default_factory=dict)
    findings_by_type: dict = Field(default_factory=dict)

    # Timing
    start_time: datetime = Field(default_factory=datetime.utcnow)
    end_time: Optional[datetime] = None
    duration_seconds: Optional[float] = None

    # Status
    status: str = Field("in_progress", description="Scan status")
    error_message: Optional[str] = None

    def add_finding(self, finding: Finding) -> None:
        """Add a finding and update statistics."""
        self.findings.append(finding)
        self.total_findings = len(self.findings)

        # Update severity counts
        severity = finding.severity
        self.findings_by_severity[severity] = self.findings_by_severity.get(severity, 0) + 1

        # Update type counts
        pii_type = finding.pii_type
        self.findings_by_type[pii_type] = self.findings_by_type.get(pii_type, 0) + 1

    def complete(self) -> None:
        """Mark scan as completed."""
        self.end_time = datetime.utcnow()
        self.duration_seconds = (self.end_time - self.start_time).total_seconds()
        self.status = "completed"

    def fail(self, error: str) -> None:
        """Mark scan as failed."""
        self.end_time = datetime.utcnow()
        self.duration_seconds = (self.end_time - self.start_time).total_seconds()
        self.status = "failed"
        self.error_message = error
