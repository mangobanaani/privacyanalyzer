"""Anonymization engine for PII data."""

import hashlib
import re
from enum import Enum
from typing import Dict, List, Optional, Callable
from datetime import datetime

from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import RecognizerResult, OperatorConfig

from src.models import Finding, ScanResult
from src.utils import get_logger

logger = get_logger(__name__)


class AnonymizationStrategy(str, Enum):
    """Anonymization strategies."""

    REDACT = "redact"  # Replace with [REDACTED]
    MASK = "mask"  # Replace with ****
    HASH = "hash"  # One-way hash
    ENCRYPT = "encrypt"  # Reversible encryption (future)
    GENERALIZE = "generalize"  # Replace with category
    SUPPRESS = "suppress"  # Remove entirely
    SYNTHETIC = "synthetic"  # Replace with fake data


class AnonymizationEngine:
    """Engine for anonymizing PII in text and structured data."""

    def __init__(self, default_strategy: AnonymizationStrategy = AnonymizationStrategy.MASK):
        """
        Initialize anonymization engine.

        Args:
            default_strategy: Default anonymization strategy
        """
        self.default_strategy = default_strategy
        self.presidio_engine = AnonymizerEngine()

        # Strategy mappings for different PII types
        self.strategy_map: Dict[str, AnonymizationStrategy] = {
            "SSN": AnonymizationStrategy.HASH,
            "CREDIT_CARD": AnonymizationStrategy.HASH,
            "EMAIL": AnonymizationStrategy.MASK,
            "PHONE_NUMBER": AnonymizationStrategy.MASK,
            "PERSON": AnonymizationStrategy.GENERALIZE,
            "LOCATION": AnonymizationStrategy.GENERALIZE,
            "OTHER": AnonymizationStrategy.SUPPRESS,  # For passwords and other sensitive data
        }

    def anonymize_text(
        self,
        text: str,
        findings: List[Finding],
        strategy: Optional[AnonymizationStrategy] = None,
    ) -> str:
        """
        Anonymize PII in text based on findings.

        Args:
            text: Original text
            findings: List of PII findings
            strategy: Anonymization strategy (uses default if None)

        Returns:
            Anonymized text
        """
        if not findings:
            return text

        anonymized = text
        strategy = strategy or self.default_strategy

        # Sort findings by position (reverse to maintain positions)
        sorted_findings = sorted(
            findings, key=lambda f: f.location if hasattr(f, "position") else 0, reverse=True
        )

        for finding in sorted_findings:
            # Get strategy for this PII type
            pii_strategy = self.strategy_map.get(finding.pii_type, strategy)

            # Apply anonymization
            replacement = self._apply_strategy(finding.content, finding.pii_type, pii_strategy)

            # Replace in text
            anonymized = anonymized.replace(finding.content, replacement)

        return anonymized

    def anonymize_findings(
        self, scan_result: ScanResult, strategy: Optional[AnonymizationStrategy] = None
    ) -> ScanResult:
        """
        Anonymize all findings in a scan result.

        Args:
            scan_result: Scan result with findings
            strategy: Anonymization strategy

        Returns:
            New scan result with anonymized content
        """
        strategy = strategy or self.default_strategy

        anonymized_result = ScanResult(
            source=scan_result.source,
            source_type=scan_result.source_type,
            scan_id=f"{scan_result.scan_id}_anonymized",
        )

        for finding in scan_result.findings:
            anonymized_finding = Finding(
                id=finding.id,
                source=finding.source,
                location=finding.location,
                pii_type=finding.pii_type,
                content=self._apply_strategy(
                    finding.content, finding.pii_type, self.strategy_map.get(finding.pii_type, strategy)
                ),
                context=finding.context,
                confidence=finding.confidence,
                severity=finding.severity,
                gdpr_articles=finding.gdpr_articles,
                recommendation=finding.recommendation,
            )
            anonymized_result.add_finding(anonymized_finding)

        anonymized_result.complete()
        return anonymized_result

    def _apply_strategy(
        self, content: str, pii_type: str, strategy: AnonymizationStrategy
    ) -> str:
        """
        Apply anonymization strategy to content.

        Args:
            content: Original content
            pii_type: Type of PII
            strategy: Strategy to apply

        Returns:
            Anonymized content
        """
        if strategy == AnonymizationStrategy.REDACT:
            return f"[REDACTED_{pii_type}]"

        elif strategy == AnonymizationStrategy.MASK:
            return self._mask_content(content, pii_type)

        elif strategy == AnonymizationStrategy.HASH:
            return self._hash_content(content)

        elif strategy == AnonymizationStrategy.GENERALIZE:
            return self._generalize_content(content, pii_type)

        elif strategy == AnonymizationStrategy.SUPPRESS:
            return ""

        elif strategy == AnonymizationStrategy.SYNTHETIC:
            return self._generate_synthetic(pii_type)

        else:
            return f"[{pii_type}]"

    def _mask_content(self, content: str, pii_type: str) -> str:
        """
        Mask content with asterisks.

        Args:
            content: Original content
            pii_type: Type of PII

        Returns:
            Masked content
        """
        if pii_type == "EMAIL":
            # Mask email: john.doe@example.com -> j***@example.com
            if "@" in content:
                parts = content.split("@")
                if len(parts[0]) > 1:
                    return f"{parts[0][0]}***@{parts[1]}"
            return "***@***.com"

        elif pii_type == "PHONE_NUMBER":
            # Mask phone: (555) 123-4567 -> (***) ***-4567
            digits = re.findall(r"\d", content)
            if len(digits) >= 4:
                last_four = "".join(digits[-4:])
                return f"***-***-{last_four}"
            return "***-***-****"

        elif pii_type == "CREDIT_CARD":
            # Mask credit card: show last 4 digits
            digits = re.findall(r"\d", content)
            if len(digits) >= 4:
                last_four = "".join(digits[-4:])
                return f"****-****-****-{last_four}"
            return "****-****-****-****"

        else:
            # Generic masking
            if len(content) <= 4:
                return "*" * len(content)
            return content[0] + "*" * (len(content) - 2) + content[-1]

    def _hash_content(self, content: str) -> str:
        """
        Hash content using SHA-256.

        Args:
            content: Original content

        Returns:
            Hashed content (first 16 chars of hash)
        """
        hashed = hashlib.sha256(content.encode()).hexdigest()
        return f"[HASH:{hashed[:16]}]"

    def _generalize_content(self, content: str, pii_type: str) -> str:
        """
        Generalize content to category.

        Args:
            content: Original content
            pii_type: Type of PII

        Returns:
            Generalized content
        """
        generalizations = {
            "PERSON": "[Person]",
            "LOCATION": "[Location]",
            "ORGANIZATION": "[Organization]",
            "DATE_OF_BIRTH": "[Date]",
            "AGE": "[Age Range: 25-35]",
        }

        return generalizations.get(pii_type, f"[{pii_type}]")

    def _generate_synthetic(self, pii_type: str) -> str:
        """
        Generate synthetic replacement data.

        Args:
            pii_type: Type of PII

        Returns:
            Synthetic data
        """
        synthetics = {
            "EMAIL": "user@example.com",
            "PHONE_NUMBER": "(555) 555-5555",
            "PERSON": "John Doe",
            "SSN": "000-00-0000",
            "CREDIT_CARD": "0000-0000-0000-0000",
            "LOCATION": "City, State",
        }

        return synthetics.get(pii_type, f"[SYNTHETIC_{pii_type}]")

    def anonymize_structured_data(
        self, data: Dict, pii_fields: List[str], strategy: Optional[AnonymizationStrategy] = None
    ) -> Dict:
        """
        Anonymize structured data (dictionaries).

        Args:
            data: Dictionary with data
            pii_fields: List of field names containing PII
            strategy: Anonymization strategy

        Returns:
            Anonymized dictionary
        """
        strategy = strategy or self.default_strategy
        anonymized = data.copy()

        for field in pii_fields:
            if field in anonymized and anonymized[field]:
                # Detect PII type from field name
                pii_type = self._infer_pii_type(field)
                anonymized[field] = self._apply_strategy(
                    str(anonymized[field]), pii_type, strategy
                )

        return anonymized

    def _infer_pii_type(self, field_name: str) -> str:
        """
        Infer PII type from field name.

        Args:
            field_name: Field name

        Returns:
            PII type
        """
        field_lower = field_name.lower()

        if "email" in field_lower:
            return "EMAIL"
        elif "phone" in field_lower:
            return "PHONE_NUMBER"
        elif "ssn" in field_lower or "social_security" in field_lower:
            return "SSN"
        elif "credit" in field_lower or "card" in field_lower:
            return "CREDIT_CARD"
        elif "name" in field_lower:
            return "PERSON"
        elif "address" in field_lower:
            return "LOCATION"
        elif "password" in field_lower:
            return "OTHER"
        else:
            return "OTHER"

    def create_anonymization_map(self, findings: List[Finding]) -> Dict[str, str]:
        """
        Create a mapping of original values to anonymized values.

        Args:
            findings: List of findings

        Returns:
            Mapping dictionary
        """
        anonymization_map = {}

        for finding in findings:
            strategy = self.strategy_map.get(finding.pii_type, self.default_strategy)
            anonymized = self._apply_strategy(finding.content, finding.pii_type, strategy)
            anonymization_map[finding.content] = anonymized

        return anonymization_map

    def get_strategy_for_pii_type(self, pii_type: str) -> AnonymizationStrategy:
        """
        Get recommended strategy for PII type.

        Args:
            pii_type: Type of PII

        Returns:
            Recommended anonymization strategy
        """
        return self.strategy_map.get(pii_type, self.default_strategy)

    def set_strategy_for_pii_type(
        self, pii_type: str, strategy: AnonymizationStrategy
    ) -> None:
        """
        Set anonymization strategy for a PII type.

        Args:
            pii_type: Type of PII
            strategy: Anonymization strategy to use
        """
        self.strategy_map[pii_type] = strategy
        logger.info(f"Set anonymization strategy for {pii_type}: {strategy}")
