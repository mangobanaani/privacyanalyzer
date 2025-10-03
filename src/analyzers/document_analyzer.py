"""Document analyzer for PII detection in files."""

import os
from pathlib import Path
from typing import Any, List
import uuid

from src.analyzers.base import AnalyzerBase
from src.models import Finding, ScanResult, PIIType, Severity
from src.detectors import PIIDetector, CustomPIIPatterns
from src.processors import DocumentProcessor
from src.llm import LLMAnalyzer
from src.utils import get_logger

logger = get_logger(__name__)


class DocumentAnalyzer(AnalyzerBase):
    """Analyze documents for PII and privacy issues."""

    def __init__(self, config: Any = None, use_llm: bool = False):
        """
        Initialize document analyzer.

        Args:
            config: Optional analyzer configuration
            use_llm: Enable LLM-powered analysis (requires API key)
        """
        super().__init__(config)
        self.pii_detector = PIIDetector()
        self.document_processor = DocumentProcessor(enable_ocr=True)
        # Convert string to boolean if needed (for CLI compatibility)
        if isinstance(use_llm, str):
            use_llm = use_llm.lower() in ('true', '1', 'yes')
        self.use_llm = use_llm
        self.llm_analyzer = LLMAnalyzer() if use_llm else None

    def validate_source(self, source: Any) -> bool:
        """
        Validate that the file exists and is readable.

        Args:
            source: File path to validate

        Returns:
            True if file is valid and readable
        """
        try:
            path = Path(source)
            return path.exists() and path.is_file() and os.access(source, os.R_OK)
        except Exception as e:
            logger.error(f"Source validation failed: {e}")
            return False

    async def analyze(self, source: Any) -> ScanResult:
        """
        Analyze a document for PII.

        Args:
            source: Path to document file

        Returns:
            ScanResult with all findings
        """
        if not self.validate_source(source):
            raise ValueError(f"Invalid or inaccessible source: {source}")

        file_path = str(source)
        scan_result = self._create_scan_result(file_path, "document")

        try:
            logger.info(f"Starting document analysis: {file_path}")

            # Extract text from document
            text_sections = self.document_processor.process(file_path)

            logger.info(f"Extracted {len(text_sections)} sections from document")

            # Analyze each section
            for text, metadata in text_sections:
                findings = await self._analyze_text(text, metadata, file_path)
                for finding in findings:
                    scan_result.add_finding(finding)

            scan_result.complete()
            logger.info(
                f"Document analysis complete: {scan_result.total_findings} findings in {scan_result.duration_seconds:.2f}s"
            )

        except Exception as e:
            logger.error(f"Document analysis failed: {e}")
            scan_result.fail(str(e))
            raise

        return scan_result

    async def _analyze_text(
        self, text: str, metadata: dict, source_file: str
    ) -> List[Finding]:
        """
        Analyze text content for PII.

        Args:
            text: Text content to analyze
            metadata: Metadata about the text (page number, etc.)
            source_file: Source file path

        Returns:
            List of findings
        """
        findings = []

        if not text or not text.strip():
            return findings

        # Detect PII using Presidio
        detections = self.pii_detector.detect(text)

        # Also run custom patterns
        custom_detections = CustomPIIPatterns.detect_all(text)
        detections.extend(custom_detections)

        # Create findings
        for detection in detections:
            finding = self._create_finding(detection, text, metadata, source_file)

            # Enhance with LLM if enabled
            if self.use_llm and self.llm_analyzer:
                try:
                    finding = await self.llm_analyzer.enhance_finding(finding, text[:500])
                except Exception as e:
                    logger.warning(f"LLM enhancement failed for finding: {e}")

            findings.append(finding)

        return findings

    def _create_finding(
        self, detection: dict, text: str, metadata: dict, source_file: str
    ) -> Finding:
        """
        Create a Finding object from a detection.

        Args:
            detection: Detection dictionary from PII detector
            text: Full text content
            metadata: Document metadata
            source_file: Source file path

        Returns:
            Finding object
        """
        # Extract context around the detection
        start = max(0, detection["start"] - 50)
        end = min(len(text), detection["end"] + 50)
        context = text[start:end].replace("\n", " ")

        # Determine location
        page_num = metadata.get("page_number")
        location = f"Page {page_num}" if page_num else "Document"

        # Map PII type
        pii_type = detection.get("type", PIIType.OTHER)

        # Assess severity
        severity = self._assess_severity(pii_type, detection["confidence"])

        # Map GDPR articles
        gdpr_articles = self._map_gdpr_articles(pii_type)

        # Generate recommendation
        recommendation = self._get_recommendation(pii_type, severity)

        finding = Finding(
            id=str(uuid.uuid4()),
            source=os.path.basename(source_file),
            location=location,
            pii_type=pii_type,
            content="[REDACTED]",  # Never log actual PII
            context=context,
            confidence=detection["confidence"],
            severity=severity,
            gdpr_articles=gdpr_articles,
            recommendation=recommendation,
            page_number=page_num,
        )

        return finding

    def _assess_severity(self, pii_type: PIIType, confidence: float) -> Severity:
        """
        Assess severity based on PII type and confidence.

        Args:
            pii_type: Type of PII
            confidence: Detection confidence

        Returns:
            Severity level
        """
        # Base severity by PII type
        severity_map = {
            PIIType.SSN: Severity.CRITICAL,
            PIIType.CREDIT_CARD: Severity.CRITICAL,
            PIIType.PASSPORT: Severity.CRITICAL,
            PIIType.MEDICAL_LICENSE: Severity.HIGH,
            PIIType.DRIVER_LICENSE: Severity.HIGH,
            PIIType.EMAIL: Severity.HIGH,
            PIIType.PHONE_NUMBER: Severity.HIGH,
            PIIType.IBAN: Severity.HIGH,
            PIIType.DATE_OF_BIRTH: Severity.MEDIUM,
            PIIType.LOCATION: Severity.MEDIUM,
            PIIType.PERSON: Severity.MEDIUM,
            PIIType.IP_ADDRESS: Severity.MEDIUM,
            PIIType.ORGANIZATION: Severity.LOW,
            PIIType.URL: Severity.LOW,
            PIIType.OTHER: Severity.LOW,
        }

        base_severity = severity_map.get(pii_type, Severity.MEDIUM)

        # Downgrade if low confidence
        if confidence < 0.7 and base_severity == Severity.CRITICAL:
            return Severity.HIGH
        elif confidence < 0.6 and base_severity == Severity.HIGH:
            return Severity.MEDIUM

        return base_severity

    def _map_gdpr_articles(self, pii_type: PIIType) -> List[str]:
        """
        Map PII type to relevant GDPR articles.

        Args:
            pii_type: Type of PII

        Returns:
            List of relevant GDPR articles
        """
        # Special category data (Art. 9)
        special_categories = [
            PIIType.SSN,
            PIIType.MEDICAL_LICENSE,
            PIIType.DATE_OF_BIRTH,
        ]

        # Financial data
        financial_data = [PIIType.CREDIT_CARD, PIIType.IBAN]

        articles = ["Art. 5"]  # Always applies (principles)

        if pii_type in special_categories:
            articles.extend(["Art. 9", "Art. 32"])  # Special categories + security
        elif pii_type in financial_data:
            articles.extend(["Art. 6", "Art. 32"])  # Lawfulness + security
        else:
            articles.append("Art. 6")  # Lawfulness of processing

        return articles

    def _get_recommendation(self, pii_type: PIIType, severity: Severity) -> str:
        """
        Generate remediation recommendation.

        Args:
            pii_type: Type of PII
            severity: Severity level

        Returns:
            Recommendation text
        """
        recommendations = {
            PIIType.SSN: "Immediately encrypt or remove SSN. Consider tokenization for storage. Implement strict access controls.",
            PIIType.CREDIT_CARD: "Remove credit card data or ensure PCI-DSS compliance. Use tokenization. Never store CVV.",
            PIIType.PASSPORT: "Encrypt passport numbers. Implement multi-factor authentication for access. Consider tokenization.",
            PIIType.EMAIL: "Verify legitimate business need. Implement encryption at rest. Provide opt-out mechanism.",
            PIIType.PHONE_NUMBER: "Verify consent for collection. Implement encryption. Provide opt-out mechanism.",
            PIIType.IBAN: "Encrypt bank account numbers. Implement access logging. Ensure PSD2 compliance if applicable.",
            PIIType.PERSON: "Verify data minimization principles. Document lawful basis for processing.",
            PIIType.LOCATION: "Implement purpose limitation. Allow users to delete location history. Document retention period.",
            PIIType.IP_ADDRESS: "Consider anonymization after processing. Document retention period and purpose.",
        }

        base_rec = recommendations.get(
            pii_type,
            "Review data processing necessity. Implement appropriate technical and organizational measures.",
        )

        if severity == Severity.CRITICAL:
            return f"CRITICAL: {base_rec} Immediate action required."
        elif severity == Severity.HIGH:
            return f"HIGH PRIORITY: {base_rec}"
        else:
            return base_rec
