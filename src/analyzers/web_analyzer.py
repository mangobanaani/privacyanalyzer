"""Web analyzer for website privacy scanning."""

import uuid
from typing import Any, List
from urllib.parse import urlparse

from src.analyzers.base import AnalyzerBase
from src.models import Finding, ScanResult, PIIType, Severity
from src.detectors import PIIDetector, CustomPIIPatterns
from src.processors.web_processor import WebProcessor
from src.llm import LLMAnalyzer
from src.utils import get_logger

logger = get_logger(__name__)


class WebAnalyzer(AnalyzerBase):
    """Analyze websites for PII and privacy issues."""

    def __init__(self, config: Any = None, use_llm: bool = False):
        """
        Initialize web analyzer.

        Args:
            config: Optional configuration
            use_llm: Enable LLM-powered analysis
        """
        super().__init__(config)
        self.pii_detector = PIIDetector()
        self.web_processor = WebProcessor(
            follow_links=True, max_pages=10  # Configurable
        )
        # Convert string to boolean if needed (for CLI compatibility)
        if isinstance(use_llm, str):
            use_llm = use_llm.lower() in ('true', '1', 'yes')
        self.use_llm = use_llm
        self.llm_analyzer = LLMAnalyzer() if use_llm else None

    def validate_source(self, source: Any) -> bool:
        """
        Validate that the URL is accessible.

        Args:
            source: URL to validate

        Returns:
            True if URL is valid and accessible
        """
        try:
            parsed = urlparse(str(source))
            return parsed.scheme in ["http", "https"] and bool(parsed.netloc)
        except Exception as e:
            logger.error(f"URL validation failed: {e}")
            return False

    async def analyze(self, source: Any) -> ScanResult:
        """
        Analyze a website for PII and privacy issues.

        Args:
            source: Website URL

        Returns:
            ScanResult with all findings
        """
        if not self.validate_source(source):
            raise ValueError(f"Invalid URL: {source}")

        url = str(source)
        scan_result = self._create_scan_result(url, "web")

        try:
            logger.info(f"Starting web analysis: {url}")

            # Extract content from website
            pages = self.web_processor.process(url)

            logger.info(f"Extracted {len(pages)} pages from website")

            # Analyze each page
            for text, metadata in pages:
                # PII detection in content
                findings = await self._analyze_text(text, metadata)
                for finding in findings:
                    scan_result.add_finding(finding)

                # Cookie analysis
                cookie_findings = self._analyze_cookies(metadata.get("cookies", {}))
                for finding in cookie_findings:
                    scan_result.add_finding(finding)

                # Form analysis
                form_findings = self._analyze_forms(
                    metadata.get("forms", []), metadata["source"]
                )
                for finding in form_findings:
                    scan_result.add_finding(finding)

                # Security analysis
                security_findings = self._analyze_security(
                    metadata.get("security", {}), metadata["source"]
                )
                for finding in security_findings:
                    scan_result.add_finding(finding)

                # Privacy policy check
                if not metadata.get("has_privacy_policy", False):
                    scan_result.add_finding(
                        self._create_privacy_policy_finding(metadata["source"])
                    )

            scan_result.complete()
            logger.info(
                f"Web analysis complete: {scan_result.total_findings} findings in {scan_result.duration_seconds:.2f}s"
            )

        except Exception as e:
            logger.error(f"Web analysis failed: {e}")
            scan_result.fail(str(e))
            raise

        return scan_result

    async def _analyze_text(self, text: str, metadata: dict) -> List[Finding]:
        """
        Analyze page text for PII.

        Args:
            text: Extracted text
            metadata: Page metadata

        Returns:
            List of findings
        """
        findings = []

        if not text or not text.strip():
            return findings

        # Detect PII
        detections = self.pii_detector.detect(text)
        custom_detections = CustomPIIPatterns.detect_all(text)
        detections.extend(custom_detections)

        # Create findings
        for detection in detections:
            finding = self._create_finding(detection, text, metadata)

            # Enhance with LLM if enabled
            if self.use_llm and self.llm_analyzer:
                try:
                    finding = await self.llm_analyzer.enhance_finding(finding, text[:500])
                except Exception as e:
                    logger.warning(f"LLM enhancement failed: {e}")

            findings.append(finding)

        return findings

    def _analyze_cookies(self, cookies: dict) -> List[Finding]:
        """
        Analyze cookies for privacy issues.

        Args:
            cookies: Cookie analysis from web processor

        Returns:
            List of findings
        """
        findings = []

        if not cookies.get("has_cookies"):
            return findings

        # Check for tracking cookies
        for cookie in cookies.get("types", []):
            if cookie["type"] in ["analytics", "advertising"]:
                severity = Severity.MEDIUM
                if cookie["type"] == "advertising":
                    severity = Severity.HIGH

                finding = Finding(
                    id=str(uuid.uuid4()),
                    source="Website Cookies",
                    location=f"Cookie: {cookie['name']}",
                    pii_type=PIIType.OTHER,
                    content="[REDACTED]",
                    context=f"{cookie['type']} cookie detected",
                    confidence=0.9,
                    severity=severity,
                    gdpr_articles=["Art. 5", "Art. 6", "Art. 7"],
                    recommendation=f"Ensure user consent for {cookie['type']} cookies. Implement cookie banner with opt-in. Document legitimate interest basis if applicable.",
                )
                findings.append(finding)

            # Check security flags
            if not cookie.get("secure"):
                finding = Finding(
                    id=str(uuid.uuid4()),
                    source="Website Cookies",
                    location=f"Cookie: {cookie['name']}",
                    pii_type=PIIType.OTHER,
                    content="[REDACTED]",
                    context="Cookie missing Secure flag",
                    confidence=1.0,
                    severity=Severity.MEDIUM,
                    gdpr_articles=["Art. 32"],
                    recommendation="Set Secure flag on all cookies to ensure transmission only over HTTPS.",
                )
                findings.append(finding)

        return findings

    def _analyze_forms(self, forms: List[dict], page_url: str) -> List[Finding]:
        """
        Analyze forms for PII collection.

        Args:
            forms: Form analysis from web processor
            page_url: Page URL

        Returns:
            List of findings
        """
        findings = []

        for form in forms:
            if not form.get("collects_pii"):
                continue

            # Check if form uses HTTPS
            is_secure = page_url.startswith("https://")
            action = form.get("action", "")
            is_action_secure = action.startswith("https://") if action else is_secure

            if not is_action_secure:
                finding = Finding(
                    id=str(uuid.uuid4()),
                    source="Website Form",
                    location=page_url,
                    pii_type=PIIType.OTHER,
                    content="[REDACTED]",
                    context=f"Form collecting PII without HTTPS: {action}",
                    confidence=1.0,
                    severity=Severity.CRITICAL,
                    gdpr_articles=["Art. 32"],
                    recommendation="Use HTTPS for all forms collecting personal data. Configure SSL/TLS certificate.",
                )
                findings.append(finding)

            # Check for PII fields
            pii_fields = [inp for inp in form.get("inputs", []) if inp.get("may_collect_pii")]

            if pii_fields:
                finding = Finding(
                    id=str(uuid.uuid4()),
                    source="Website Form",
                    location=page_url,
                    pii_type=PIIType.OTHER,
                    content="[REDACTED]",
                    context=f"Form collecting PII: {len(pii_fields)} fields",
                    confidence=0.8,
                    severity=Severity.HIGH,
                    gdpr_articles=["Art. 5", "Art. 6", "Art. 13"],
                    recommendation="Ensure clear consent mechanism. Provide privacy notice. Implement data minimization. Document lawful basis for processing.",
                )
                findings.append(finding)

        return findings

    def _analyze_security(self, security: dict, page_url: str) -> List[Finding]:
        """
        Analyze security headers and HTTPS.

        Args:
            security: Security analysis from web processor
            page_url: Page URL

        Returns:
            List of findings
        """
        findings = []

        # Check HTTPS
        if not security.get("uses_https"):
            finding = Finding(
                id=str(uuid.uuid4()),
                source="Website Security",
                location=page_url,
                pii_type=PIIType.OTHER,
                content="[REDACTED]",
                context="Website not using HTTPS",
                confidence=1.0,
                severity=Severity.CRITICAL,
                gdpr_articles=["Art. 32"],
                recommendation="Implement HTTPS with valid SSL/TLS certificate. Redirect HTTP to HTTPS.",
            )
            findings.append(finding)

        # Check security headers
        headers = security.get("headers", {})
        if not headers.get("strict_transport_security"):
            finding = Finding(
                id=str(uuid.uuid4()),
                source="Website Security",
                location=page_url,
                pii_type=PIIType.OTHER,
                content="[REDACTED]",
                context="Missing Strict-Transport-Security header",
                confidence=1.0,
                severity=Severity.MEDIUM,
                gdpr_articles=["Art. 32"],
                recommendation="Add HSTS header to enforce HTTPS. Set max-age to at least 31536000 seconds.",
            )
            findings.append(finding)

        if not headers.get("content_security_policy"):
            finding = Finding(
                id=str(uuid.uuid4()),
                source="Website Security",
                location=page_url,
                pii_type=PIIType.OTHER,
                content="[REDACTED]",
                context="Missing Content-Security-Policy header",
                confidence=1.0,
                severity=Severity.LOW,
                gdpr_articles=["Art. 32"],
                recommendation="Implement CSP header to prevent XSS attacks and data exfiltration.",
            )
            findings.append(finding)

        return findings

    def _create_privacy_policy_finding(self, page_url: str) -> Finding:
        """
        Create finding for missing privacy policy.

        Args:
            page_url: Page URL

        Returns:
            Finding
        """
        return Finding(
            id=str(uuid.uuid4()),
            source="Website Privacy",
            location=page_url,
            pii_type=PIIType.OTHER,
            content="[REDACTED]",
            context="No privacy policy link found",
            confidence=0.7,
            severity=Severity.HIGH,
            gdpr_articles=["Art. 12", "Art. 13"],
            recommendation="Add privacy policy link in footer. Ensure policy covers all required GDPR disclosures.",
        )

    def _create_finding(self, detection: dict, text: str, metadata: dict) -> Finding:
        """
        Create finding from detection.

        Args:
            detection: Detection dictionary
            text: Full text
            metadata: Page metadata

        Returns:
            Finding
        """
        start = max(0, detection["start"] - 50)
        end = min(len(text), detection["end"] + 50)
        context = text[start:end].replace("\n", " ")

        pii_type = detection.get("type", PIIType.OTHER)
        severity = self._assess_severity(pii_type, detection["confidence"])
        gdpr_articles = self._map_gdpr_articles(pii_type)
        recommendation = self._get_recommendation(pii_type, severity, "web")

        return Finding(
            id=str(uuid.uuid4()),
            source=metadata.get("source", "Website"),
            location=metadata.get("title", "Page"),
            pii_type=pii_type,
            content="[REDACTED]",
            context=context,
            confidence=detection["confidence"],
            severity=severity,
            gdpr_articles=gdpr_articles,
            recommendation=recommendation,
        )

    def _assess_severity(self, pii_type: PIIType, confidence: float) -> Severity:
        """Assess severity based on PII type and confidence."""
        severity_map = {
            PIIType.SSN: Severity.CRITICAL,
            PIIType.CREDIT_CARD: Severity.CRITICAL,
            PIIType.PASSPORT: Severity.CRITICAL,
            PIIType.EMAIL: Severity.HIGH,
            PIIType.PHONE_NUMBER: Severity.HIGH,
            PIIType.IBAN: Severity.HIGH,
            PIIType.PERSON: Severity.MEDIUM,
            PIIType.LOCATION: Severity.MEDIUM,
            PIIType.IP_ADDRESS: Severity.MEDIUM,
        }
        return severity_map.get(pii_type, Severity.MEDIUM)

    def _map_gdpr_articles(self, pii_type: PIIType) -> List[str]:
        """Map PII type to GDPR articles."""
        if pii_type in [PIIType.SSN, PIIType.MEDICAL_LICENSE]:
            return ["Art. 5", "Art. 9", "Art. 32"]
        elif pii_type in [PIIType.CREDIT_CARD, PIIType.IBAN]:
            return ["Art. 5", "Art. 6", "Art. 32"]
        else:
            return ["Art. 5", "Art. 6"]

    def _get_recommendation(self, pii_type: PIIType, severity: Severity, context: str) -> str:
        """Generate recommendation."""
        recommendations = {
            PIIType.EMAIL: "Remove exposed email addresses. Implement email obfuscation or contact forms.",
            PIIType.PHONE_NUMBER: "Remove phone numbers or use click-to-call functionality.",
            PIIType.SSN: "CRITICAL: Remove all SSN from public web pages immediately.",
            PIIType.CREDIT_CARD: "CRITICAL: Remove all payment card data. Never display on web pages.",
        }
        return recommendations.get(
            pii_type, "Review necessity of displaying this data publicly. Consider removal or access control."
        )
