"""Tests for GDPR compliance engine."""

import pytest
from src.detectors.gdpr_engine import GDPREngine, GDPRRule
from src.models import ScanResult, Finding, Severity


class TestGDPREngine:
    """Test GDPR compliance checking."""

    @pytest.fixture
    def engine(self):
        """Create a GDPR engine instance."""
        return GDPREngine()

    @pytest.fixture
    def sample_scan_result(self):
        """Create a sample scan result with findings."""
        result = ScanResult(
            source="test.txt",
            source_type="document",
            scan_id="test-123"
        )

        # Add finding with special category data
        finding1 = Finding(
            id="gdpr-finding-1",
            source="test.txt",
            location="line 1",
            pii_type="SSN",
            content="123-45-6789",
            context="SSN: 123-45-6789",
            confidence=0.95,
            severity=Severity.CRITICAL,
            recommendation="Hash SSN",
            gdpr_articles=["Art. 9"]
        )

        # Add finding with regular personal data
        finding2 = Finding(
            id="gdpr-finding-2",
            source="test.txt",
            location="line 2",
            pii_type="EMAIL",
            content="test@example.com",
            context="Email: test@example.com",
            confidence=0.90,
            severity=Severity.MEDIUM,
            recommendation="Encrypt email",
            gdpr_articles=["Art. 6"]
        )

        result.add_finding(finding1)
        result.add_finding(finding2)
        result.complete()

        return result

    def test_load_rules(self, engine: GDPREngine):
        """Test that GDPR rules are loaded."""
        assert len(engine.rules) > 0
        assert all(isinstance(rule, GDPRRule) for rule in engine.rules)

    def test_analyze_compliance(self, engine: GDPREngine, sample_scan_result: ScanResult):
        """Test compliance analysis."""
        compliance = engine.analyze_compliance(sample_scan_result)

        assert "compliance_score" in compliance
        assert "status" in compliance
        assert "total_violations" in compliance
        assert "violations" in compliance
        assert "recommendations" in compliance

        assert 0 <= compliance["compliance_score"] <= 100
        assert isinstance(compliance["total_violations"], int)

    def test_special_category_detection(self, engine: GDPREngine, sample_scan_result: ScanResult):
        """Test detection of special category data (Art. 9)."""
        compliance = engine.analyze_compliance(sample_scan_result)

        violations = compliance["violations"]

        # Should detect special category data violation
        special_category_violations = [
            v for v in violations
            if "Art. 9" in v.get("article", "")
        ]

        assert len(special_category_violations) > 0

    def test_compliance_scoring(self, engine: GDPREngine):
        """Test compliance score calculation."""
        # Result with no findings should score 100%
        clean_result = ScanResult(
            source="clean.txt",
            source_type="document",
            scan_id="clean-123"
        )
        clean_result.complete()

        compliance = engine.analyze_compliance(clean_result)
        assert compliance["compliance_score"] == 100.0

    def test_violation_severity(self, engine: GDPREngine, sample_scan_result: ScanResult):
        """Test that violations include severity levels."""
        compliance = engine.analyze_compliance(sample_scan_result)

        for violation in compliance["violations"]:
            assert "severity" in violation
            assert violation["severity"] in ["critical", "high", "medium", "low"]

    def test_recommendations_generated(self, engine: GDPREngine, sample_scan_result: ScanResult):
        """Test that recommendations are generated."""
        compliance = engine.analyze_compliance(sample_scan_result)

        assert len(compliance["recommendations"]) > 0
        assert all(isinstance(rec, str) for rec in compliance["recommendations"])

    def test_compliance_status(self, engine: GDPREngine):
        """Test compliance status classification."""
        # Clean result
        clean_result = ScanResult(
            source="clean.txt",
            source_type="document",
            scan_id="clean-123"
        )
        clean_result.complete()

        compliance = engine.analyze_compliance(clean_result)
        assert compliance["status"] == "compliant"

        # Result with critical findings
        critical_result = ScanResult(
            source="critical.txt",
            source_type="document",
            scan_id="critical-123"
        )

        for i in range(10):
            finding = Finding(
                id=f"critical-finding-{i}",
                source="critical.txt",
                location=f"line {i}",
                pii_type="SSN",
                content="XXX-XX-XXXX",
                context="SSN: XXX-XX-XXXX",
                confidence=0.95,
                severity=Severity.CRITICAL,
                recommendation="Hash SSN",
                gdpr_articles=["Art. 9"]
            )
            critical_result.add_finding(finding)

        critical_result.complete()

        compliance = engine.analyze_compliance(critical_result)
        assert compliance["status"] in ["non_compliant", "at_risk"]

    def test_article_coverage(self, engine: GDPREngine):
        """Test that major GDPR articles are covered."""
        rule_articles = set()
        for rule in engine.rules:
            if hasattr(rule, 'article'):
                rule_articles.add(rule.article)

        # Should cover key articles
        key_articles = ["Art. 5", "Art. 6", "Art. 9", "Art. 32"]
        covered = [article for article in key_articles if any(article in ra for ra in rule_articles)]

        assert len(covered) > 0
