"""Tests for anonymization engine."""

import pytest
from src.anonymizers import AnonymizationEngine, AnonymizationStrategy
from src.models import ScanResult, Finding, Severity


class TestAnonymizationEngine:
    """Test anonymization engine functionality."""

    @pytest.fixture
    def engine(self):
        """Create an anonymization engine instance."""
        return AnonymizationEngine(default_strategy=AnonymizationStrategy.MASK)

    @pytest.fixture
    def sample_findings(self):
        """Create sample findings for testing."""
        return [
            Finding(
                id="finding-1",
                source="test.txt",
                location="line 1",
                pii_type="EMAIL",
                content="john.doe@example.com",
                context="Email: john.doe@example.com",
                confidence=0.95,
                severity=Severity.MEDIUM,
                recommendation="Encrypt or mask email address"
            ),
            Finding(
                id="finding-2",
                source="test.txt",
                location="line 2",
                pii_type="PHONE_NUMBER",
                content="(555) 123-4567",
                context="Phone: (555) 123-4567",
                confidence=0.90,
                severity=Severity.MEDIUM,
                recommendation="Mask or encrypt phone number"
            ),
            Finding(
                id="finding-3",
                source="test.txt",
                location="line 3",
                pii_type="SSN",
                content="123-45-6789",
                context="SSN: 123-45-6789",
                confidence=0.98,
                severity=Severity.CRITICAL,
                recommendation="Hash or encrypt SSN immediately"
            ),
        ]

    def test_mask_email(self, engine: AnonymizationEngine):
        """Test email masking."""
        masked = engine._mask_content("john.doe@example.com", "EMAIL")

        assert masked.startswith("j***@")
        assert "@example.com" in masked

    def test_mask_phone(self, engine: AnonymizationEngine):
        """Test phone number masking."""
        masked = engine._mask_content("(555) 123-4567", "PHONE_NUMBER")

        assert "4567" in masked
        assert "***" in masked

    def test_mask_credit_card(self, engine: AnonymizationEngine):
        """Test credit card masking."""
        masked = engine._mask_content("4532-1234-5678-9010", "CREDIT_CARD")

        assert "9010" in masked
        assert "****" in masked

    def test_hash_content(self, engine: AnonymizationEngine):
        """Test content hashing."""
        hashed = engine._hash_content("sensitive data")

        assert hashed.startswith("[HASH:")
        assert len(hashed) > 10

    def test_redact_content(self, engine: AnonymizationEngine):
        """Test content redaction."""
        redacted = engine._apply_strategy(
            "john.doe@example.com",
            "EMAIL",
            AnonymizationStrategy.REDACT
        )

        assert redacted == "[REDACTED_EMAIL]"

    def test_generalize_content(self, engine: AnonymizationEngine):
        """Test content generalization."""
        generalized = engine._generalize_content("John Smith", "PERSON")

        assert generalized == "[Person]"

    def test_suppress_content(self, engine: AnonymizationEngine):
        """Test content suppression."""
        suppressed = engine._apply_strategy(
            "sensitive",
            "OTHER",
            AnonymizationStrategy.SUPPRESS
        )

        assert suppressed == ""

    def test_synthetic_email(self, engine: AnonymizationEngine):
        """Test synthetic email generation."""
        synthetic = engine._generate_synthetic("EMAIL")

        assert "@" in synthetic
        assert synthetic == "user@example.com"

    def test_anonymize_text(self, engine: AnonymizationEngine, sample_findings):
        """Test text anonymization."""
        original = "Contact john.doe@example.com or call (555) 123-4567"
        anonymized = engine.anonymize_text(original, sample_findings[:2])

        assert "john.doe@example.com" not in anonymized
        assert "(555) 123-4567" not in anonymized
        assert "***" in anonymized

    def test_anonymize_findings(self, engine: AnonymizationEngine):
        """Test anonymizing scan results."""
        result = ScanResult(
            source="test.txt",
            source_type="document",
            scan_id="test-123"
        )

        finding = Finding(
            id="finding-ssn",
            source="test.txt",
            location="line 1",
            pii_type="SSN",
            content="123-45-6789",
            context="SSN: 123-45-6789",
            confidence=0.95,
            severity=Severity.CRITICAL,
            recommendation="Hash or encrypt SSN immediately"
        )

        result.add_finding(finding)
        result.complete()

        anonymized_result = engine.anonymize_findings(result)

        assert anonymized_result.total_findings == 1
        assert "123-45-6789" not in anonymized_result.findings[0].content

    def test_anonymize_structured_data(self, engine: AnonymizationEngine):
        """Test structured data anonymization."""
        data = {
            "name": "John Smith",
            "email": "john@example.com",
            "phone": "555-1234",
            "product_id": 12345,
        }

        pii_fields = ["email", "phone"]
        anonymized = engine.anonymize_structured_data(data, pii_fields)

        assert anonymized["email"] != "john@example.com"
        assert anonymized["phone"] != "555-1234"
        assert anonymized["product_id"] == 12345  # Not anonymized

    def test_infer_pii_type_email(self, engine: AnonymizationEngine):
        """Test PII type inference for email field."""
        pii_type = engine._infer_pii_type("user_email")

        assert pii_type == "EMAIL"

    def test_infer_pii_type_phone(self, engine: AnonymizationEngine):
        """Test PII type inference for phone field."""
        pii_type = engine._infer_pii_type("contact_phone")

        assert pii_type == "PHONE_NUMBER"

    def test_infer_pii_type_ssn(self, engine: AnonymizationEngine):
        """Test PII type inference for SSN field."""
        pii_type = engine._infer_pii_type("social_security_number")

        assert pii_type == "SSN"

    def test_create_anonymization_map(self, engine: AnonymizationEngine, sample_findings):
        """Test anonymization map creation."""
        anon_map = engine.create_anonymization_map(sample_findings)

        assert len(anon_map) == 3
        assert "john.doe@example.com" in anon_map
        assert "(555) 123-4567" in anon_map
        assert "123-45-6789" in anon_map

    def test_get_strategy_for_pii_type(self, engine: AnonymizationEngine):
        """Test getting strategy for PII type."""
        strategy = engine.get_strategy_for_pii_type("SSN")

        assert strategy == AnonymizationStrategy.HASH

    def test_set_strategy_for_pii_type(self, engine: AnonymizationEngine):
        """Test setting custom strategy for PII type."""
        engine.set_strategy_for_pii_type("EMAIL", AnonymizationStrategy.REDACT)

        strategy = engine.get_strategy_for_pii_type("EMAIL")
        assert strategy == AnonymizationStrategy.REDACT

    def test_strategy_map_default(self, engine: AnonymizationEngine):
        """Test default strategy mapping."""
        assert engine.strategy_map["SSN"] == AnonymizationStrategy.HASH
        assert engine.strategy_map["EMAIL"] == AnonymizationStrategy.MASK
        assert engine.strategy_map["OTHER"] == AnonymizationStrategy.SUPPRESS
