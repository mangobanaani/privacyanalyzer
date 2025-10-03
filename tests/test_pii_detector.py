"""Tests for PII detector."""

import pytest
from src.detectors import PIIDetector, CustomPIIPatterns
from src.models import PIIType


def test_email_detection():
    """Test email address detection."""
    detector = PIIDetector(score_threshold=0.5)
    text = "Contact me at john.doe@example.com for more info."

    detections = detector.detect(text)

    assert len(detections) > 0
    email_found = any(d["type"] == PIIType.EMAIL for d in detections)
    assert email_found, "Email should be detected"


def test_phone_detection():
    """Test phone number detection."""
    detector = PIIDetector(score_threshold=0.5)
    text = "Call me at +1-555-123-4567 or 555.123.4567"

    detections = detector.detect(text)

    assert len(detections) > 0
    phone_found = any(d["type"] == PIIType.PHONE_NUMBER for d in detections)
    assert phone_found, "Phone number should be detected"


def test_ssn_detection():
    """Test SSN detection."""
    detector = PIIDetector(score_threshold=0.5)
    text = "My SSN is 123-45-6789 for verification."

    detections = detector.detect(text)

    ssn_detections = [d for d in detections if d["type"] == PIIType.SSN]
    assert len(ssn_detections) > 0, "SSN should be detected"


def test_credit_card_detection():
    """Test credit card detection."""
    detector = PIIDetector(score_threshold=0.5)
    text = "Card number: 4532-1488-0343-6467"

    detections = detector.detect(text)

    cc_found = any(d["type"] == PIIType.CREDIT_CARD for d in detections)
    assert cc_found, "Credit card should be detected"


def test_ipv6_detection():
    """Test IPv6 address detection with custom patterns."""
    text = "Server address: 2001:0db8:85a3:0000:0000:8a2e:0370:7334"

    detections = CustomPIIPatterns.detect_ipv6(text)

    assert len(detections) > 0
    assert detections[0]["type"] == PIIType.IP_ADDRESS


def test_no_false_positives():
    """Test that regular text doesn't trigger false positives."""
    detector = PIIDetector(score_threshold=0.7)  # Higher threshold
    text = "This is a normal sentence with no PII."

    detections = detector.detect(text)

    # Should have very few or no detections
    assert len(detections) == 0, "Regular text should not trigger detections"


def test_batch_detection():
    """Test batch processing."""
    detector = PIIDetector(score_threshold=0.5)
    texts = [
        "Email: test@example.com",
        "Phone: 555-1234",
        "No PII here",
    ]

    results = detector.batch_detect(texts)

    assert len(results) == 3
    assert len(results[0]) > 0  # First text has email
    assert len(results[2]) == 0  # Third text has no PII


def test_confidence_scores():
    """Test that confidence scores are within valid range."""
    detector = PIIDetector(score_threshold=0.0)  # Detect everything
    text = "Email: john@example.com, Phone: 555-1234"

    detections = detector.detect(text)

    for detection in detections:
        assert 0.0 <= detection["confidence"] <= 1.0, "Confidence must be between 0 and 1"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
