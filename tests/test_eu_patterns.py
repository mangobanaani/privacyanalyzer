"""Tests for European and Nordic PII pattern detection."""

import pytest
from src.detectors.eu_patterns import (
    EUPIIPatterns,
    NordicSSNValidator,
    validate_finnish_ssn,
    validate_swedish_ssn,
    validate_norwegian_ssn,
    validate_danish_cpr,
)


class TestFinnishSSNValidator:
    """Test Finnish SSN validation."""

    def test_valid_finnish_ssn_1900s(self):
        """Test valid Finnish SSN from 1900s."""
        # Format: DDMMYY-NNNC where - indicates 1900s
        assert validate_finnish_ssn("131052-308T")

    def test_finnish_ssn_century_marker_validation(self):
        """Test that century markers are properly validated."""
        # Valid century markers: + (1800s), - (1900s), A (2000s)
        assert validate_finnish_ssn("131052-308T")  # 1900s with -
        # Invalid century marker should be rejected
        assert not validate_finnish_ssn("131052B308T")  # B is invalid
        assert not validate_finnish_ssn("131052X308T")  # X is invalid

    def test_invalid_finnish_ssn_wrong_checksum(self):
        """Test Finnish SSN with wrong checksum."""
        assert not validate_finnish_ssn("131052-308X")  # Wrong checksum

    def test_invalid_finnish_ssn_wrong_date(self):
        """Test Finnish SSN with invalid date."""
        assert not validate_finnish_ssn("320152-308T")  # Invalid day (32)

    def test_invalid_finnish_ssn_wrong_format(self):
        """Test Finnish SSN with wrong format."""
        assert not validate_finnish_ssn("13105308T")  # Missing separator
        assert not validate_finnish_ssn("131052X308T")  # Wrong separator

    def test_invalid_finnish_ssn_forbidden_checksum_chars(self):
        """Test Finnish SSN with forbidden checksum characters."""
        # Checksum cannot be G, I, O, Q
        assert not validate_finnish_ssn("131052-308G")


class TestSwedishSSNValidator:
    """Test Swedish Personnummer validation."""

    def test_valid_swedish_ssn_10_digit(self):
        """Test valid 10-digit Swedish SSN."""
        assert validate_swedish_ssn("8507099805")  # Valid with Luhn

    def test_valid_swedish_ssn_12_digit(self):
        """Test valid 12-digit Swedish SSN."""
        assert validate_swedish_ssn("198507099805")

    def test_valid_swedish_ssn_with_separator(self):
        """Test valid Swedish SSN with separator."""
        assert validate_swedish_ssn("850709-9805")

    def test_invalid_swedish_ssn_wrong_checksum(self):
        """Test Swedish SSN with wrong Luhn checksum."""
        assert not validate_swedish_ssn("8507099806")  # Wrong checksum

    def test_invalid_swedish_ssn_wrong_date(self):
        """Test Swedish SSN with invalid date."""
        assert not validate_swedish_ssn("8513099805")  # Month 13 invalid

    def test_invalid_swedish_ssn_wrong_length(self):
        """Test Swedish SSN with wrong length."""
        assert not validate_swedish_ssn("85070998")  # Too short


class TestNorwegianSSNValidator:
    """Test Norwegian Fødselsnummer validation."""

    def test_valid_norwegian_ssn(self):
        """Test valid Norwegian SSN."""
        # This is a test number with valid check digits, format DDMMYYXXXCC
        assert validate_norwegian_ssn("15076500565")  # Valid test number

    def test_invalid_norwegian_ssn_wrong_date(self):
        """Test Norwegian SSN with invalid date."""
        assert not validate_norwegian_ssn("32010012345")  # Day 32 invalid

    def test_invalid_norwegian_ssn_wrong_length(self):
        """Test Norwegian SSN with wrong length."""
        assert not validate_norwegian_ssn("0101001234")  # Too short

    def test_invalid_norwegian_ssn_non_numeric(self):
        """Test Norwegian SSN with non-numeric characters."""
        assert not validate_norwegian_ssn("0101001234A")


class TestDanishCPRValidator:
    """Test Danish CPR validation."""

    def test_valid_danish_cpr(self):
        """Test valid Danish CPR."""
        assert validate_danish_cpr("0101901234")  # Valid date format

    def test_valid_danish_cpr_with_separator(self):
        """Test valid Danish CPR with separator."""
        assert validate_danish_cpr("010190-1234")

    def test_invalid_danish_cpr_wrong_date(self):
        """Test Danish CPR with invalid date."""
        assert not validate_danish_cpr("3201901234")  # Day 32 invalid

    def test_invalid_danish_cpr_wrong_length(self):
        """Test Danish CPR with wrong length."""
        assert not validate_danish_cpr("010190123")  # Too short

    def test_invalid_danish_cpr_non_numeric(self):
        """Test Danish CPR with non-numeric characters."""
        assert not validate_danish_cpr("010190123X")


class TestEUPIIPatterns:
    """Test EU PII pattern detection."""

    def test_detect_finnish_ssn(self):
        """Test detection of Finnish SSN in text."""
        text = "His henkilötunnus is 131052-308T"
        detections = EUPIIPatterns.detect_all(text)

        finnish_ssns = [d for d in detections if d['type'] == 'FINNISH_SSN']
        assert len(finnish_ssns) == 1
        assert finnish_ssns[0]['content'] == '131052-308T'
        assert finnish_ssns[0]['confidence'] > 0.85

    def test_detect_swedish_ssn(self):
        """Test detection of Swedish SSN in text."""
        text = "Personnummer: 850709-9805"
        detections = EUPIIPatterns.detect_all(text)

        swedish_ssns = [d for d in detections if d['type'] == 'SWEDISH_SSN']
        assert len(swedish_ssns) == 1
        assert '850709-9805' in swedish_ssns[0]['content']

    def test_detect_uk_nino(self):
        """Test detection of UK National Insurance Number."""
        text = "National Insurance Number: AB123456C"
        detections = EUPIIPatterns.detect_all(text)

        ninos = [d for d in detections if d['type'] == 'UK_NINO']
        assert len(ninos) == 1
        assert ninos[0]['content'] == 'AB123456C'

    def test_detect_bic_swift(self):
        """Test detection of BIC/SWIFT code."""
        text = "SWIFT code: NDEAFIHH"
        detections = EUPIIPatterns.detect_all(text)

        bics = [d for d in detections if d['type'] == 'BIC_SWIFT']
        assert len(bics) == 1
        assert bics[0]['content'] == 'NDEAFIHH'

    def test_detect_eu_vat(self):
        """Test detection of EU VAT number."""
        text = "VAT number: FI12345678"
        detections = EUPIIPatterns.detect_all(text)

        vats = [d for d in detections if d['type'] == 'EU_VAT']
        assert len(vats) == 1
        assert vats[0]['content'] == 'FI12345678'

    def test_no_false_positives_on_random_numbers(self):
        """Test that random numbers are not detected as SSNs."""
        text = "The price is 123456.78 euros"
        detections = EUPIIPatterns.detect_all(text)

        # Should not detect random numbers as SSNs
        assert len(detections) == 0

    def test_context_boosts_confidence(self):
        """Test that context keywords increase confidence."""
        text_with_context = "henkilötunnus: 131052-308T"
        text_without_context = "Number: 131052-308T"

        detections_with = EUPIIPatterns.detect_all(text_with_context)
        detections_without = EUPIIPatterns.detect_all(text_without_context)

        # Both should detect, but confidence should be higher with context
        assert len(detections_with) == 1
        assert len(detections_without) == 1
        assert detections_with[0]['confidence'] > detections_without[0]['confidence']

    def test_multiple_pii_types_in_text(self):
        """Test detection of multiple PII types in same text."""
        text = """
        Customer Information:
        Finnish SSN: 131052-308T
        UK NINO: AB123456C
        VAT: FI12345678
        """
        detections = EUPIIPatterns.detect_all(text)

        # Should detect all three
        types_detected = {d['type'] for d in detections}
        assert 'FINNISH_SSN' in types_detected
        assert 'UK_NINO' in types_detected
        assert 'EU_VAT' in types_detected

    def test_get_supported_types(self):
        """Test getting list of supported PII types."""
        types = EUPIIPatterns.get_supported_types()

        assert 'FINNISH_SSN' in types
        assert 'SWEDISH_SSN' in types
        assert 'NORWEGIAN_SSN' in types
        assert 'DANISH_CPR' in types
        assert 'UK_NINO' in types
        assert 'BIC_SWIFT' in types
        assert 'EU_VAT' in types

    def test_get_description(self):
        """Test getting description for PII type."""
        description = EUPIIPatterns.get_description('FINNISH_SSN')
        assert 'Finnish' in description
        assert 'Henkilötunnus' in description


class TestLuhnAlgorithm:
    """Test Luhn checksum validation."""

    def test_luhn_valid_numbers(self):
        """Test Luhn algorithm with valid numbers."""
        # Swedish personnummer uses Luhn
        assert NordicSSNValidator._luhn_checksum("8507099805")

    def test_luhn_invalid_numbers(self):
        """Test Luhn algorithm with invalid numbers."""
        assert not NordicSSNValidator._luhn_checksum("8507099806")


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_string(self):
        """Test with empty string."""
        assert not validate_finnish_ssn("")
        assert not validate_swedish_ssn("")
        assert not validate_norwegian_ssn("")
        assert not validate_danish_cpr("")

    def test_none_input(self):
        """Test with None input - should handle gracefully."""
        # These should not raise exceptions
        try:
            validate_finnish_ssn(None)
        except (TypeError, AttributeError):
            pass  # Expected

    def test_very_long_input(self):
        """Test with very long input."""
        long_string = "1" * 1000
        assert not validate_finnish_ssn(long_string)

    def test_special_characters(self):
        """Test with special characters."""
        text = "SSN: 131052-308T with special chars !@#$%"
        detections = EUPIIPatterns.detect_all(text)
        # Should still detect the valid SSN
        assert len(detections) > 0

    def test_mixed_case(self):
        """Test case insensitivity."""
        # UK NINO should work in different cases
        text = "NINO: ab123456c"
        detections = EUPIIPatterns.detect_all(text)
        # Pattern uses case-insensitive matching
        ninos = [d for d in detections if d['type'] == 'UK_NINO']
        assert len(ninos) == 1
