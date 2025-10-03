"""European and Nordic PII pattern detection with validation.

This module provides detection and validation for region-specific PII patterns
from European countries, with a focus on Nordic countries.
"""

import re
from datetime import datetime
from typing import List, Optional, Dict, Tuple
from src.utils import get_logger

logger = get_logger(__name__)


class NordicSSNValidator:
    """Validators for Nordic country Social Security Numbers."""

    @staticmethod
    def validate_finnish_ssn(ssn: str) -> bool:
        """
        Validate Finnish Personal Identity Code (Henkilötunnus).

        Format: DDMMYY[+-A]NNN[0-9A-FHJ-NPR-Y]
        - DDMMYY: Date of birth
        - Century: + (1800s), - (1900s), A (2000s)
        - NNN: Individual number (odd for males, even for females)
        - Checksum: 0-9, A-Y (excluding G, I, O, Q)

        Args:
            ssn: Finnish SSN to validate

        Returns:
            True if valid, False otherwise
        """
        # Remove spaces
        ssn = ssn.replace(' ', '').upper()

        # Check format
        if not re.match(r'^\d{6}[+\-A]\d{3}[0-9A-FHJ-NPR-Y]$', ssn):
            return False

        # Extract components
        day = int(ssn[0:2])
        month = int(ssn[2:4])
        year = int(ssn[4:6])
        century_char = ssn[6]
        individual_num = ssn[7:10]
        checksum_char = ssn[10]

        # Determine century
        century_map = {'+': 1800, '-': 1900, 'A': 2000}
        if century_char not in century_map:
            return False
        century = century_map[century_char]
        full_year = century + year

        # Validate date
        try:
            datetime(full_year, month, day)
        except ValueError:
            return False

        # Validate checksum
        checksum_chars = '0123456789ABCDEFHJKLMNPRSTUVWXY'
        number_part = ssn[0:6] + ssn[7:10]
        checksum_index = int(number_part) % 31
        expected_checksum = checksum_chars[checksum_index]

        return checksum_char == expected_checksum

    @staticmethod
    def validate_swedish_ssn(ssn: str) -> bool:
        """
        Validate Swedish Personal Number (Personnummer).

        Format: YYYYMMDD-XXXX or YYMMDD-XXXX
        - Date of birth
        - 3 digit serial number
        - 1 digit checksum (Luhn algorithm)

        Args:
            ssn: Swedish SSN to validate

        Returns:
            True if valid, False otherwise
        """
        # Remove spaces and separators
        ssn = ssn.replace(' ', '').replace('-', '').replace('+', '')

        # Handle both 10 and 12 digit formats
        if len(ssn) == 12:
            ssn = ssn[2:]  # Remove century, use last 10 digits

        if len(ssn) != 10:
            return False

        if not ssn.isdigit():
            return False

        # Extract date
        year = int(ssn[0:2])
        month = int(ssn[2:4])
        day = int(ssn[4:6])

        # Validate date (approximate - use current century for validation)
        current_year = datetime.now().year % 100
        century = 1900 if year > current_year else 2000
        try:
            datetime(century + year, month, day)
        except ValueError:
            return False

        # Validate checksum using Luhn algorithm
        return NordicSSNValidator._luhn_checksum(ssn)

    @staticmethod
    def validate_norwegian_ssn(ssn: str) -> bool:
        """
        Validate Norwegian National ID (Fødselsnummer).

        Format: DDMMYY-XXXXX
        - DDMMYY: Date of birth
        - XXX: Individual number (500-749 for 1900s, 500-999 for 2000s)
        - XX: Two check digits

        Args:
            ssn: Norwegian SSN to validate

        Returns:
            True if valid, False otherwise
        """
        # Remove spaces and separators
        ssn = ssn.replace(' ', '').replace('-', '')

        if len(ssn) != 11:
            return False

        if not ssn.isdigit():
            return False

        # Extract components
        day = int(ssn[0:2])
        month = int(ssn[2:4])
        year = int(ssn[4:6])
        individual_num = int(ssn[6:9])

        # Determine century based on individual number
        if 0 <= individual_num < 500:
            century = 1900
        elif 500 <= individual_num < 750 and year >= 54:
            century = 1800
        elif 500 <= individual_num < 750 and year < 54:
            century = 2000
        elif 900 <= individual_num < 1000 and year >= 40:
            century = 1900
        elif 900 <= individual_num < 1000 and year < 40:
            century = 2000
        else:
            century = 1900

        full_year = century + year

        # Validate date
        try:
            datetime(full_year, month, day)
        except ValueError:
            return False

        # Validate check digits (modulo 11 algorithm)
        weights1 = [3, 7, 6, 1, 8, 9, 4, 5, 2]
        weights2 = [5, 4, 3, 2, 7, 6, 5, 4, 3, 2]

        # First check digit
        sum1 = sum(int(ssn[i]) * weights1[i] for i in range(9))
        check1 = 11 - (sum1 % 11)
        if check1 == 11:
            check1 = 0
        if check1 == 10 or check1 != int(ssn[9]):
            return False

        # Second check digit
        sum2 = sum(int(ssn[i]) * weights2[i] for i in range(10))
        check2 = 11 - (sum2 % 11)
        if check2 == 11:
            check2 = 0
        if check2 == 10 or check2 != int(ssn[10]):
            return False

        return True

    @staticmethod
    def validate_danish_cpr(cpr: str) -> bool:
        """
        Validate Danish CPR Number (Det Centrale Personregister).

        Format: DDMMYY-XXXX
        - DDMMYY: Date of birth
        - XXXX: Serial number (7th digit indicates century)

        Args:
            cpr: Danish CPR to validate

        Returns:
            True if valid, False otherwise
        """
        # Remove spaces and separators
        cpr = cpr.replace(' ', '').replace('-', '')

        if len(cpr) != 10:
            return False

        if not cpr.isdigit():
            return False

        # Extract components
        day = int(cpr[0:2])
        month = int(cpr[2:4])
        year = int(cpr[4:6])
        serial = int(cpr[6:10])

        # Determine century from 7th digit
        seventh_digit = int(cpr[6])
        if seventh_digit in [0, 1, 2, 3]:
            century = 1900
        elif seventh_digit in [4, 9]:
            if year <= 36:
                century = 2000
            else:
                century = 1900
        elif seventh_digit in [5, 6, 7, 8]:
            if year <= 57:
                century = 2000
            else:
                century = 1800
        else:
            return False

        full_year = century + year

        # Validate date
        try:
            datetime(full_year, month, day)
        except ValueError:
            return False

        # Note: Old CPR numbers had modulo 11 check, but it's no longer used
        # for numbers issued after 2007, so we only validate format and date

        return True

    @staticmethod
    def _luhn_checksum(number: str) -> bool:
        """
        Validate using Luhn algorithm (modulo 10).

        Args:
            number: Number string to validate

        Returns:
            True if checksum is valid
        """
        digits = [int(d) for d in number]
        checksum = 0

        # Process digits from right to left
        for i, digit in enumerate(reversed(digits)):
            if i % 2 == 1:  # Every second digit from the right
                digit *= 2
                if digit > 9:
                    digit -= 9
            checksum += digit

        return checksum % 10 == 0


class EUPIIPatterns:
    """European PII pattern detection and validation."""

    # Pattern definitions with metadata
    PATTERNS = {
        'FINNISH_SSN': {
            'pattern': r'\b\d{6}[+\-A]\d{3}[0-9A-FHJ-NPR-Y]\b',
            'description': 'Finnish Personal Identity Code (Henkilötunnus)',
            'validator': NordicSSNValidator.validate_finnish_ssn,
            'context_keywords': ['henkilötunnus', 'hetu', 'personnummer'],
            'confidence_base': 0.85,
        },
        'SWEDISH_SSN': {
            'pattern': r'\b(19|20)?\d{6}[-+\s]?\d{4}\b',
            'description': 'Swedish Personal Number (Personnummer)',
            'validator': NordicSSNValidator.validate_swedish_ssn,
            'context_keywords': ['personnummer', 'person-nummer', 'pnr'],
            'confidence_base': 0.80,
        },
        'NORWEGIAN_SSN': {
            'pattern': r'\b\d{6}[-\s]?\d{5}\b',
            'description': 'Norwegian National ID (Fødselsnummer)',
            'validator': NordicSSNValidator.validate_norwegian_ssn,
            'context_keywords': ['fødselsnummer', 'fnr', 'personnummer'],
            'confidence_base': 0.80,
        },
        'DANISH_CPR': {
            'pattern': r'\b\d{6}[-\s]?\d{4}\b',
            'description': 'Danish CPR Number',
            'validator': NordicSSNValidator.validate_danish_cpr,
            'context_keywords': ['cpr', 'cpr-nummer', 'personnummer'],
            'confidence_base': 0.80,
        },
        'UK_NINO': {
            'pattern': r'\b[A-CEGHJ-PR-TW-Z]{1}[A-CEGHJ-NPR-TW-Z]{1}\s?\d{6}\s?[A-D]{1}\b',
            'description': 'UK National Insurance Number',
            'validator': lambda x: EUPIIPatterns._validate_uk_nino(x),
            'context_keywords': ['national insurance', 'nino', 'ni number'],
            'confidence_base': 0.90,
        },
        'BIC_SWIFT': {
            'pattern': r'\b[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?\b',
            'description': 'BIC/SWIFT Code',
            'validator': lambda x: True,  # Format-only validation
            'context_keywords': ['swift', 'bic', 'bank identifier'],
            'confidence_base': 0.75,
        },
        'EU_VAT': {
            'pattern': r'\b(AT|BE|BG|CY|CZ|DE|DK|EE|EL|ES|FI|FR|GB|HR|HU|IE|IT|LT|LU|LV|MT|NL|PL|PT|RO|SE|SI|SK)U?\d{8,12}\b',
            'description': 'EU VAT Number',
            'validator': lambda x: True,  # Complex country-specific validation
            'context_keywords': ['vat', 'vat number', 'moms', 'alv'],
            'confidence_base': 0.80,
        },
    }

    @classmethod
    def detect_all(cls, text: str, source: str = None) -> List[dict]:
        """
        Detect all European PII patterns in text.

        Args:
            text: Text to scan
            source: Optional source identifier

        Returns:
            List of detection dictionaries
        """
        detections = []

        for pii_type, config in cls.PATTERNS.items():
            pattern = config['pattern']
            validator = config['validator']
            base_confidence = config['confidence_base']
            context_keywords = config['context_keywords']

            # Find all matches
            matches = re.finditer(pattern, text, re.IGNORECASE)

            for match in matches:
                value = match.group()

                # Validate the match
                try:
                    if validator(value):
                        # Check for context to boost confidence
                        confidence = base_confidence
                        context_start = max(0, match.start() - 100)
                        context_end = min(len(text), match.end() + 100)
                        context = text[context_start:context_end].lower()

                        # Boost confidence if context keywords found
                        if any(keyword in context for keyword in context_keywords):
                            confidence = min(0.95, confidence + 0.10)

                        detections.append({
                            'type': pii_type,
                            'start': match.start(),
                            'end': match.end(),
                            'confidence': confidence,
                            'content': value,
                            'description': config['description'],
                        })

                        logger.debug(f"Detected {pii_type}: {value} (confidence: {confidence})")
                except Exception as e:
                    logger.warning(f"Validation failed for {pii_type} candidate '{value}': {e}")
                    continue

        return detections

    @staticmethod
    def _validate_uk_nino(nino: str) -> bool:
        """
        Validate UK National Insurance Number.

        Args:
            nino: UK NINO to validate

        Returns:
            True if valid, False otherwise
        """
        # Remove spaces
        nino = nino.replace(' ', '').upper()

        if len(nino) != 9:
            return False

        # Invalid prefixes (administrative reasons)
        invalid_prefixes = [
            'BG', 'GB', 'NK', 'KN', 'TN', 'NT', 'ZZ',
            'D', 'F', 'I', 'Q', 'U', 'V'  # Invalid first letters
        ]

        # Check first letter
        if nino[0] in 'DFIQUV':
            return False

        # Check prefix
        if nino[:2] in invalid_prefixes:
            return False

        # Check suffix
        if nino[8] not in 'ABCD ':
            return False

        # Check middle is numeric
        if not nino[2:8].isdigit():
            return False

        return True

    @classmethod
    def get_supported_types(cls) -> List[str]:
        """Get list of supported PII types."""
        return list(cls.PATTERNS.keys())

    @classmethod
    def get_description(cls, pii_type: str) -> Optional[str]:
        """Get description for a PII type."""
        if pii_type in cls.PATTERNS:
            return cls.PATTERNS[pii_type]['description']
        return None


# Convenience functions for individual validations
def validate_finnish_ssn(ssn: str) -> bool:
    """Validate Finnish SSN."""
    return NordicSSNValidator.validate_finnish_ssn(ssn)


def validate_swedish_ssn(ssn: str) -> bool:
    """Validate Swedish SSN."""
    return NordicSSNValidator.validate_swedish_ssn(ssn)


def validate_norwegian_ssn(ssn: str) -> bool:
    """Validate Norwegian SSN."""
    return NordicSSNValidator.validate_norwegian_ssn(ssn)


def validate_danish_cpr(cpr: str) -> bool:
    """Validate Danish CPR."""
    return NordicSSNValidator.validate_danish_cpr(cpr)
