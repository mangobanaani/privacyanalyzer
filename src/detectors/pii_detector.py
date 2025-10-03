"""PII detection engine using Presidio and custom patterns."""

import re
from typing import List, Dict, Optional
from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer
from presidio_analyzer.nlp_engine import NlpEngineProvider
from src.models import PIIType
from src.detectors.eu_patterns import EUPIIPatterns, NordicSSNValidator


class PIIDetector:
    """Detects PII in text using Presidio, spaCy, and custom patterns."""

    def __init__(self, languages: List[str] = None, score_threshold: float = 0.5):
        """
        Initialize PII detector.

        Args:
            languages: List of language codes (default: ["en"])
            score_threshold: Minimum confidence score for detections
        """
        self.languages = languages or ["en"]
        self.score_threshold = score_threshold
        self.analyzer = self._initialize_analyzer()

    def _initialize_analyzer(self) -> AnalyzerEngine:
        """Initialize Presidio analyzer with custom recognizers."""
        # Configure NLP engine (spaCy)
        configuration = {
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": lang, "model_name": f"{lang}_core_web_lg"}
                      for lang in self.languages],
        }

        provider = NlpEngineProvider(nlp_configuration=configuration)
        nlp_engine = provider.create_engine()

        # Create analyzer with NLP engine
        analyzer = AnalyzerEngine(nlp_engine=nlp_engine)

        # Add custom recognizers
        self._add_custom_recognizers(analyzer)

        return analyzer

    def _add_custom_recognizers(self, analyzer: AnalyzerEngine) -> None:
        """Add custom pattern-based recognizers for Nordic and EU PII."""

        # Finnish SSN with validation
        finnish_ssn_pattern = Pattern(
            name="finnish_ssn",
            regex=r"\b\d{6}[+\-A]\d{3}[0-9A-FHJ-NPR-Y]\b",
            score=0.95,
        )
        finnish_ssn_recognizer = PatternRecognizer(
            supported_entity="FINNISH_SSN",
            patterns=[finnish_ssn_pattern],
            context=["henkilötunnus", "hetu", "personnummer", "ssn"],
        )
        analyzer.registry.add_recognizer(finnish_ssn_recognizer)

        # Swedish Personnummer
        swedish_ssn_pattern = Pattern(
            name="swedish_ssn",
            regex=r"\b(19|20)?\d{6}[-+\s]?\d{4}\b",
            score=0.85,
        )
        swedish_ssn_recognizer = PatternRecognizer(
            supported_entity="SWEDISH_SSN",
            patterns=[swedish_ssn_pattern],
            context=["personnummer", "person-nummer", "pnr", "ssn"],
        )
        analyzer.registry.add_recognizer(swedish_ssn_recognizer)

        # Norwegian Fødselsnummer
        norwegian_ssn_pattern = Pattern(
            name="norwegian_ssn",
            regex=r"\b\d{6}[-\s]?\d{5}\b",
            score=0.85,
        )
        norwegian_ssn_recognizer = PatternRecognizer(
            supported_entity="NORWEGIAN_SSN",
            patterns=[norwegian_ssn_pattern],
            context=["fødselsnummer", "fnr", "personnummer", "ssn"],
        )
        analyzer.registry.add_recognizer(norwegian_ssn_recognizer)

        # Danish CPR
        danish_cpr_pattern = Pattern(
            name="danish_cpr",
            regex=r"\b\d{6}[-\s]?\d{4}\b",
            score=0.85,
        )
        danish_cpr_recognizer = PatternRecognizer(
            supported_entity="DANISH_CPR",
            patterns=[danish_cpr_pattern],
            context=["cpr", "cpr-nummer", "personnummer", "ssn"],
        )
        analyzer.registry.add_recognizer(danish_cpr_recognizer)

        # UK National Insurance Number
        uk_nino_pattern = Pattern(
            name="uk_nino",
            regex=r"\b[A-CEGHJ-PR-TW-Z]{1}[A-CEGHJ-NPR-TW-Z]{1}\s?\d{6}\s?[A-D]{1}\b",
            score=0.90,
        )
        uk_nino_recognizer = PatternRecognizer(
            supported_entity="UK_NINO",
            patterns=[uk_nino_pattern],
            context=["national insurance", "nino", "ni number", "ni no"],
        )
        analyzer.registry.add_recognizer(uk_nino_recognizer)

        # IBAN (International Bank Account Number)
        iban_pattern = Pattern(
            name="iban",
            regex=r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b",
            score=0.90,
        )
        iban_recognizer = PatternRecognizer(
            supported_entity="IBAN",
            patterns=[iban_pattern],
            context=["iban", "account", "bank", "account number"],
        )
        analyzer.registry.add_recognizer(iban_recognizer)

        # BIC/SWIFT Code
        bic_pattern = Pattern(
            name="bic_swift",
            regex=r"\b[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?\b",
            score=0.80,
        )
        bic_recognizer = PatternRecognizer(
            supported_entity="BIC_SWIFT",
            patterns=[bic_pattern],
            context=["swift", "bic", "bank identifier", "swift code"],
        )
        analyzer.registry.add_recognizer(bic_recognizer)

        # EU VAT Number
        vat_pattern = Pattern(
            name="eu_vat",
            regex=r"\b(AT|BE|BG|CY|CZ|DE|DK|EE|EL|ES|FI|FR|GB|HR|HU|IE|IT|LT|LU|LV|MT|NL|PL|PT|RO|SE|SI|SK)U?\d{8,12}\b",
            score=0.80,
        )
        vat_recognizer = PatternRecognizer(
            supported_entity="EU_VAT",
            patterns=[vat_pattern],
            context=["vat", "tax", "eu", "moms", "alv"],
        )
        analyzer.registry.add_recognizer(vat_recognizer)

        # Cryptocurrency addresses (Bitcoin)
        crypto_pattern = Pattern(
            name="crypto_address",
            regex=r"\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}\b",
            score=0.85,
        )
        crypto_recognizer = PatternRecognizer(
            supported_entity="CRYPTO_ADDRESS",
            patterns=[crypto_pattern],
            context=["bitcoin", "btc", "wallet", "crypto", "cryptocurrency"],
        )
        analyzer.registry.add_recognizer(crypto_recognizer)

        # Passport number (generic)
        passport_pattern = Pattern(
            name="passport",
            regex=r"\b[A-Z]{1,2}\d{6,9}\b",
            score=0.70,
        )
        passport_recognizer = PatternRecognizer(
            supported_entity="PASSPORT",
            patterns=[passport_pattern],
            context=["passport", "travel document", "document number", "pass number"],
        )
        analyzer.registry.add_recognizer(passport_recognizer)

    def detect(self, text: str, language: str = "en") -> List[Dict]:
        """
        Detect PII in text.

        Args:
            text: Text to analyze
            language: Language code

        Returns:
            List of detections with type, value, location, and confidence
        """
        if not text or not text.strip():
            return []

        # Analyze with Presidio
        results = self.analyzer.analyze(
            text=text, language=language, score_threshold=self.score_threshold
        )

        # Convert to our format
        detections = []
        for result in results:
            detection = {
                "type": self._map_entity_type(result.entity_type),
                "start": result.start,
                "end": result.end,
                "confidence": result.score,
                "value": text[result.start : result.end],
                "entity_type": result.entity_type,
            }
            detections.append(detection)

        return detections

    def _map_entity_type(self, entity_type: str) -> PIIType:
        """Map Presidio entity types to our PIIType enum."""
        mapping = {
            # Generic
            "EMAIL_ADDRESS": PIIType.EMAIL,
            "PHONE_NUMBER": PIIType.PHONE_NUMBER,
            "PERSON": PIIType.PERSON,
            "LOCATION": PIIType.LOCATION,
            "ORGANIZATION": PIIType.ORGANIZATION,
            "IP_ADDRESS": PIIType.IP_ADDRESS,
            "URL": PIIType.URL,
            "DATE_TIME": PIIType.DATE_OF_BIRTH,
            # US
            "US_SSN": PIIType.SSN,
            # Nordic
            "FINNISH_SSN": PIIType.FINNISH_SSN,
            "SWEDISH_SSN": PIIType.SWEDISH_SSN,
            "NORWEGIAN_SSN": PIIType.NORWEGIAN_SSN,
            "DANISH_CPR": PIIType.DANISH_CPR,
            # EU/UK
            "UK_NINO": PIIType.UK_NINO,
            "EU_VAT": PIIType.EU_VAT,
            # Financial
            "CREDIT_CARD": PIIType.CREDIT_CARD,
            "IBAN": PIIType.IBAN,
            "BIC_SWIFT": PIIType.BIC_SWIFT,
            # Documents
            "PASSPORT": PIIType.PASSPORT,
            "MEDICAL_LICENSE": PIIType.MEDICAL_LICENSE,
            # Crypto
            "CRYPTO_ADDRESS": PIIType.CRYPTO_ADDRESS,
        }
        return mapping.get(entity_type, PIIType.OTHER)

    def detect_batch(self, texts: List[str], language: str = "en") -> List[List[Dict]]:
        """
        Detect PII in multiple texts efficiently.

        Args:
            texts: List of texts to analyze
            language: Language code

        Returns:
            List of detection lists (one per input text)
        """
        return [self.detect(text, language) for text in texts]

    def get_supported_entities(self) -> List[str]:
        """Get list of supported entity types."""
        return self.analyzer.get_supported_entities()


class CustomPIIPatterns:
    """Additional custom patterns for structured data."""

    @staticmethod
    def detect_all(text: str) -> List[Dict]:
        """Run all custom pattern detections."""
        detections = []
        detections.extend(CustomPIIPatterns.detect_ipv6(text))
        detections.extend(CustomPIIPatterns.detect_mac_address(text))
        detections.extend(CustomPIIPatterns.detect_coordinates(text))
        return detections

    @staticmethod
    def detect_ipv6(text: str) -> List[Dict]:
        """Detect IPv6 addresses."""
        pattern = r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
        matches = re.finditer(pattern, text)
        return [
            {
                "type": PIIType.IP_ADDRESS,
                "start": m.start(),
                "end": m.end(),
                "confidence": 0.95,
                "value": m.group(),
                "entity_type": "IPV6_ADDRESS",
            }
            for m in matches
        ]

    @staticmethod
    def detect_mac_address(text: str) -> List[Dict]:
        """Detect MAC addresses."""
        pattern = r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"
        matches = re.finditer(pattern, text)
        return [
            {
                "type": PIIType.OTHER,
                "start": m.start(),
                "end": m.end(),
                "confidence": 0.90,
                "value": m.group(),
                "entity_type": "MAC_ADDRESS",
            }
            for m in matches
        ]

    @staticmethod
    def detect_coordinates(text: str) -> List[Dict]:
        """Detect GPS coordinates."""
        pattern = r"[-+]?([1-8]?\d(\.\d+)?|90(\.0+)?),\s*[-+]?(180(\.0+)?|((1[0-7]\d)|([1-9]?\d))(\.\d+)?)"
        matches = re.finditer(pattern, text)
        return [
            {
                "type": PIIType.LOCATION,
                "start": m.start(),
                "end": m.end(),
                "confidence": 0.85,
                "value": m.group(),
                "entity_type": "GPS_COORDINATES",
            }
            for m in matches
        ]
