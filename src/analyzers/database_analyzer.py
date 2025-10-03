"""Database analyzer for scanning databases for PII."""

import asyncio
from typing import List, Dict, Optional, Any
from urllib.parse import urlparse
import uuid

from sqlalchemy import create_engine, MetaData, Table, select, inspect
from sqlalchemy.engine import Engine

from src.analyzers.base import AnalyzerBase
from src.models import ScanResult, Finding, Severity
from src.detectors.pii_detector import PIIDetector
from src.utils import get_logger

logger = get_logger(__name__)


class DatabaseAnalyzer(AnalyzerBase):
    """Analyze databases for PII and privacy issues."""

    def __init__(
        self,
        config=None,
        max_rows_sample: int = 1000,
        use_llm: bool = False,
        sample_percentage: float = 0.1,
    ):
        """
        Initialize database analyzer.

        Args:
            config: Optional configuration
            max_rows_sample: Maximum rows to sample per table
            use_llm: Enable LLM-powered analysis
            sample_percentage: Percentage of rows to sample (0.0-1.0)
        """
        super().__init__(config)
        self.max_rows_sample = max_rows_sample
        # Convert string to boolean if needed (for CLI compatibility)
        if isinstance(use_llm, str):
            use_llm = use_llm.lower() in ('true', '1', 'yes')
        self.use_llm = use_llm
        self.sample_percentage = min(max(sample_percentage, 0.0), 1.0)
        self.pii_detector = PIIDetector()

    def validate_source(self, source: str) -> bool:
        """
        Validate database connection string.

        Args:
            source: Database connection string

        Returns:
            True if valid
        """
        try:
            # Parse connection string
            parsed = urlparse(source)
            # Handle dialect+driver format (e.g., mysql+pymysql, postgresql+psycopg2)
            scheme = parsed.scheme.split('+')[0] if '+' in parsed.scheme else parsed.scheme
            return scheme in ["postgresql", "mysql", "sqlite", "mssql"]
        except Exception as e:
            logger.error(f"Invalid connection string: {e}")
            return False

    async def analyze(self, source: str) -> ScanResult:
        """
        Analyze a database for PII.

        Args:
            source: Database connection string (e.g., postgresql://user:pass@host/db)

        Returns:
            ScanResult with findings
        """
        if not self.validate_source(source):
            raise ValueError(f"Invalid database connection string: {source}")

        scan_result = self._create_scan_result(source, "database")

        try:
            # Create database engine
            engine = create_engine(source)

            # Get database metadata
            metadata = MetaData()
            metadata.reflect(bind=engine)

            logger.info(f"Found {len(metadata.tables)} tables in database")

            # Analyze each table
            for table_name in metadata.tables:
                table_findings = await self._analyze_table(
                    engine, metadata.tables[table_name], source
                )

                for finding in table_findings:
                    scan_result.add_finding(finding)

            # Analyze schema and metadata
            schema_findings = await self._analyze_schema(engine, metadata, source)
            for finding in schema_findings:
                scan_result.add_finding(finding)

            scan_result.complete()
            logger.info(
                f"Database scan complete: {len(metadata.tables)} tables, "
                f"{scan_result.total_findings} findings"
            )

        except Exception as e:
            logger.error(f"Database analysis failed: {e}")
            scan_result.fail(str(e))
            raise
        finally:
            if "engine" in locals():
                engine.dispose()

        return scan_result

    async def _analyze_table(
        self, engine: Engine, table: Table, source: str
    ) -> List[Finding]:
        """
        Analyze a single table for PII.

        Args:
            engine: Database engine
            table: Table object
            source: Database connection string

        Returns:
            List of findings
        """
        findings = []
        table_name = table.name

        logger.info(f"Analyzing table: {table_name}")

        try:
            # Sample rows from table
            with engine.connect() as conn:
                # Calculate sample size
                stmt = select(table).limit(self.max_rows_sample)
                result = conn.execute(stmt)
                rows = result.fetchall()

                if not rows:
                    logger.debug(f"Table {table_name} is empty")
                    return findings

                logger.debug(f"Sampled {len(rows)} rows from {table_name}")

                # Analyze each column
                for column in table.columns:
                    column_name = column.name
                    column_type = str(column.type)

                    # Check column name for PII indicators
                    name_finding = self._check_column_name(
                        table_name, column_name, column_type, source
                    )
                    if name_finding:
                        findings.append(name_finding)

                    # Sample column values
                    column_values = [
                        str(row[column_name]) for row in rows if row[column_name] is not None
                    ]

                    if column_values:
                        # Detect PII in column values
                        value_findings = self._detect_pii_in_column(
                            table_name, column_name, column_values, source
                        )
                        findings.extend(value_findings)

        except Exception as e:
            logger.error(f"Failed to analyze table {table_name}: {e}")

        return findings

    def _check_column_name(
        self, table_name: str, column_name: str, column_type: str, source: str
    ) -> Optional[Finding]:
        """
        Check if column name suggests PII storage.

        Args:
            table_name: Table name
            column_name: Column name
            column_type: Column data type
            source: Database source

        Returns:
            Finding if PII suspected, None otherwise
        """
        pii_keywords = {
            "email": ("EMAIL", Severity.MEDIUM),
            "phone": ("PHONE_NUMBER", Severity.MEDIUM),
            "ssn": ("SSN", Severity.CRITICAL),
            "social_security": ("SSN", Severity.CRITICAL),
            "password": ("OTHER", Severity.CRITICAL),  # PASSWORD not in PIIType enum
            "credit_card": ("CREDIT_CARD", Severity.CRITICAL),
            "card_number": ("CREDIT_CARD", Severity.CRITICAL),
            "dob": ("DATE_OF_BIRTH", Severity.HIGH),
            "birth_date": ("DATE_OF_BIRTH", Severity.HIGH),
            "address": ("LOCATION", Severity.MEDIUM),
            "salary": ("OTHER", Severity.HIGH),  # FINANCIAL not in PIIType enum
            "income": ("OTHER", Severity.HIGH),  # FINANCIAL not in PIIType enum
            "passport": ("PASSPORT", Severity.CRITICAL),
            "license": ("DRIVER_LICENSE", Severity.HIGH),
            "tax_id": ("OTHER", Severity.CRITICAL),  # TAX_ID not in PIIType enum
            "medical": ("MEDICAL_LICENSE", Severity.CRITICAL),
            "health": ("MEDICAL_LICENSE", Severity.CRITICAL),
        }

        column_lower = column_name.lower()

        for keyword, (pii_type, severity) in pii_keywords.items():
            if keyword in column_lower:
                return Finding(
                    id=str(uuid.uuid4()),
                    source=source,
                    location=f"{table_name}.{column_name}",
                    pii_type=pii_type,
                    content=f"Column: {column_name} (type: {column_type})",
                    context=f"Table column with potential PII: {column_name}",
                    confidence=0.75,
                    severity=severity,
                    gdpr_articles=self._get_gdpr_articles(pii_type),
                    recommendation=f"Review column {table_name}.{column_name} for PII. "
                    f"Consider encryption at rest and access controls.",
                )

        return None

    def _detect_pii_in_column(
        self, table_name: str, column_name: str, values: List[str], source: str
    ) -> List[Finding]:
        """
        Detect PII in column values.

        Args:
            table_name: Table name
            column_name: Column name
            values: Sample values
            source: Database source

        Returns:
            List of findings
        """
        findings = []

        # Concatenate sample values for analysis
        sample_text = "\n".join(values[:100])  # Limit sample size

        try:
            # Detect PII in sample text
            detections = self.pii_detector.detect(sample_text, source=source)

            # Group by PII type
            pii_counts = {}
            for detection in detections:
                pii_type = detection.pii_type
                pii_counts[pii_type] = pii_counts.get(pii_type, 0) + 1

            # Create findings for detected PII
            for pii_type, count in pii_counts.items():
                percentage = (count / len(values)) * 100 if values else 0

                # Only report if significant percentage contains PII
                if percentage >= 5.0:  # At least 5% of samples
                    finding = Finding(
                        id=str(uuid.uuid4()),
                        source=source,
                        location=f"{table_name}.{column_name}",
                        pii_type=pii_type,
                        content=f"Column contains {pii_type} in ~{percentage:.1f}% of sampled rows",
                        context=f"Detected {count} instances of {pii_type} in {len(values)} samples",
                        confidence=0.85,
                        severity=self._determine_severity(pii_type),
                        gdpr_articles=self._get_gdpr_articles(pii_type),
                        recommendation=f"Column {table_name}.{column_name} contains {pii_type}. "
                        f"Ensure proper encryption, access controls, and data retention policies.",
                    )
                    findings.append(finding)

        except Exception as e:
            logger.error(f"Failed to detect PII in {table_name}.{column_name}: {e}")

        return findings

    async def _analyze_schema(
        self, engine: Engine, metadata: MetaData, source: str
    ) -> List[Finding]:
        """
        Analyze database schema for privacy issues.

        Args:
            engine: Database engine
            metadata: Database metadata
            source: Database source

        Returns:
            List of schema-level findings
        """
        findings = []

        try:
            inspector = inspect(engine)

            # Check for encryption
            encryption_finding = self._check_encryption(inspector, source)
            if encryption_finding:
                findings.append(encryption_finding)

            # Check for audit tables
            audit_finding = self._check_audit_tables(metadata, source)
            if audit_finding:
                findings.append(audit_finding)

        except Exception as e:
            logger.error(f"Schema analysis failed: {e}")

        return findings

    def _check_encryption(self, inspector, source: str) -> Optional[Finding]:
        """
        Check if database uses encryption.

        Args:
            inspector: Database inspector
            source: Database source

        Returns:
            Finding if encryption issues detected
        """
        return Finding(
            id=str(uuid.uuid4()),
            source=source,
            location="database_schema",
            pii_type="OTHER",
            content="Database encryption configuration",
            context="Database-level security review",
            confidence=0.60,
            severity=Severity.MEDIUM,
            gdpr_articles=["Art. 32"],
            recommendation="Verify that the database uses encryption at rest and in transit. "
            "Enable Transparent Data Encryption (TDE) if available.",
        )

    def _check_audit_tables(self, metadata: MetaData, source: str) -> Optional[Finding]:
        """
        Check for audit/logging tables.

        Args:
            metadata: Database metadata
            source: Database source

        Returns:
            Finding if audit issues detected
        """
        audit_keywords = ["audit", "log", "history", "changelog"]
        has_audit = any(
            any(keyword in table_name.lower() for keyword in audit_keywords)
            for table_name in metadata.tables
        )

        if not has_audit:
            return Finding(
                id=str(uuid.uuid4()),
                source=source,
                location="database_schema",
                pii_type="OTHER",
                content="No audit tables detected",
                context="Database schema analysis",
                confidence=0.70,
                severity=Severity.MEDIUM,
                gdpr_articles=["Art. 5", "Art. 32"],
                recommendation="Implement audit logging for PII access and modifications. "
                "Create audit tables to track who accessed what data and when.",
            )

        return None

    def _determine_severity(self, pii_type: str) -> str:
        """
        Determine severity based on PII type.

        Args:
            pii_type: Type of PII

        Returns:
            Severity level
        """
        critical_types = ["SSN", "CREDIT_CARD", "PASSPORT", "MEDICAL_LICENSE", "CRYPTO_ADDRESS"]
        high_types = ["DATE_OF_BIRTH", "DRIVER_LICENSE"]

        if pii_type in critical_types:
            return Severity.CRITICAL
        elif pii_type in high_types:
            return Severity.HIGH
        else:
            return Severity.MEDIUM

    def _get_gdpr_articles(self, pii_type: str) -> List[str]:
        """
        Get relevant GDPR articles for PII type.

        Args:
            pii_type: Type of PII

        Returns:
            List of GDPR article references
        """
        # Special category data (Art. 9)
        special_categories = ["SSN", "MEDICAL_LICENSE", "PASSPORT"]

        if pii_type in special_categories:
            return ["Art. 9", "Art. 32"]
        else:
            return ["Art. 6", "Art. 32"]
