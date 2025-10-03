"""Tests for database analyzer."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from src.analyzers.database_analyzer import DatabaseAnalyzer
from src.models import ScanResult


class TestDatabaseAnalyzer:
    """Test database analyzer functionality."""

    @pytest.fixture
    def analyzer(self):
        """Create a database analyzer instance."""
        return DatabaseAnalyzer(max_rows_sample=100, use_llm=False)

    def test_validate_source_valid_postgresql(self, analyzer: DatabaseAnalyzer):
        """Test source validation with valid PostgreSQL connection string."""
        conn_str = "postgresql://user:pass@localhost/db"
        assert analyzer.validate_source(conn_str)

    def test_validate_source_valid_mysql(self, analyzer: DatabaseAnalyzer):
        """Test source validation with valid MySQL connection string."""
        conn_str = "mysql+pymysql://user:pass@localhost/db"
        assert analyzer.validate_source(conn_str)

    def test_validate_source_valid_sqlite(self, analyzer: DatabaseAnalyzer):
        """Test source validation with valid SQLite connection string."""
        conn_str = "sqlite:///path/to/database.db"
        assert analyzer.validate_source(conn_str)

    def test_validate_source_invalid(self, analyzer: DatabaseAnalyzer):
        """Test source validation with invalid connection string."""
        assert not analyzer.validate_source("invalid://connection")
        assert not analyzer.validate_source("not-a-connection-string")

    def test_check_column_name_email(self, analyzer: DatabaseAnalyzer):
        """Test column name checking for email field."""
        finding = analyzer._check_column_name(
            "users", "email_address", "VARCHAR(255)", "test_db"
        )

        assert finding is not None
        assert finding.pii_type == "EMAIL"
        assert finding.severity == "medium"
        assert "email_address" in finding.location

    def test_check_column_name_ssn(self, analyzer: DatabaseAnalyzer):
        """Test column name checking for SSN field."""
        finding = analyzer._check_column_name(
            "employees", "ssn", "VARCHAR(11)", "test_db"
        )

        assert finding is not None
        assert finding.pii_type == "SSN"
        assert finding.severity == "critical"

    def test_check_column_name_no_pii(self, analyzer: DatabaseAnalyzer):
        """Test column name checking with no PII."""
        finding = analyzer._check_column_name(
            "products", "product_id", "INTEGER", "test_db"
        )

        assert finding is None

    def test_determine_severity_critical(self, analyzer: DatabaseAnalyzer):
        """Test severity determination for critical PII."""
        from src.models import Severity
        assert analyzer._determine_severity("SSN") == Severity.CRITICAL
        assert analyzer._determine_severity("CREDIT_CARD") == Severity.CRITICAL
        assert analyzer._determine_severity("PASSPORT") == Severity.CRITICAL

    def test_determine_severity_high(self, analyzer: DatabaseAnalyzer):
        """Test severity determination for high PII."""
        from src.models import Severity
        assert analyzer._determine_severity("DATE_OF_BIRTH") == Severity.HIGH
        assert analyzer._determine_severity("DRIVER_LICENSE") == Severity.HIGH

    def test_determine_severity_medium(self, analyzer: DatabaseAnalyzer):
        """Test severity determination for medium PII."""
        from src.models import Severity
        assert analyzer._determine_severity("EMAIL") == Severity.MEDIUM
        assert analyzer._determine_severity("PHONE_NUMBER") == Severity.MEDIUM

    def test_get_gdpr_articles_special_category(self, analyzer: DatabaseAnalyzer):
        """Test GDPR article mapping for special category data."""
        articles = analyzer._get_gdpr_articles("SSN")

        assert "Art. 9" in articles
        assert "Art. 32" in articles

    def test_get_gdpr_articles_regular(self, analyzer: DatabaseAnalyzer):
        """Test GDPR article mapping for regular personal data."""
        articles = analyzer._get_gdpr_articles("EMAIL_ADDRESS")

        assert "Art. 6" in articles
        assert "Art. 32" in articles

    @pytest.mark.asyncio
    async def test_analyze_invalid_connection(self, analyzer: DatabaseAnalyzer):
        """Test analysis with invalid connection string."""
        with pytest.raises(ValueError):
            await analyzer.analyze("invalid://connection")

    def test_check_encryption(self, analyzer: DatabaseAnalyzer):
        """Test encryption check."""
        mock_inspector = Mock()
        finding = analyzer._check_encryption(mock_inspector, "test_db")

        assert finding is not None
        assert finding.pii_type == "OTHER"
        assert "Art. 32" in finding.gdpr_articles

    def test_check_audit_tables_missing(self, analyzer: DatabaseAnalyzer):
        """Test audit table check when missing."""
        from sqlalchemy import MetaData
        from src.models import Severity

        metadata = MetaData()
        # No tables added, so no audit tables

        finding = analyzer._check_audit_tables(metadata, "test_db")

        assert finding is not None
        assert finding.pii_type == "OTHER"
        assert finding.severity == Severity.MEDIUM

    def test_check_audit_tables_present(self, analyzer: DatabaseAnalyzer):
        """Test audit table check when present."""
        from sqlalchemy import MetaData, Table, Column, Integer

        metadata = MetaData()
        # Add an audit table
        Table("audit_log", metadata, Column("id", Integer))

        finding = analyzer._check_audit_tables(metadata, "test_db")

        assert finding is None
