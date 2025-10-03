"""Tests for FastAPI server."""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
from src.api.server import app
from src.models import ScanResult, Finding, Severity


@pytest.fixture
def client():
    """Create test client."""
    return TestClient(app)


@pytest.fixture
def sample_scan_result():
    """Create sample scan result."""
    result = ScanResult(
        source="test.txt",
        source_type="document",
        scan_id="test-123"
    )

    result.add_finding(Finding(
        id="api-finding-1",
        source="test.txt",
        location="line 1",
        pii_type="EMAIL",
        content="test@example.com",
        context="Email: test@example.com",
        confidence=0.95,
        severity=Severity.MEDIUM,
        recommendation="Encrypt email"
    ))

    result.complete()
    return result


class TestHealthEndpoint:
    """Test health check endpoint."""

    def test_health_check(self, client: TestClient):
        """Test health check returns 200."""
        response = client.get("/health")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "timestamp" in data


class TestScanEndpoints:
    """Test scan endpoints."""

    def test_scan_text(self, client: TestClient):
        """Test scanning text."""
        response = client.post(
            "/scan/text",
            json={"content": "Test content", "use_llm": False}
        )

        assert response.status_code == 200
        data = response.json()
        assert "scan_id" in data
        assert data["status"] == "pending"

    def test_scan_file(self, client: TestClient, temp_dir):
        """Test scanning uploaded file."""
        test_file = temp_dir / "test.txt"
        test_file.write_text("Test content")

        with open(test_file, "rb") as f:
            response = client.post(
                "/scan/file",
                files={"file": ("test.txt", f, "text/plain")},
                data={"use_llm": "false"}
            )

        assert response.status_code == 200
        data = response.json()
        assert "scan_id" in data
        assert data["status"] == "pending"

    def test_scan_website(self, client: TestClient):
        """Test scanning website."""
        response = client.post(
            "/scan/website",
            json={
                "url": "https://example.com",
                "max_pages": 5,
                "use_llm": False
            }
        )

        assert response.status_code == 200
        data = response.json()
        assert "scan_id" in data

    def test_scan_database(self, client: TestClient):
        """Test scanning database."""
        response = client.post(
            "/scan/database",
            json={
                "connection_string": "sqlite:///test.db",
                "max_rows": 100,
                "use_llm": False
            }
        )

        assert response.status_code == 200
        data = response.json()
        assert "scan_id" in data

    def test_get_scan_result_not_found(self, client: TestClient):
        """Test getting non-existent scan result."""
        response = client.get("/scan/non-existent-id")

        assert response.status_code == 404

    def test_get_scan_result_pending(self, client: TestClient):
        """Test getting pending scan result."""
        from src.api.server import scan_status

        scan_status["test-pending"] = "pending"

        response = client.get("/scan/test-pending")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "pending"

    def test_get_scan_result_completed(self, client: TestClient, sample_scan_result):
        """Test getting completed scan result."""
        from src.api.server import scan_results, scan_status

        scan_id = "test-completed"
        scan_results[scan_id] = sample_scan_result
        scan_status[scan_id] = "completed"

        response = client.get(f"/scan/{scan_id}")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "completed"
        assert "result" in data

    def test_list_scans(self, client: TestClient, sample_scan_result):
        """Test listing scans."""
        from src.api.server import scan_results, scan_status

        scan_results["test-1"] = sample_scan_result
        scan_status["test-1"] = "completed"

        response = client.get("/scans")

        assert response.status_code == 200
        data = response.json()
        assert "scans" in data
        assert "total" in data

    def test_list_scans_with_limit(self, client: TestClient):
        """Test listing scans with limit."""
        from src.api.server import scan_status

        # Add multiple scans
        for i in range(10):
            scan_status[f"test-{i}"] = "completed"

        response = client.get("/scans?limit=5")

        assert response.status_code == 200
        data = response.json()
        assert len(data["scans"]) <= 5


class TestAnonymizationEndpoint:
    """Test anonymization endpoint."""

    def test_anonymize_content(self, client: TestClient, sample_scan_result):
        """Test anonymizing content."""
        from src.api.server import scan_results

        scan_id = "test-anon"
        scan_results[scan_id] = sample_scan_result

        response = client.post(
            "/anonymize",
            json={
                "scan_id": scan_id,
                "content": "Email: test@example.com",
                "strategy": "mask"
            }
        )

        assert response.status_code == 200
        data = response.json()
        assert "anonymized_content" in data
        assert "pii_count" in data

    def test_anonymize_scan_not_found(self, client: TestClient):
        """Test anonymizing with non-existent scan."""
        response = client.post(
            "/anonymize",
            json={
                "scan_id": "non-existent",
                "content": "Test",
                "strategy": "mask"
            }
        )

        assert response.status_code == 404


class TestComplianceEndpoint:
    """Test compliance endpoint."""

    def test_analyze_compliance(self, client: TestClient, sample_scan_result):
        """Test GDPR compliance analysis."""
        from src.api.server import scan_results

        scan_id = "test-compliance"
        scan_results[scan_id] = sample_scan_result

        response = client.post(
            "/compliance",
            json={"scan_id": scan_id}
        )

        assert response.status_code == 200
        data = response.json()
        assert "compliance_score" in data
        assert "total_violations" in data

    def test_compliance_scan_not_found(self, client: TestClient):
        """Test compliance with non-existent scan."""
        response = client.post(
            "/compliance",
            json={"scan_id": "non-existent"}
        )

        assert response.status_code == 404


class TestCompareEndpoint:
    """Test comparison endpoint."""

    def test_compare_scans(self, client: TestClient, sample_scan_result):
        """Test comparing two scans."""
        from src.api.server import scan_results

        scan_results["baseline"] = sample_scan_result
        scan_results["current"] = sample_scan_result

        response = client.post(
            "/compare",
            json={
                "baseline_id": "baseline",
                "current_id": "current"
            }
        )

        assert response.status_code == 200
        data = response.json()
        assert "baseline" in data
        assert "current" in data
        assert "changes" in data
        assert "summary" in data

    def test_compare_baseline_not_found(self, client: TestClient, sample_scan_result):
        """Test comparison with missing baseline."""
        from src.api.server import scan_results

        scan_results["current"] = sample_scan_result

        response = client.post(
            "/compare",
            json={
                "baseline_id": "non-existent",
                "current_id": "current"
            }
        )

        assert response.status_code == 404

    def test_compare_current_not_found(self, client: TestClient, sample_scan_result):
        """Test comparison with missing current scan."""
        from src.api.server import scan_results

        scan_results["baseline"] = sample_scan_result

        response = client.post(
            "/compare",
            json={
                "baseline_id": "baseline",
                "current_id": "non-existent"
            }
        )

        assert response.status_code == 404


class TestExportEndpoint:
    """Test export endpoint."""

    def test_export_csv(self, client: TestClient, sample_scan_result):
        """Test exporting to CSV."""
        from src.api.server import scan_results

        scan_id = "test-export"
        scan_results[scan_id] = sample_scan_result

        response = client.get(f"/export/{scan_id}/csv")

        assert response.status_code == 200
        assert response.headers["content-type"] == "text/csv; charset=utf-8"

    def test_export_scan_not_found(self, client: TestClient):
        """Test export with non-existent scan."""
        response = client.get("/export/non-existent/csv")

        assert response.status_code == 404

    def test_export_invalid_format(self, client: TestClient, sample_scan_result):
        """Test export with invalid format."""
        from src.api.server import scan_results

        scan_id = "test-export"
        scan_results[scan_id] = sample_scan_result

        response = client.get(f"/export/{scan_id}/invalid")

        assert response.status_code == 400
