"""Pytest configuration and shared fixtures."""

import pytest
import tempfile
from pathlib import Path
from typing import Generator


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create a temporary directory for tests."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_text_with_pii() -> str:
    """Sample text containing various PII types."""
    return """
    John Smith's email is john.smith@example.com and his phone number is (555) 123-4567.
    His SSN is 123-45-6789 and he lives at 123 Main St, Springfield, IL 62701.
    Credit card: 4532-1234-5678-9010
    Date of birth: 03/15/1985
    """


@pytest.fixture
def sample_text_no_pii() -> str:
    """Sample text without PII."""
    return """
    This is a sample document that contains no personal information.
    It discusses general topics like weather, technology, and current events.
    The document is used for testing purposes only.
    """


@pytest.fixture
def sample_pdf_path(temp_dir: Path) -> Path:
    """Create a sample PDF file for testing."""
    pdf_path = temp_dir / "sample.pdf"

    # Create a simple PDF with PyMuPDF
    try:
        import fitz
        doc = fitz.open()
        page = doc.new_page()
        page.insert_text((72, 72), "Name: John Smith\nSSN: 123-45-6789\nEmail: john@example.com")
        doc.save(pdf_path)
        doc.close()
    except ImportError:
        # Fallback: create empty file if PyMuPDF not available
        pdf_path.touch()

    return pdf_path


@pytest.fixture
def sample_text_file(temp_dir: Path, sample_text_with_pii: str) -> Path:
    """Create a sample text file with PII."""
    txt_path = temp_dir / "sample.txt"
    txt_path.write_text(sample_text_with_pii)
    return txt_path


@pytest.fixture
def mock_anthropic_response():
    """Mock Anthropic API response."""
    return {
        "content": [
            {
                "type": "text",
                "text": "Sensitive field containing employee SSN. High risk for GDPR Art. 9 violation. Recommendation: Encrypt at rest and implement access controls."
            }
        ]
    }
