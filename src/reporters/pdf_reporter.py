"""PDF report generation."""

from pathlib import Path
from typing import Optional, Dict
import subprocess
import tempfile

from src.models import ScanResult
from src.reporters.html_reporter import HTMLReporter
from src.utils import get_logger

logger = get_logger(__name__)


class PDFReporter:
    """Generate PDF compliance reports."""

    def __init__(self):
        """Initialize PDF reporter."""
        self.html_reporter = HTMLReporter()

    def generate_compliance_report(
        self, scan_result: ScanResult, output_path: str, compliance_data: Optional[Dict] = None
    ) -> None:
        """
        Generate PDF compliance report.

        Args:
            scan_result: Scan results
            output_path: Output file path
            compliance_data: Optional pre-computed compliance data
        """
        try:
            # Check if wkhtmltopdf is available
            if not self._check_wkhtmltopdf():
                logger.warning(
                    "wkhtmltopdf not found. Install with: sudo apt-get install wkhtmltopdf (Linux) or brew install wkhtmltopdf (macOS)"
                )
                logger.info("Falling back to HTML report generation")

                # Generate HTML instead
                html_path = output_path.replace(".pdf", ".html")
                self.html_reporter.generate_compliance_report(
                    scan_result, html_path, compliance_data
                )
                logger.info(f"HTML report generated instead: {html_path}")
                return

            # Generate HTML in temp file
            with tempfile.NamedTemporaryFile(mode="w", suffix=".html", delete=False) as tmp:
                tmp_html = tmp.name
                self.html_reporter.generate_compliance_report(
                    scan_result, tmp_html, compliance_data
                )

            # Convert HTML to PDF using wkhtmltopdf
            cmd = [
                "wkhtmltopdf",
                "--enable-local-file-access",
                "--page-size",
                "A4",
                "--margin-top",
                "10mm",
                "--margin-bottom",
                "10mm",
                "--margin-left",
                "10mm",
                "--margin-right",
                "10mm",
                tmp_html,
                output_path,
            ]

            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode != 0:
                logger.error(f"wkhtmltopdf failed: {result.stderr}")
                raise RuntimeError(f"PDF generation failed: {result.stderr}")

            # Clean up temp file
            Path(tmp_html).unlink()

            logger.info(f"PDF report generated: {output_path}")

        except Exception as e:
            logger.error(f"Failed to generate PDF report: {e}")
            # Fallback to HTML
            html_path = output_path.replace(".pdf", ".html")
            self.html_reporter.generate_compliance_report(scan_result, html_path, compliance_data)
            logger.info(f"Generated HTML report instead: {html_path}")

    def _check_wkhtmltopdf(self) -> bool:
        """
        Check if wkhtmltopdf is installed.

        Returns:
            True if available
        """
        try:
            result = subprocess.run(
                ["wkhtmltopdf", "--version"], capture_output=True, text=True, timeout=5
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            return False
