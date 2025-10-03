"""HTML report generation."""

from datetime import datetime
from pathlib import Path
from typing import Optional, Dict
from jinja2 import Environment, FileSystemLoader, select_autoescape

from src.models import ScanResult
from src.detectors import GDPREngine
from src.utils import get_logger

logger = get_logger(__name__)


class HTMLReporter:
    """Generate HTML compliance reports."""

    def __init__(self, template_dir: Optional[str] = None):
        """
        Initialize HTML reporter.

        Args:
            template_dir: Directory containing templates
        """
        if template_dir is None:
            template_dir = Path(__file__).parent / "templates"

        self.template_dir = Path(template_dir)

        # Setup Jinja2 environment
        self.env = Environment(
            loader=FileSystemLoader(str(self.template_dir)), autoescape=select_autoescape(["html"])
        )

        self.gdpr_engine = GDPREngine()

    def generate_compliance_report(
        self, scan_result: ScanResult, output_path: str, compliance_data: Optional[Dict] = None
    ) -> None:
        """
        Generate HTML compliance report.

        Args:
            scan_result: Scan results
            output_path: Output file path
            compliance_data: Optional pre-computed compliance data
        """
        try:
            # Analyze GDPR compliance if not provided
            if compliance_data is None:
                compliance_data = self.gdpr_engine.analyze_compliance(scan_result)

            # Load template
            template = self.env.get_template("compliance_report.html")

            # Prepare data for template
            context = {
                "scan_result": scan_result,
                "compliance": compliance_data,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }

            # Render HTML
            html_content = template.render(**context)

            # Write to file
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html_content)

            logger.info(f"HTML report generated: {output_path}")

        except Exception as e:
            logger.error(f"Failed to generate HTML report: {e}")
            raise

    def generate_summary_report(
        self, scan_results: list, output_path: str, title: str = "Privacy Scan Summary"
    ) -> None:
        """
        Generate summary report for multiple scans.

        Args:
            scan_results: List of scan results
            output_path: Output file path
            title: Report title
        """
        try:
            # Aggregate statistics
            total_findings = sum(r.total_findings for r in scan_results)
            total_scans = len(scan_results)

            # Aggregate by severity
            aggregated_severity = {}
            for result in scan_results:
                for severity, count in result.findings_by_severity.items():
                    aggregated_severity[severity] = aggregated_severity.get(severity, 0) + count

            # Aggregate by type
            aggregated_type = {}
            for result in scan_results:
                for pii_type, count in result.findings_by_type.items():
                    aggregated_type[pii_type] = aggregated_type.get(pii_type, 0) + count

            # Simple HTML generation (could create a separate template)
            html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>{title}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #2c3e50; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background-color: #34495e; color: white; }}
    </style>
</head>
<body>
    <h1>{title}</h1>
    <p><strong>Total Scans:</strong> {total_scans}</p>
    <p><strong>Total Findings:</strong> {total_findings}</p>

    <h2>Findings by Severity</h2>
    <table>
        <tr><th>Severity</th><th>Count</th></tr>
"""

            for severity, count in aggregated_severity.items():
                html += f"        <tr><td>{severity}</td><td>{count}</td></tr>\n"

            html += """
    </table>

    <h2>Findings by Type</h2>
    <table>
        <tr><th>PII Type</th><th>Count</th></tr>
"""

            for pii_type, count in aggregated_type.items():
                html += f"        <tr><td>{pii_type}</td><td>{count}</td></tr>\n"

            html += """
    </table>

    <h2>Individual Scans</h2>
    <table>
        <tr><th>Source</th><th>Findings</th><th>Status</th></tr>
"""

            for result in scan_results:
                html += f"""        <tr>
            <td>{result.source}</td>
            <td>{result.total_findings}</td>
            <td>{result.status}</td>
        </tr>
"""

            html += """
    </table>
</body>
</html>
"""

            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html)

            logger.info(f"Summary report generated: {output_path}")

        except Exception as e:
            logger.error(f"Failed to generate summary report: {e}")
            raise
