"""Command-line interface for Privacy Analyzer."""

import asyncio
import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from src.analyzers import DocumentAnalyzer, BatchAnalyzer, WebAnalyzer, DatabaseAnalyzer
from src.models import ScanResult, Severity
from src.detectors import GDPREngine
from src.reporters import HTMLReporter, PDFReporter, CSVReporter, ExcelReporter
from src.utils import setup_logging, get_logger, ScanComparator
from src.anonymizers import AnonymizationEngine, AnonymizationStrategy

app = typer.Typer(
    name="privacy-analyzer",
    help="AI-powered privacy analyzer for PII detection and GDPR compliance",
    rich_markup_mode=None,  # Disable rich formatting to fix compatibility issue
)
console = Console()
logger = get_logger(__name__)


@app.command()
def scan_document(
    file_path: str = typer.Argument(..., help="Path to document to scan"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file for results (JSON)"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    use_llm: bool = typer.Option(False, "--llm", help="Enable LLM-powered analysis (requires API key)"),
) -> None:
    """
    Scan a document for PII and privacy issues.

    Example:
        privacy-analyzer scan-document document.pdf
        privacy-analyzer scan-document document.pdf -o results.json
    """
    if verbose:
        setup_logging(log_level="DEBUG")
    else:
        setup_logging(log_level="INFO")

    console.print(f"\n[bold blue]Privacy Analyzer - Document Scan[/bold blue]")
    console.print(f"File: {file_path}\n")

    # Validate file
    if not Path(file_path).exists():
        console.print(f"[bold red]Error:[/bold red] File not found: {file_path}")
        raise typer.Exit(1)

    # Run analysis
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Analyzing document...", total=None)

        try:
            # Run async analysis
            result = asyncio.run(_scan_document_async(file_path, use_llm))
            progress.update(task, completed=True)

        except Exception as e:
            progress.stop()
            console.print(f"\n[bold red]Error:[/bold red] {str(e)}")
            logger.exception("Scan failed")
            raise typer.Exit(1)

    # Display results
    _display_results(result)

    # Save to file if requested
    if output:
        _save_results(result, output)
        console.print(f"\n[green]Results saved to:[/green] {output}")


async def _scan_document_async(file_path: str, use_llm: bool = False) -> ScanResult:
    """Run document scan asynchronously."""
    analyzer = DocumentAnalyzer(use_llm=use_llm)
    return await analyzer.analyze(file_path)


def _display_results(result: ScanResult) -> None:
    """Display scan results in a formatted table."""
    console.print(f"\n[bold]Scan Results[/bold]")
    console.print(f"Status: [green]{result.status}[/green]")
    console.print(f"Duration: {result.duration_seconds:.2f}s")
    console.print(f"Total Findings: {result.total_findings}\n")

    if result.total_findings == 0:
        console.print("[green]No PII detected![/green]")
        return

    # Summary by severity
    console.print("[bold]Findings by Severity:[/bold]")
    severity_table = Table()
    severity_table.add_column("Severity", style="bold")
    severity_table.add_column("Count", justify="right")

    for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
        count = result.findings_by_severity.get(severity, 0)
        if count > 0:
            color = _get_severity_color(severity)
            severity_table.add_row(f"[{color}]{severity.upper()}[/{color}]", str(count))

    console.print(severity_table)

    # Summary by PII type
    console.print("\n[bold]Findings by Type:[/bold]")
    type_table = Table()
    type_table.add_column("PII Type", style="bold")
    type_table.add_column("Count", justify="right")

    for pii_type, count in sorted(
        result.findings_by_type.items(), key=lambda x: x[1], reverse=True
    ):
        type_table.add_row(pii_type, str(count))

    console.print(type_table)

    # Detailed findings
    if result.total_findings <= 20:
        console.print("\n[bold]Detailed Findings:[/bold]")
        findings_table = Table(show_lines=True)
        findings_table.add_column("Location", style="cyan")
        findings_table.add_column("Type", style="yellow")
        findings_table.add_column("Severity")
        findings_table.add_column("Recommendation", max_width=50)

        for finding in result.findings[:20]:
            color = _get_severity_color(finding.severity)
            findings_table.add_row(
                finding.location,
                finding.pii_type,
                f"[{color}]{finding.severity.upper()}[/{color}]",
                finding.recommendation,
            )

        console.print(findings_table)
    else:
        console.print(
            f"\n[yellow]Showing summary only ({result.total_findings} findings). Use --output to save full results.[/yellow]"
        )


def _get_severity_color(severity: str) -> str:
    """Get color for severity level."""
    colors = {
        Severity.CRITICAL: "red bold",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "blue",
        Severity.INFO: "green",
    }
    return colors.get(severity, "white")


def _save_results(result: ScanResult, output_path: str) -> None:
    """Save scan results to JSON file."""
    output_data = result.model_dump()

    # Redact PII from output
    for finding in output_data.get("findings", []):
        finding["content"] = "[REDACTED]"

    with open(output_path, "w") as f:
        json.dump(output_data, f, indent=2, default=str)


@app.command()
def version() -> None:
    """Show version information."""
    console.print("[bold]Privacy Analyzer[/bold] v1.0.0")
    console.print("AI-powered PII detection and GDPR compliance scanner")


@app.command()
def scan_folder(
    folder_path: str = typer.Argument(..., help="Path to folder to scan"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file for results (JSON)"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    use_llm: bool = typer.Option(False, "--llm", help="Enable LLM-powered analysis"),
    max_workers: int = typer.Option(4, "--workers", "-w", help="Max concurrent file processing"),
) -> None:
    """
    Scan an entire folder for PII and privacy issues.

    Example:
        privacy-analyzer scan-folder ./documents
        privacy-analyzer scan-folder ./documents -o results.json --workers 8
    """
    if verbose:
        setup_logging(log_level="DEBUG")
    else:
        setup_logging(log_level="INFO")

    console.print(f"\n[bold blue]Privacy Analyzer - Folder Scan[/bold blue]")
    console.print(f"Folder: {folder_path}\n")

    # Validate folder
    if not Path(folder_path).exists():
        console.print(f"[bold red]Error:[/bold red] Folder not found: {folder_path}")
        raise typer.Exit(1)

    # Run analysis
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning folder...", total=None)

        try:
            result = asyncio.run(_scan_folder_async(folder_path, use_llm, max_workers))
            progress.update(task, completed=True)

        except Exception as e:
            progress.stop()
            console.print(f"\n[bold red]Error:[/bold red] {str(e)}")
            logger.exception("Folder scan failed")
            raise typer.Exit(1)

    # Display results
    _display_results(result)

    # Save to file if requested
    if output:
        _save_results(result, output)
        console.print(f"\n[green]Results saved to:[/green] {output}")


async def _scan_folder_async(
    folder_path: str, use_llm: bool = False, max_workers: int = 4
) -> ScanResult:
    """Run folder scan asynchronously."""
    analyzer = BatchAnalyzer(max_workers=max_workers, use_llm=use_llm)
    return await analyzer.analyze(folder_path)


@app.command()
def scan_website(
    url: str = typer.Argument(..., help="Website URL to scan"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file for results (JSON)"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    use_llm: bool = typer.Option(False, "--llm", help="Enable LLM-powered analysis"),
    max_pages: int = typer.Option(10, "--max-pages", help="Maximum pages to scan"),
) -> None:
    """
    Scan a website for privacy issues.

    Example:
        privacy-analyzer scan-website https://example.com
        privacy-analyzer scan-website https://example.com --max-pages 20 -o results.json
    """
    if verbose:
        setup_logging(log_level="DEBUG")
    else:
        setup_logging(log_level="INFO")

    console.print(f"\n[bold blue]Privacy Analyzer - Website Scan[/bold blue]")
    console.print(f"URL: {url}\n")

    # Run analysis
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning website...", total=None)

        try:
            result = asyncio.run(_scan_website_async(url, use_llm, max_pages))
            progress.update(task, completed=True)

        except Exception as e:
            progress.stop()
            console.print(f"\n[bold red]Error:[/bold red] {str(e)}")
            logger.exception("Website scan failed")
            raise typer.Exit(1)

    # Display results
    _display_results(result)

    # Save to file if requested
    if output:
        _save_results(result, output)
        console.print(f"\n[green]Results saved to:[/green] {output}")


async def _scan_website_async(url: str, use_llm: bool = False, max_pages: int = 10) -> ScanResult:
    """Run website scan asynchronously."""
    from src.processors.web_processor import WebProcessor

    analyzer = WebAnalyzer(use_llm=use_llm)
    analyzer.web_processor.max_pages = max_pages
    return await analyzer.analyze(url)


@app.command()
def export(
    scan_file: str = typer.Argument(..., help="Path to scan results JSON file"),
    output: str = typer.Option(..., "--output", "-o", help="Output file"),
    format: str = typer.Option("csv", "--format", "-f", help="Export format (csv, excel)"),
) -> None:
    """
    Export scan results to CSV or Excel.

    Example:
        privacy-analyzer export results.json -o findings.csv
        privacy-analyzer export results.json -o findings.xlsx -f excel
    """
    console.print(f"\n[bold blue]Privacy Analyzer - Export[/bold blue]")
    console.print(f"Input: {scan_file}")
    console.print(f"Output: {output}\n")

    try:
        # Load scan results
        with open(scan_file, "r") as f:
            scan_data = json.load(f)

        scan_result = ScanResult(**scan_data)

        # Export based on format
        if format.lower() == "excel":
            reporter = ExcelReporter()
            reporter.export_findings(scan_result, output)
        else:
            reporter = CSVReporter()
            reporter.export_findings(scan_result, output)

        console.print(f"[green]Export complete:[/green] {output}")

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        logger.exception("Export failed")
        raise typer.Exit(1)


@app.command()
def generate_report(
    scan_file: str = typer.Argument(..., help="Path to scan results JSON file"),
    output: str = typer.Option(..., "--output", "-o", help="Output report file (.html or .pdf)"),
    format: str = typer.Option("html", "--format", "-f", help="Report format (html or pdf)"),
) -> None:
    """
    Generate compliance report from scan results.

    Example:
        privacy-analyzer generate-report results.json -o report.html
        privacy-analyzer generate-report results.json -o report.pdf -f pdf
    """
    console.print(f"\n[bold blue]Privacy Analyzer - Report Generation[/bold blue]")
    console.print(f"Input: {scan_file}")
    console.print(f"Output: {output}\n")

    try:
        # Load scan results
        with open(scan_file, "r") as f:
            scan_data = json.load(f)

        # Reconstruct ScanResult
        scan_result = ScanResult(**scan_data)

        # Run GDPR compliance analysis
        console.print("Analyzing GDPR compliance...")
        gdpr_engine = GDPREngine()
        compliance_data = gdpr_engine.analyze_compliance(scan_result)

        console.print(f"Compliance Score: [bold]{compliance_data['compliance_score']}%[/bold]")
        console.print(f"Status: [bold]{compliance_data['status']}[/bold]")
        console.print(f"Total Violations: [bold]{compliance_data['total_violations']}[/bold]\n")

        # Generate report
        console.print(f"Generating {format.upper()} report...")

        if format.lower() == "pdf":
            reporter = PDFReporter()
            reporter.generate_compliance_report(scan_result, output, compliance_data)
        else:
            reporter = HTMLReporter()
            reporter.generate_compliance_report(scan_result, output, compliance_data)

        console.print(f"[green]Report generated:[/green] {output}")

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        logger.exception("Report generation failed")
        raise typer.Exit(1)


@app.command()
def scan_database(
    connection_string: str = typer.Argument(..., help="Database connection string"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file for results (JSON)"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    use_llm: bool = typer.Option(False, "--llm", help="Enable LLM-powered analysis"),
    max_rows: int = typer.Option(1000, "--max-rows", help="Maximum rows to sample per table"),
) -> None:
    """
    Scan a database for PII and privacy issues.

    Example:
        privacy-analyzer scan-database postgresql://user:pass@localhost/db
        privacy-analyzer scan-database mysql+pymysql://user:pass@localhost/db -o results.json
    """
    if verbose:
        setup_logging(log_level="DEBUG")
    else:
        setup_logging(log_level="INFO")

    console.print(f"\n[bold blue]Privacy Analyzer - Database Scan[/bold blue]")
    console.print(f"Connection: {connection_string.split('@')[-1] if '@' in connection_string else connection_string}\n")

    # Run analysis
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning database...", total=None)

        try:
            result = asyncio.run(_scan_database_async(connection_string, use_llm, max_rows))
            progress.update(task, completed=True)

        except Exception as e:
            progress.stop()
            console.print(f"\n[bold red]Error:[/bold red] {str(e)}")
            logger.exception("Database scan failed")
            raise typer.Exit(1)

    # Display results
    _display_results(result)

    # Save to file if requested
    if output:
        _save_results(result, output)
        console.print(f"\n[green]Results saved to:[/green] {output}")


async def _scan_database_async(
    connection_string: str, use_llm: bool = False, max_rows: int = 1000
) -> ScanResult:
    """Run database scan asynchronously."""
    analyzer = DatabaseAnalyzer(max_rows_sample=max_rows, use_llm=use_llm)
    return await analyzer.analyze(connection_string)


@app.command()
def compare(
    baseline_file: str = typer.Argument(..., help="Baseline scan results JSON file"),
    current_file: str = typer.Argument(..., help="Current scan results JSON file"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file for comparison"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
) -> None:
    """
    Compare two scan results to identify changes.

    Example:
        privacy-analyzer compare baseline.json current.json
        privacy-analyzer compare baseline.json current.json -o comparison.txt
    """
    console.print(f"\n[bold blue]Privacy Analyzer - Scan Comparison[/bold blue]")
    console.print(f"Baseline: {baseline_file}")
    console.print(f"Current: {current_file}\n")

    try:
        # Load scan results
        with open(baseline_file, "r") as f:
            baseline_data = json.load(f)
        baseline = ScanResult(**baseline_data)

        with open(current_file, "r") as f:
            current_data = json.load(f)
        current = ScanResult(**current_data)

        # Compare
        comparator = ScanComparator()
        comparison = comparator.compare(baseline, current)

        # Display summary
        console.print("[bold]Comparison Summary:[/bold]")
        summary_table = Table()
        summary_table.add_column("Metric", style="bold")
        summary_table.add_column("Count", justify="right")

        summary_table.add_row("New Findings", str(comparison["summary"]["new_count"]))
        summary_table.add_row("Resolved Findings", str(comparison["summary"]["resolved_count"]))
        summary_table.add_row("Modified Findings", str(comparison["summary"]["modified_count"]))
        summary_table.add_row("Unchanged Findings", str(comparison["summary"]["unchanged_count"]))

        net_change = comparison["summary"]["net_change"]
        trend = comparison["summary"]["trend"]
        trend_color = "green" if trend == "better" else "red" if trend == "worse" else "yellow"

        summary_table.add_row(
            "Net Change",
            f"[{trend_color}]{net_change:+d} ({trend})[/{trend_color}]"
        )

        console.print(summary_table)

        # Verbose output
        if verbose:
            # New findings
            if comparison["changes"]["new_findings"]:
                console.print("\n[bold red]New Findings:[/bold red]")
                for finding in comparison["changes"]["new_findings"]:
                    console.print(
                        f"  [{finding['severity'].upper()}] {finding['pii_type']} "
                        f"at {finding['location']}"
                    )

            # Resolved findings
            if comparison["changes"]["resolved_findings"]:
                console.print("\n[bold green]Resolved Findings:[/bold green]")
                for finding in comparison["changes"]["resolved_findings"]:
                    console.print(
                        f"  [{finding['severity'].upper()}] {finding['pii_type']} "
                        f"at {finding['location']}"
                    )

        # Save to file if requested
        if output:
            report = comparator.generate_comparison_report(baseline, current)
            with open(output, "w") as f:
                f.write(report)
            console.print(f"\n[green]Comparison saved to:[/green] {output}")

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        logger.exception("Comparison failed")
        raise typer.Exit(1)


@app.command()
def anonymize(
    scan_file: str = typer.Argument(..., help="Path to scan results JSON file"),
    input_file: str = typer.Argument(..., help="Path to file to anonymize"),
    output: str = typer.Option(..., "--output", "-o", help="Output file for anonymized content"),
    strategy: str = typer.Option("mask", "--strategy", "-s", help="Anonymization strategy (mask, redact, hash, generalize)"),
) -> None:
    """
    Anonymize a file based on scan results.

    Example:
        privacy-analyzer anonymize results.json document.txt -o anonymized.txt
        privacy-analyzer anonymize results.json document.txt -o anonymized.txt -s hash
    """
    console.print(f"\n[bold blue]Privacy Analyzer - Anonymization[/bold blue]")
    console.print(f"Input: {input_file}")
    console.print(f"Output: {output}\n")

    try:
        # Load scan results
        with open(scan_file, "r") as f:
            scan_data = json.load(f)
        scan_result = ScanResult(**scan_data)

        # Load input file
        with open(input_file, "r") as f:
            original_text = f.read()

        # Validate strategy
        try:
            anon_strategy = AnonymizationStrategy(strategy.lower())
        except ValueError:
            console.print(f"[bold red]Error:[/bold red] Invalid strategy: {strategy}")
            console.print("Valid strategies: mask, redact, hash, generalize, suppress, synthetic")
            raise typer.Exit(1)

        # Anonymize
        console.print(f"Anonymizing with strategy: [bold]{strategy}[/bold]")
        engine = AnonymizationEngine(default_strategy=anon_strategy)

        anonymized_text = engine.anonymize_text(original_text, scan_result.findings, anon_strategy)

        # Save anonymized content
        with open(output, "w") as f:
            f.write(anonymized_text)

        console.print(f"\n[green]Anonymization complete:[/green] {output}")
        console.print(f"Anonymized {scan_result.total_findings} PII instances")

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        logger.exception("Anonymization failed")
        raise typer.Exit(1)


@app.command()
def test() -> None:
    """Test the analyzer setup."""
    console.print("[bold blue]Testing Privacy Analyzer Setup[/bold blue]\n")

    # Check dependencies
    try:
        from presidio_analyzer import AnalyzerEngine

        console.print("[green]PASS[/green] Presidio installed")
    except ImportError:
        console.print("[red]FAIL[/red] Presidio not installed")

    try:
        import spacy

        console.print("[green]PASS[/green] spaCy installed")

        # Check for language model
        try:
            spacy.load("en_core_web_lg")
            console.print("[green]PASS[/green] spaCy language model (en_core_web_lg) installed")
        except OSError:
            console.print(
                "[yellow]WARN[/yellow] spaCy language model not found. Run: python -m spacy download en_core_web_lg"
            )
    except ImportError:
        console.print("[red]FAIL[/red] spaCy not installed")

    try:
        import pytesseract

        console.print("[green]PASS[/green] Tesseract OCR installed")
    except ImportError:
        console.print("[yellow]WARN[/yellow] Tesseract not installed (OCR disabled)")

    try:
        from anthropic import Anthropic

        console.print("[green]PASS[/green] Anthropic SDK installed")
    except ImportError:
        console.print("[yellow]WARN[/yellow] Anthropic SDK not installed (LLM features disabled)")

    console.print("\n[green]Setup test complete[/green]")


if __name__ == "__main__":
    app()
