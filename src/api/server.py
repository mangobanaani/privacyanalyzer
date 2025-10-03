"""FastAPI server for Privacy Analyzer REST API."""

from fastapi import FastAPI, HTTPException, UploadFile, File, BackgroundTasks, Depends
from fastapi.responses import JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, List, Dict
from pathlib import Path
import tempfile
import asyncio
import uuid
from datetime import datetime

from src.analyzers import DocumentAnalyzer, BatchAnalyzer, WebAnalyzer, DatabaseAnalyzer
from src.models import ScanResult
from src.detectors import GDPREngine
from src.anonymizers import AnonymizationEngine, AnonymizationStrategy
from src.reporters import HTMLReporter, PDFReporter, CSVReporter
from src.utils import get_logger, ScanComparator

logger = get_logger(__name__)

# Create FastAPI app
app = FastAPI(
    title="Privacy Analyzer API",
    description="AI-powered PII detection and GDPR compliance API",
    version="1.0.0",
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage for scans (use database in production)
scan_results: Dict[str, ScanResult] = {}
scan_status: Dict[str, str] = {}


# Request/Response Models
class ScanRequest(BaseModel):
    """Request to scan content."""

    content: str = Field(..., description="Content to scan")
    use_llm: bool = Field(False, description="Enable LLM analysis")


class WebScanRequest(BaseModel):
    """Request to scan a website."""

    url: str = Field(..., description="Website URL")
    max_pages: int = Field(10, description="Maximum pages to scan")
    use_llm: bool = Field(False, description="Enable LLM analysis")


class DatabaseScanRequest(BaseModel):
    """Request to scan a database."""

    connection_string: str = Field(..., description="Database connection string")
    max_rows: int = Field(1000, description="Maximum rows to sample per table")
    use_llm: bool = Field(False, description="Enable LLM analysis")


class AnonymizeRequest(BaseModel):
    """Request to anonymize content."""

    scan_id: str = Field(..., description="Scan ID with findings")
    content: str = Field(..., description="Content to anonymize")
    strategy: AnonymizationStrategy = Field(
        AnonymizationStrategy.MASK, description="Anonymization strategy"
    )


class ComplianceRequest(BaseModel):
    """Request for GDPR compliance analysis."""

    scan_id: str = Field(..., description="Scan ID to analyze")


class CompareRequest(BaseModel):
    """Request to compare two scans."""

    baseline_id: str = Field(..., description="Baseline scan ID")
    current_id: str = Field(..., description="Current scan ID")


class ScanResponse(BaseModel):
    """Response with scan ID."""

    scan_id: str
    status: str
    message: str


# Health check
@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}


# Scan text content
@app.post("/scan/text", response_model=ScanResponse)
async def scan_text(request: ScanRequest, background_tasks: BackgroundTasks):
    """
    Scan text content for PII.

    Args:
        request: Scan request with content
        background_tasks: Background task handler

    Returns:
        Scan ID and status
    """
    scan_id = str(uuid.uuid4())
    scan_status[scan_id] = "pending"

    # Run scan in background
    background_tasks.add_task(
        _run_text_scan, scan_id, request.content, request.use_llm
    )

    return ScanResponse(
        scan_id=scan_id,
        status="pending",
        message="Scan started. Use /scan/{scan_id} to check status.",
    )


# Scan uploaded file
@app.post("/scan/file", response_model=ScanResponse)
async def scan_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    use_llm: bool = False,
):
    """
    Scan uploaded file for PII.

    Args:
        file: Uploaded file
        use_llm: Enable LLM analysis
        background_tasks: Background task handler

    Returns:
        Scan ID and status
    """
    scan_id = str(uuid.uuid4())
    scan_status[scan_id] = "pending"

    # Save uploaded file temporarily
    with tempfile.NamedTemporaryFile(delete=False, suffix=Path(file.filename).suffix) as tmp:
        content = await file.read()
        tmp.write(content)
        tmp_path = tmp.name

    # Run scan in background
    background_tasks.add_task(_run_file_scan, scan_id, tmp_path, use_llm)

    return ScanResponse(
        scan_id=scan_id,
        status="pending",
        message=f"Scanning {file.filename}. Use /scan/{scan_id} to check status.",
    )


# Scan website
@app.post("/scan/website", response_model=ScanResponse)
async def scan_website(request: WebScanRequest, background_tasks: BackgroundTasks):
    """
    Scan website for privacy issues.

    Args:
        request: Web scan request
        background_tasks: Background task handler

    Returns:
        Scan ID and status
    """
    scan_id = str(uuid.uuid4())
    scan_status[scan_id] = "pending"

    background_tasks.add_task(
        _run_web_scan, scan_id, request.url, request.max_pages, request.use_llm
    )

    return ScanResponse(
        scan_id=scan_id,
        status="pending",
        message=f"Scanning {request.url}. Use /scan/{scan_id} to check status.",
    )


# Scan database
@app.post("/scan/database", response_model=ScanResponse)
async def scan_database(request: DatabaseScanRequest, background_tasks: BackgroundTasks):
    """
    Scan database for PII.

    Args:
        request: Database scan request
        background_tasks: Background task handler

    Returns:
        Scan ID and status
    """
    scan_id = str(uuid.uuid4())
    scan_status[scan_id] = "pending"

    background_tasks.add_task(
        _run_database_scan,
        scan_id,
        request.connection_string,
        request.max_rows,
        request.use_llm,
    )

    return ScanResponse(
        scan_id=scan_id,
        status="pending",
        message="Database scan started. Use /scan/{scan_id} to check status.",
    )


# Get scan result
@app.get("/scan/{scan_id}")
async def get_scan_result(scan_id: str):
    """
    Get scan result by ID.

    Args:
        scan_id: Scan identifier

    Returns:
        Scan result
    """
    if scan_id not in scan_status:
        raise HTTPException(status_code=404, detail="Scan not found")

    status = scan_status[scan_id]

    if status == "pending":
        return {"scan_id": scan_id, "status": "pending", "message": "Scan in progress"}

    if status == "failed":
        return {"scan_id": scan_id, "status": "failed", "message": "Scan failed"}

    if scan_id in scan_results:
        result = scan_results[scan_id]
        return {
            "scan_id": scan_id,
            "status": "completed",
            "result": result.model_dump(),
        }

    return {"scan_id": scan_id, "status": "unknown"}


# List all scans
@app.get("/scans")
async def list_scans(limit: int = 50):
    """
    List all scans.

    Args:
        limit: Maximum number of scans to return

    Returns:
        List of scans
    """
    scans = []
    for scan_id, status in list(scan_status.items())[:limit]:
        scan_info = {
            "scan_id": scan_id,
            "status": status,
        }

        if scan_id in scan_results:
            result = scan_results[scan_id]
            scan_info["total_findings"] = result.total_findings
            scan_info["timestamp"] = result.timestamp.isoformat() if result.timestamp else None

        scans.append(scan_info)

    return {"scans": scans, "total": len(scan_status)}


# Anonymize content
@app.post("/anonymize")
async def anonymize_content(request: AnonymizeRequest):
    """
    Anonymize content based on scan results.

    Args:
        request: Anonymization request

    Returns:
        Anonymized content
    """
    if request.scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")

    result = scan_results[request.scan_id]
    engine = AnonymizationEngine(default_strategy=request.strategy)

    anonymized = engine.anonymize_text(request.content, result.findings, request.strategy)

    return {
        "anonymized_content": anonymized,
        "pii_count": result.total_findings,
        "strategy": request.strategy,
    }


# GDPR compliance analysis
@app.post("/compliance")
async def analyze_compliance(request: ComplianceRequest):
    """
    Analyze GDPR compliance for scan results.

    Args:
        request: Compliance request

    Returns:
        Compliance analysis
    """
    if request.scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")

    result = scan_results[request.scan_id]
    engine = GDPREngine()

    compliance = engine.analyze_compliance(result)

    return compliance


# Compare scans
@app.post("/compare")
async def compare_scans(request: CompareRequest):
    """
    Compare two scan results.

    Args:
        request: Compare request

    Returns:
        Comparison result
    """
    if request.baseline_id not in scan_results:
        raise HTTPException(status_code=404, detail="Baseline scan not found")

    if request.current_id not in scan_results:
        raise HTTPException(status_code=404, detail="Current scan not found")

    baseline = scan_results[request.baseline_id]
    current = scan_results[request.current_id]

    comparator = ScanComparator()
    comparison = comparator.compare(baseline, current)

    return comparison


# Export results
@app.get("/export/{scan_id}/{format}")
async def export_results(scan_id: str, format: str):
    """
    Export scan results in various formats.

    Args:
        scan_id: Scan identifier
        format: Export format (csv, html, pdf)

    Returns:
        File download
    """
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")

    result = scan_results[scan_id]

    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = Path(tmpdir) / f"export.{format}"

        if format == "csv":
            reporter = CSVReporter()
            reporter.export_findings(result, str(output_path))
            return FileResponse(output_path, media_type="text/csv", filename=f"findings_{scan_id}.csv")

        elif format == "html":
            reporter = HTMLReporter()
            gdpr_engine = GDPREngine()
            compliance = gdpr_engine.analyze_compliance(result)
            reporter.generate_compliance_report(result, str(output_path), compliance)
            return FileResponse(output_path, media_type="text/html", filename=f"report_{scan_id}.html")

        elif format == "pdf":
            reporter = PDFReporter()
            gdpr_engine = GDPREngine()
            compliance = gdpr_engine.analyze_compliance(result)
            reporter.generate_compliance_report(result, str(output_path), compliance)
            return FileResponse(output_path, media_type="application/pdf", filename=f"report_{scan_id}.pdf")

        else:
            raise HTTPException(status_code=400, detail=f"Unsupported format: {format}")


# Background task functions
async def _run_text_scan(scan_id: str, content: str, use_llm: bool):
    """Run text scan in background."""
    try:
        # Save content to temp file
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as tmp:
            tmp.write(content)
            tmp_path = tmp.name

        analyzer = DocumentAnalyzer(use_llm=use_llm)
        result = await analyzer.analyze(tmp_path)

        scan_results[scan_id] = result
        scan_status[scan_id] = "completed"

        # Cleanup
        Path(tmp_path).unlink()

    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {e}")
        scan_status[scan_id] = "failed"


async def _run_file_scan(scan_id: str, file_path: str, use_llm: bool):
    """Run file scan in background."""
    try:
        analyzer = DocumentAnalyzer(use_llm=use_llm)
        result = await analyzer.analyze(file_path)

        scan_results[scan_id] = result
        scan_status[scan_id] = "completed"

        # Cleanup temp file
        Path(file_path).unlink()

    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {e}")
        scan_status[scan_id] = "failed"


async def _run_web_scan(scan_id: str, url: str, max_pages: int, use_llm: bool):
    """Run web scan in background."""
    try:
        analyzer = WebAnalyzer(use_llm=use_llm)
        analyzer.web_processor.max_pages = max_pages
        result = await analyzer.analyze(url)

        scan_results[scan_id] = result
        scan_status[scan_id] = "completed"

    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {e}")
        scan_status[scan_id] = "failed"


async def _run_database_scan(
    scan_id: str, connection_string: str, max_rows: int, use_llm: bool
):
    """Run database scan in background."""
    try:
        analyzer = DatabaseAnalyzer(max_rows_sample=max_rows, use_llm=use_llm)
        result = await analyzer.analyze(connection_string)

        scan_results[scan_id] = result
        scan_status[scan_id] = "completed"

    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {e}")
        scan_status[scan_id] = "failed"


def run_server():
    """Run the API server (entry point for poetry script)."""
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)


if __name__ == "__main__":
    run_server()
