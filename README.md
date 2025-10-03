# Privacy Analyzer

Data loss prevention and GDPR compliance tool for identifying sensitive information across documents, databases, and web applications.

## What It Does

Scans your data sources to find personally identifiable information (PII) and flags potential compliance issues. Works with documents, databases, and websites. Designed for security teams, compliance officers, and developers who need to audit where sensitive data lives.

## Quick Start

```bash
# Install
poetry install
poetry run python -m spacy download en_core_web_lg

# Scan a folder
poetry run privacy-analyzer scan-folder ./documents -o results.json

# Scan a database
poetry run privacy-analyzer scan-database "postgresql://localhost/mydb"

# Generate report
poetry run privacy-analyzer report results.json --format html -o report.html
```

## Requirements

- Python 3.10+
- Tesseract OCR (optional, for image processing)

## Installation

**Poetry:**
```bash
poetry install
poetry install -E database  # For database scanning
poetry install -E web       # For website analysis
```

**pip:**
```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Supported Data Sources

**Documents:**
- PDF (including scanned documents via OCR)
- Microsoft Word (.docx, .doc)
- Excel (.xlsx, .xls)
- Email files (.eml, .msg)
- Plain text
- Images (PNG, JPG, TIFF, BMP)

**Databases:**
- PostgreSQL
- MySQL
- SQLite
- Microsoft SQL Server

**Web:**
- HTML pages
- Forms
- Cookies
- Security headers

## What Gets Detected

**Nordic Countries:**
- Finnish Henkilötunnus (with checksum validation)
- Swedish Personnummer (Luhn algorithm)
- Norwegian Fødselsnummer (dual checksum)
- Danish CPR

**EU/UK:**
- UK National Insurance Numbers
- EU VAT Numbers
- IBAN bank accounts
- BIC/SWIFT codes

**US:**
- Social Security Numbers
- Driver's licenses
- Passport numbers

**Financial:**
- Credit card numbers
- Bank account numbers
- Cryptocurrency addresses

**Contact:**
- Email addresses
- Phone numbers
- Physical addresses

**Other:**
- IP addresses
- MAC addresses
- GPS coordinates
- Names and organizations

## Configuration

Create `.env`:
```env
# Optional: Enable AI-powered analysis
ANTHROPIC_API_KEY=your_key_here

# Logging
LOG_LEVEL=INFO
ENABLE_PII_REDACTION=true
```

## Usage Examples

**Scan folder with parallel processing:**
```bash
privacy-analyzer scan-folder ./data --workers 8 -o scan.json
```

**Database audit:**
```bash
privacy-analyzer scan-database \
  "postgresql://user:pass@localhost/db" \
  --tables users,orders,payments
```

**Website privacy check:**
```bash
privacy-analyzer scan-website https://yoursite.com --max-pages 50
```

**Generate compliance report:**
```bash
privacy-analyzer report scan.json --format pdf -o compliance-report.pdf
```

## Output Formats

- **JSON** - Raw scan data
- **HTML** - Interactive web report
- **PDF** - Executive summary
- **CSV** - Spreadsheet import

## API Server

```bash
# Start server
poetry run privacy-analyzer-server

# Or with production settings
gunicorn src.api.server:app \
  --workers 4 \
  --worker-class uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:8000
```

Access documentation at `http://localhost:8000/docs`

## Programmatic Usage

```python
from src.analyzers.document_analyzer import DocumentAnalyzer

analyzer = DocumentAnalyzer()
result = await analyzer.analyze("sensitive.pdf")

for finding in result.findings:
    print(f"{finding.pii_type} found at {finding.location}")
    print(f"Severity: {finding.severity}")
    print(f"GDPR: {finding.gdpr_articles}")
```

## GDPR Mapping

Findings are mapped to relevant articles:
- **Art. 5** - Data minimization principles
- **Art. 6** - Lawful processing basis
- **Art. 9** - Special category data (health, biometric)
- **Art. 32** - Security requirements

## Security

- PII values are redacted from all logs
- Database connections use read-only mode
- No sensitive data is persisted
- API keys stored in environment variables only

## Performance

For large-scale scanning:
- Use `--workers` to set parallel processing threads
- Database scanner samples tables intelligently
- LLM features cache responses to reduce costs
- PDF processing uses memory-efficient chunking

## Testing

```bash
# Run full test suite
poetry run pytest

# With coverage report
poetry run pytest --cov=src --cov-report=html

# Parallel execution
poetry run pytest -n auto
```

Current test coverage: 160+ tests passing

## Development

**Code formatting:**
```bash
poetry run black src/ tests/
```

**Type checking:**
```bash
poetry run mypy src/
```

**Linting:**
```bash
poetry run flake8 src/ tests/
```

## Docker

```bash
docker build -t privacy-analyzer .
docker run -v $(pwd)/data:/data privacy-analyzer scan-folder /data
```

## Known Limitations

- OCR accuracy depends on image quality
- Website scanning respects robots.txt
- Database sampling may miss rare PII patterns
- LLM features require external API access

## License

MIT

## Contributing

Pull requests welcome. Run tests and linting before submitting.
