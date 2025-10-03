# Privacy Analyzer Examples

This directory contains example files and sample outputs for Privacy Analyzer.

## Files

### Sample Documents

- **sample_document.txt**: Employee record with various PII types
  - Personal identifiers (name, SSN, employee ID)
  - Contact information (email, phone, address)
  - Financial data (salary, bank account)
  - Medical information (health insurance, conditions)
  - Performance review data

### Running Examples

Before running examples, ensure you have installed Privacy Analyzer:

```bash
# Install dependencies
poetry install

# Or with all optional features
poetry install --extras all

# Install spaCy language model
python -m spacy download en_core_web_lg
```

## Example Workflows

### Basic Document Scan

```bash
# Scan the sample document
poetry run privacy-analyzer scan-document examples/sample_document.txt

# Scan with output to JSON
poetry run privacy-analyzer scan-document examples/sample_document.txt -o scan_results.json
```

Expected findings:
- SSN (123-45-6789) - CRITICAL
- Email addresses - MEDIUM
- Phone numbers - MEDIUM
- Names - MEDIUM
- Bank account - CRITICAL
- Medical info - CRITICAL

### Generate Compliance Report

```bash
# First scan the document
poetry run privacy-analyzer scan-document examples/sample_document.txt -o results.json

# Generate HTML compliance report
poetry run privacy-analyzer generate-report results.json -o compliance_report.html

# Generate PDF report
poetry run privacy-analyzer generate-report results.json -o compliance_report.pdf -f pdf
```

The report will include:
- Executive summary
- Compliance score
- GDPR violations by article
- Detailed findings
- Remediation recommendations

### Export to CSV/Excel

```bash
# Export findings to CSV
poetry run privacy-analyzer export results.json -o findings.csv

# Export to Excel (requires openpyxl)
poetry run privacy-analyzer export results.json -o findings.xlsx -f excel
```

### Compare Scan Results

```bash
# Scan baseline
poetry run privacy-analyzer scan-document examples/sample_document.txt -o baseline.json

# Make changes to document and scan again
poetry run privacy-analyzer scan-document examples/sample_document.txt -o current.json

# Compare the two scans
poetry run privacy-analyzer compare baseline.json current.json -v

# Save comparison to file
poetry run privacy-analyzer compare baseline.json current.json -o comparison.txt
```

### Batch Folder Scan

```bash
# Create a folder with multiple documents
mkdir test_docs
cp examples/sample_document.txt test_docs/doc1.txt
cp examples/sample_document.txt test_docs/doc2.txt

# Scan the entire folder
poetry run privacy-analyzer scan-folder test_docs -o batch_results.json

# Use more workers for faster processing
poetry run privacy-analyzer scan-folder test_docs --workers 8
```

### Website Privacy Scan

```bash
# Scan a website for privacy issues
poetry run privacy-analyzer scan-website https://example.com

# Scan with more pages
poetry run privacy-analyzer scan-website https://example.com --max-pages 20 -o web_scan.json
```

The website scan will check for:
- Cookie usage and classification
- Form PII collection
- Privacy policy links
- HTTPS and security headers

### LLM-Enhanced Analysis

```bash
# Set your Anthropic API key
export ANTHROPIC_API_KEY=your_key_here

# Run scan with LLM enhancement
poetry run privacy-analyzer scan-document examples/sample_document.txt --llm -o llm_results.json
```

LLM enhancement provides:
- Context-aware PII detection
- Better severity assessment
- Detailed recommendations
- GDPR article mapping

## Testing Your Setup

```bash
# Run the built-in test command
poetry run privacy-analyzer test
```

This will verify:
- Presidio installation
- spaCy and language models
- OCR capabilities (pytesseract)
- LLM integration (Anthropic SDK)

## Custom Configuration

### Using Custom Patterns

Edit `config/custom_patterns.yaml` to add your organization's patterns:

```yaml
patterns:
  - name: "INTERNAL_ID"
    description: "Internal reference numbers"
    regex: "INT-\\d{8}"
    severity: "medium"
    confidence: 0.80
```

### Using Config File

Create `config/config.yaml` from the example:

```bash
cp config/config.example.yaml config/config.yaml
```

Edit settings:
- Confidence thresholds
- LLM model selection
- OCR settings
- Web scanning options

## Advanced Examples

### Programmatic Usage

```python
import asyncio
from src.analyzers import DocumentAnalyzer

async def scan_document():
    analyzer = DocumentAnalyzer(use_llm=False)
    result = await analyzer.analyze("examples/sample_document.txt")

    print(f"Total findings: {result.total_findings}")
    print(f"By severity: {result.findings_by_severity}")

    for finding in result.findings:
        print(f"{finding.pii_type} at {finding.location}: {finding.severity}")

asyncio.run(scan_document())
```

### Batch Processing with Progress

```python
import asyncio
from src.analyzers import BatchAnalyzer

async def batch_scan():
    analyzer = BatchAnalyzer(max_workers=4, use_llm=False)
    result = await analyzer.analyze("test_docs/")

    stats = analyzer.get_statistics(result)
    print(f"Scanned {stats['files_with_findings']} files")
    print(f"Total findings: {stats['total_findings']}")

asyncio.run(batch_scan())
```

### GDPR Compliance Check

```python
from src.detectors import GDPREngine
from src.models import ScanResult
import json

# Load scan results
with open("results.json", "r") as f:
    data = json.load(f)
    result = ScanResult(**data)

# Analyze GDPR compliance
engine = GDPREngine()
compliance = engine.analyze_compliance(result)

print(f"Compliance score: {compliance['compliance_score']}%")
print(f"Status: {compliance['status']}")
print(f"Violations: {compliance['total_violations']}")

for violation in compliance['violations']:
    print(f"  {violation['rule']}: {violation['description']}")
```

## Expected Output Examples

### Sample Scan Output

```
Privacy Analyzer - Document Scan
File: examples/sample_document.txt

✓ Analyzing document... Done

Scan Results
Status: completed
Duration: 1.23s
Total Findings: 15

Findings by Severity:
CRITICAL    4
HIGH        3
MEDIUM      6
LOW         2

Findings by Type:
SSN             1
EMAIL_ADDRESS   1
PHONE_NUMBER    2
PERSON          3
LOCATION        2
...
```

### Sample Comparison Output

```
SCAN COMPARISON REPORT
================================================================================

Baseline Scan: scan-abc123
  Timestamp: 2024-01-15 10:00:00
  Total Findings: 15

Current Scan: scan-def456
  Timestamp: 2024-01-15 11:00:00
  Total Findings: 12

SUMMARY
--------------------------------------------------------------------------------
  New Findings:       2
  Resolved Findings:  5
  Modified Findings:  1
  Unchanged Findings: 10
  Net Change:         -3
  Trend:              BETTER
```

## Troubleshooting

### Common Issues

1. **spaCy model not found**
   ```bash
   python -m spacy download en_core_web_lg
   ```

2. **Tesseract not installed** (for OCR)
   ```bash
   # macOS
   brew install tesseract

   # Ubuntu/Debian
   sudo apt-get install tesseract-ocr
   ```

3. **wkhtmltopdf not found** (for PDF reports)
   ```bash
   # macOS
   brew install wkhtmltopdf

   # Ubuntu/Debian
   sudo apt-get install wkhtmltopdf
   ```

4. **LLM features not working**
   - Ensure ANTHROPIC_API_KEY is set
   - Check API key is valid
   - Use --llm flag to enable

## Performance Tips

- Use `--workers` to increase parallelism for batch scans
- Disable LLM for faster scanning (--llm flag)
- Use confidence threshold to reduce false positives
- Limit `--max-pages` for website scans

## Next Steps

- Review generated reports
- Customize GDPR rules in `config/rules/gdpr_rules.yaml`
- Add custom PII patterns for your organization
- Integrate with CI/CD pipelines
- Schedule regular scans
