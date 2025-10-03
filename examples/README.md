# Privacy Analyzer Examples

This directory contains sample files and usage examples for Privacy Analyzer.

## Sample Files

### sample_document.txt
A sample employee record containing various types of PII including:
- Personal identifiers (SSN, employee ID)
- Contact information (email, phone, address)
- Financial data (salary, bank account)
- Medical information (health insurance, conditions)
- Performance data

Use this file to test the document scanning functionality.

## Usage Examples

### Scan a Single Document

```bash
privacy-analyzer scan-document examples/sample_document.txt
```

### Scan with JSON Output

```bash
privacy-analyzer scan-document examples/sample_document.txt -o results.json
```

### Scan with LLM Enhancement

```bash
export ANTHROPIC_API_KEY=your_key_here
privacy-analyzer scan-document examples/sample_document.txt --llm
```

### Generate Compliance Report

```bash
# First, scan and save results
privacy-analyzer scan-document examples/sample_document.txt -o scan_results.json

# Then generate HTML report
privacy-analyzer generate-report scan_results.json -o compliance_report.html

# Or generate PDF report
privacy-analyzer generate-report scan_results.json -o compliance_report.pdf -f pdf
```

### Export to CSV/Excel

```bash
# Export to CSV
privacy-analyzer export scan_results.json -o findings.csv

# Export to Excel
privacy-analyzer export scan_results.json -o findings.xlsx -f excel
```

### Scan a Website

```bash
privacy-analyzer scan-website https://example.com --max-pages 5
```

### Batch Scan a Folder

```bash
privacy-analyzer scan-folder /path/to/documents --workers 8 -o batch_results.json
```

## Expected Results

When scanning `sample_document.txt`, you should expect to find:

- **PII Types**: SSN, PERSON, EMAIL_ADDRESS, PHONE_NUMBER, DATE_OF_BIRTH, LOCATION
- **GDPR Articles**: Art. 6, Art. 9, Art. 32
- **Severity Levels**: Critical (SSN, medical data), High (financial data), Medium (contact info)

## Custom Configuration

Create a custom configuration file based on `config/config.example.yaml`:

```bash
cp config/config.example.yaml config/config.yaml
```

Edit the configuration to adjust:
- Confidence thresholds
- LLM settings
- Detection patterns
- Reporting options

## Adding Custom Patterns

Customize `config/custom_patterns.yaml` to add organization-specific PII patterns:

```yaml
patterns:
  - name: "INTERNAL_ID"
    description: "Internal reference numbers"
    regex: "INT-\\d{8}"
    severity: "medium"
    confidence: 0.80
```

## Testing the Setup

Run the built-in test command to verify your installation:

```bash
privacy-analyzer test
```

This will check for:
- Presidio installation
- spaCy and language models
- Optional dependencies (OCR, LLM)
