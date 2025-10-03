"""Setup script for Privacy Analyzer."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="privacy-analyzer",
    version="0.1.0",
    author="Privacy Analyzer Team",
    description="AI-powered privacy analyzer for PII detection and GDPR compliance",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/privacy-analyzer",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.10",
    install_requires=[
        "presidio-analyzer>=2.2.0",
        "presidio-anonymizer>=2.2.0",
        "spacy>=3.7.0",
        "anthropic>=0.18.0",
        "pytesseract>=0.3.10",
        "pdf2image>=1.17.0",
        "PyMuPDF>=1.23.0",
        "python-docx>=1.1.0",
        "openpyxl>=3.1.0",
        "Pillow>=10.2.0",
        "requests>=2.31.0",
        "beautifulsoup4>=4.12.0",
        "playwright>=1.41.0",
        "lxml>=5.1.0",
        "SQLAlchemy>=2.0.0",
        "psycopg2-binary>=2.9.9",
        "pymysql>=1.1.0",
        "pyodbc>=5.0.0",
        "pandas>=2.2.0",
        "pydantic>=2.6.0",
        "pydantic-settings>=2.1.0",
        "python-dotenv>=1.0.0",
        "loguru>=0.7.0",
        "rich>=13.7.0",
        "typer>=0.9.0",
        "jinja2>=3.1.0",
        "matplotlib>=3.8.0",
        "seaborn>=0.13.0",
    ],
    extras_require={
        "dev": [
            "pytest>=8.0.0",
            "pytest-asyncio>=0.23.0",
            "pytest-cov>=4.1.0",
            "black>=24.1.0",
            "ruff>=0.2.0",
            "mypy>=1.8.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "privacy-analyzer=src.cli.main:app",
        ],
    },
)
