"""Configuration models."""

from typing import Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings."""

    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", case_sensitive=False, extra="ignore"
    )

    # LLM Configuration
    anthropic_api_key: Optional[str] = Field(None, description="Anthropic API key")
    llm_model: str = Field("claude-sonnet-4-5-20250929", description="Claude model to use")
    llm_max_tokens: int = Field(4096, description="Maximum tokens for LLM responses")
    llm_temperature: float = Field(0.0, description="LLM temperature")

    # Performance
    max_sample_size: int = Field(1000, description="Max database rows to sample")
    max_workers: int = Field(4, description="Max concurrent workers")
    request_timeout: int = Field(30, description="Request timeout in seconds")

    # Logging
    log_level: str = Field("INFO", description="Logging level")
    log_file: str = Field("privacy_analyzer.log", description="Log file path")

    # Security
    enable_pii_redaction: bool = Field(True, description="Redact PII in logs")
    report_encryption: bool = Field(False, description="Encrypt generated reports")

    # Database
    db_connection_string: Optional[str] = Field(None, description="Database connection string")

    # OCR
    tesseract_path: Optional[str] = Field(None, description="Path to Tesseract executable")
    ocr_language: str = Field("eng", description="OCR language")

    # Web scraping
    user_agent: str = Field(
        "PrivacyAnalyzer/1.0 (Compliance Scanner)", description="User agent for web requests"
    )
    web_timeout: int = Field(10, description="Web request timeout")
    max_pages_per_site: int = Field(50, description="Max pages to scan per website")


class AnalyzerConfig(BaseSettings):
    """Configuration for specific analyzer types."""

    # Document analyzer
    supported_document_extensions: list = Field(
        default_factory=lambda: [".pdf", ".docx", ".txt", ".doc", ".rtf", ".odt"]
    )
    enable_ocr: bool = Field(True, description="Enable OCR for scanned documents")
    ocr_preprocessing: bool = Field(True, description="Preprocess images before OCR")

    # Database analyzer
    db_sample_strategy: str = Field("random", description="Sampling strategy (random, top, bottom)")
    db_check_encryption: bool = Field(True, description="Check for column encryption")
    db_timeout: int = Field(30, description="Database operation timeout")

    # Web analyzer
    check_cookies: bool = Field(True, description="Analyze cookies")
    check_privacy_policy: bool = Field(True, description="Check for privacy policy")
    follow_links: bool = Field(True, description="Follow internal links")
    respect_robots_txt: bool = Field(True, description="Respect robots.txt")

    # PII Detection
    pii_score_threshold: float = Field(0.5, description="Minimum confidence for PII detection")
    enable_custom_patterns: bool = Field(True, description="Use custom regex patterns")
    languages: list = Field(default_factory=lambda: ["en"], description="Languages to detect")


# Global settings instance
settings: Optional[Settings] = None


def get_settings() -> Settings:
    """Get or create settings instance."""
    global settings
    if settings is None:
        settings = Settings()
    return settings


def get_analyzer_config() -> AnalyzerConfig:
    """Get analyzer configuration."""
    return AnalyzerConfig()
