.PHONY: install dev-install test lint format clean run help

help:
	@echo "Privacy Analyzer - Development Commands"
	@echo ""
	@echo "Setup:"
	@echo "  make install      Install production dependencies"
	@echo "  make dev-install  Install development dependencies"
	@echo ""
	@echo "Development:"
	@echo "  make test         Run test suite"
	@echo "  make lint         Run linters (ruff, mypy)"
	@echo "  make format       Format code (black, ruff)"
	@echo "  make clean        Remove generated files"
	@echo ""
	@echo "Run:"
	@echo "  make run          Run test command"

install:
	poetry install --no-dev
	poetry run python -m spacy download en_core_web_lg

dev-install:
	poetry install
	poetry run python -m spacy download en_core_web_lg

test:
	poetry run pytest tests/ -v --cov=src --cov-report=html

lint:
	poetry run ruff check src/
	poetry run mypy src/

format:
	poetry run black src/ tests/
	poetry run ruff check --fix src/

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	find . -type d -name ".mypy_cache" -exec rm -rf {} +
	find . -type d -name ".ruff_cache" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf htmlcov/
	rm -rf dist/
	rm -rf build/

run:
	poetry run python -m src.cli.main test
