# Privacy Analyzer Docker Image

FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    POETRY_VERSION=1.7.1 \
    POETRY_HOME="/opt/poetry" \
    POETRY_NO_INTERACTION=1 \
    POETRY_VIRTUALENVS_CREATE=false

# Add Poetry to PATH
ENV PATH="$POETRY_HOME/bin:$PATH"

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    tesseract-ocr \
    poppler-utils \
    wkhtmltopdf \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Poetry
RUN curl -sSL https://install.python-poetry.org | python3 -

# Copy dependency files
COPY pyproject.toml poetry.lock ./

# Install Python dependencies
RUN poetry install --no-dev --no-root --extras "all"

# Download spaCy language model
RUN python -m spacy download en_core_web_lg

# Copy application code
COPY . .

# Install the application
RUN poetry install --no-dev

# Create directories for data and output
RUN mkdir -p /data /output

# Set volume mount points
VOLUME ["/data", "/output"]

# Set default command
ENTRYPOINT ["privacy-analyzer"]
CMD ["--help"]
