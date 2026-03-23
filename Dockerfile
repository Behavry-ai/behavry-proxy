FROM python:3.12-slim

WORKDIR /app

# Install poetry
RUN pip install --no-cache-dir poetry

# Copy dependency files
COPY pyproject.toml poetry.lock* ./

# Install dependencies (no dev deps)
RUN poetry config virtualenvs.create false \
    && poetry install --no-interaction --no-ansi --only main

# Copy application code
COPY behavry_proxy/ ./behavry_proxy/
COPY config/ ./config/
COPY policies/ ./policies/

EXPOSE 8080

# Default: start the proxy
CMD ["python", "-m", "uvicorn", "behavry_proxy.main:app", "--host", "0.0.0.0", "--port", "8080"]
