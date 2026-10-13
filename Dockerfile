FROM python:3.12-slim

WORKDIR /app

# Install poetry
RUN pip install --no-cache-dir poetry

# Copy dependency files
COPY pyproject.toml poetry.lock* ./

# Install dependencies (no dev deps)
RUN poetry config virtualenvs.create false \
    && poetry install --no-interaction --no-ansi --only main --no-root

# Copy application code. The reference policies and config templates ship
# inside the package under behavry_proxy/bundled, so there is nothing else
# to copy; mount ./config and ./policies to override them.
COPY behavry_proxy/ ./behavry_proxy/
COPY README.md ./
RUN poetry install --no-interaction --no-ansi --only-root

EXPOSE 8080

CMD ["behavry-proxy", "--host", "0.0.0.0", "--port", "8080"]
