FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
# nosemgrep: dockerfile.security.missing-apt-get-clean.remove-package-cache
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    curl \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
# nosemgrep: dockerfile.security.missing-pip-no-cache-dir
RUN pip install --no-cache-dir -r requirements.txt && \
    rm -rf ~/.cache/pip

# Copy application code
COPY . .

# Create non-root user
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

# Expose port
EXPOSE 8000

# Run the application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
