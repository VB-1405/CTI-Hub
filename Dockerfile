FROM python:3.11-slim

LABEL maintainer="CTI Hub"
LABEL description="Multi-engine Cyber Threat Intelligence platform"
LABEL version="2.0.0"

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY backend.py .
COPY static/ ./static/

# Create data directories
RUN mkdir -p /data/capa_cache

# Environment defaults (override in docker-compose.yml)
ENV CAPA_CACHE=/data/capa_cache
ENV PYTHONUNBUFFERED=1

# Expose port
EXPOSE 5000

# Run with gunicorn for production
CMD ["python", "-m", "gunicorn", \
     "--workers", "4", \
     "--bind", "0.0.0.0:5000", \
     "--timeout", "300", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "backend:app"]
