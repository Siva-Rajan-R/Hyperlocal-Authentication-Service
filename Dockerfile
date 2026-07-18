FROM python:3.13-slim

WORKDIR /app

# Ensure we don't write pyc files and we run unbuffered
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install system dependencies required for pip packages (e.g. git for git+https)
RUN apt-get update && apt-get install -y \
    git \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first to leverage Docker cache
COPY requirements.txt .

# Install dependencies and explicitly install gunicorn so it's always available
RUN pip install --no-cache-dir --upgrade pip gunicorn && \
    pip install --no-cache-dir -r requirements.txt

# Copy the actual service code
COPY . .

# Expose the internal port (defaulting to 8000)
EXPOSE 8000

# Start Gunicorn with Uvicorn workers for production readiness
CMD ["gunicorn", "main:app", "--workers", "1", "--worker-class", "uvicorn.workers.UvicornWorker", "--bind", "0.0.0.0:8000"]