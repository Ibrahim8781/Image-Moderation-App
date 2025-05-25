# Use Python 3.11 slim image as base
FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y gcc && rm -rf /var/lib/apt/lists/*

# Copy only requirements first for caching
COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

# Copy all files from root into container's /app
COPY . .

RUN adduser --disabled-password --gecos '' appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 7000

HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:7000/ || exit 1

# Run FastAPI app: main.py has `app` instance
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "7000"]
