FROM --platform=linux/arm64 python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY workers/common /app/common
COPY ingestor/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ingestor/app.py .

RUN mkdir -p /data/db /logs

EXPOSE 8090
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8090", "--log-level", "info"]
