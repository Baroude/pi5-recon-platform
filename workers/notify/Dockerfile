FROM --platform=linux/arm64 python:3.12-slim

WORKDIR /app

COPY workers/notify/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt
RUN mkdir -p /logs

# Shared helpers
COPY workers/common /app/common

# Worker source
COPY workers/notify/worker.py /app/worker.py

CMD ["python", "-u", "worker.py"]
