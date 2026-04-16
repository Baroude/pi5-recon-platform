FROM python:3.11-slim

WORKDIR /app

COPY workers/notify/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Shared helpers
COPY workers/common /app/common

# Worker source
COPY workers/notify/worker.py /app/worker.py

CMD ["python", "-u", "worker.py"]
