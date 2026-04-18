# ---------------------------------------------------------------------------
# Intel worker image - Python + amass (ARM64)
# ---------------------------------------------------------------------------
FROM --platform=linux/arm64 python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl unzip \
    && rm -rf /var/lib/apt/lists/*

# Install amass ARM64 binary (same version as worker-recon)
RUN curl -fsSL https://github.com/owasp-amass/amass/releases/download/v4.2.0/amass_Linux_arm64.zip \
        -o /tmp/amass.zip \
    && unzip -j /tmp/amass.zip "amass_Linux_arm64/amass" -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/amass \
    && rm /tmp/amass.zip

WORKDIR /app

ARG CACHE_BUST=1
COPY workers/common /app/common
COPY workers/intel/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY workers/intel/worker.py .
COPY workers/intel/entrypoint.sh .
RUN chmod +x /app/entrypoint.sh

RUN mkdir -p /data/db /logs

ENTRYPOINT ["/app/entrypoint.sh"]
