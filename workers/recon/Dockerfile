# ---------------------------------------------------------------------------
# Recon worker image — Python + subfinder + amass (ARM64)
#
# Multi-stage: copy binaries from official images.
# ---------------------------------------------------------------------------
# Pin to specific version — update deliberately after testing
FROM --platform=linux/arm64 python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl unzip musl \
    && ln -s /usr/lib/aarch64-linux-musl/libc.so /usr/lib/libc.musl-aarch64.so.1 \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_arm64.zip \
        -o /tmp/subfinder.zip \
    && unzip -j /tmp/subfinder.zip subfinder -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/subfinder \
    && rm /tmp/subfinder.zip

# Download amass ARM64 binary directly from GitHub releases (avoids ghcr.io auth issues)
RUN curl -fsSL https://github.com/owasp-amass/amass/releases/download/v4.2.0/amass_Linux_arm64.zip \
        -o /tmp/amass.zip \
    && unzip -j /tmp/amass.zip "amass_Linux_arm64/amass" -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/amass \
    && rm /tmp/amass.zip

WORKDIR /app

ARG CACHE_BUST=1
COPY workers/common /app/common
COPY workers/recon/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY workers/recon/worker.py .
COPY workers/recon/entrypoint.sh .
RUN chmod +x /app/entrypoint.sh

RUN mkdir -p /data/db /data/output /logs

ENTRYPOINT ["/app/entrypoint.sh"]
