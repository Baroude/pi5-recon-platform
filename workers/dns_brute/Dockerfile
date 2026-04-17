# ---------------------------------------------------------------------------
# DNS brute-force worker — Python + dnsx + shuffledns + alterx (ARM64)
# ---------------------------------------------------------------------------
FROM --platform=linux/arm64 python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl unzip \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://github.com/projectdiscovery/dnsx/releases/download/v1.2.1/dnsx_1.2.1_linux_arm64.zip \
        -o /tmp/dnsx.zip \
    && unzip -j /tmp/dnsx.zip dnsx -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/dnsx \
    && rm /tmp/dnsx.zip

RUN curl -fsSL https://github.com/projectdiscovery/shuffledns/releases/download/v1.1.0/shuffledns_1.1.0_linux_arm64.zip \
        -o /tmp/shuffledns.zip \
    && unzip -j /tmp/shuffledns.zip shuffledns -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/shuffledns \
    && rm /tmp/shuffledns.zip

RUN curl -fsSL https://github.com/projectdiscovery/alterx/releases/download/v0.0.4/alterx_0.0.4_linux_arm64.zip \
        -o /tmp/alterx.zip \
    && unzip -j /tmp/alterx.zip alterx -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/alterx \
    && rm /tmp/alterx.zip

WORKDIR /app

ARG CACHE_BUST=1
COPY workers/common /app/common
COPY workers/dns_brute/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY workers/dns_brute/worker.py .

RUN mkdir -p /data/db /data/output /logs

CMD ["python", "worker.py"]
