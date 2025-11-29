# Stage 1: take Traefik binary from official image
FROM traefik:v3.0.0 AS traefik-base

# Stage 2: Python + Traefik + dockdns agent
FROM python:3.12-slim

# Copy Traefik binary into this image
COPY --from=traefik-base /usr/local/bin/traefik /usr/local/bin/traefik

# Workdir for the agent
WORKDIR /app

# Copy Python agent + requirements
COPY agent.py /app/agent.py
COPY requirements.txt /app/requirements.txt

# Copy Traefik static config
COPY traefik.yml /etc/traefik/traefik.yml

# Install Python deps
RUN pip install --no-cache-dir -r /app/requirements.txt

# Traefik dynamic config directory (will be written by agent)
RUN mkdir -p /etc/traefik/dynamic

# Simple entrypoint to start agent + Traefik together
RUN printf '%s\n' \
  '#!/bin/sh' \
  'set -e' \
  'echo "[dockdns] starting agent..."' \
  'python /app/agent.py & ' \
  'echo "[traefik] starting..."' \
  'exec traefik --configFile=/etc/traefik/traefik.yml' \
  > /entrypoint.sh \
  && chmod +x /entrypoint.sh

EXPOSE 80 8080

ENTRYPOINT ["/entrypoint.sh"]
