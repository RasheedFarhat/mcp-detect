# MCP-DETECT agent image: the only place MCP client/proxy code and the MCP
# server runtimes (Node for npx-based servers, uv for uvx-based servers) run.
# Host Python/Node are never load-bearing — everything needed to spawn a
# benign MCP session lives in this image. Pin every version explicitly;
# verified live on 2026-07-08 (see README.md).
FROM python:3.12-slim-bookworm

# Node.js 20.x LTS, for npx-based servers (filesystem, memory).
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates git ssh \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

# uv, for uvx-based servers (fetch, git, time) — installs into /usr/local/bin.
COPY --from=ghcr.io/astral-sh/uv:0.7.13 /uv /uvx /usr/local/bin/

WORKDIR /app

RUN pip install --no-cache-dir "mcp==1.28.1" jsonschema httpx

# Pre-warm npm/uv caches at build time so a session never needs network
# access at runtime beyond talking to Ollama/Wazuh on the compose network.
RUN npx -y @modelcontextprotocol/server-filesystem@2026.7.4 --help >/dev/null 2>&1 || true
RUN npx -y @modelcontextprotocol/server-memory@2026.7.4 --help >/dev/null 2>&1 || true
RUN uv tool install mcp-server-fetch==2026.6.4 \
    && uv tool install mcp-server-git==2026.6.16 \
    && uv tool install mcp-server-time==2026.6.4
ENV PATH="/root/.local/bin:${PATH}"

COPY proxy/ /app/proxy/
COPY client/ /app/client/
COPY schema/ /app/schema/
COPY corpus/ /app/corpus/
COPY attacks/ /app/attacks/

CMD ["sleep", "infinity"]
