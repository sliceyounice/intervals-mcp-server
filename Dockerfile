FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Install build dependencies and Python build backend
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       build-essential \
       curl \
    && rm -rf /var/lib/apt/lists/*

# uv exports the locked dependency versions from uv.lock
COPY --from=ghcr.io/astral-sh/uv:0.11.21 /uv /usr/local/bin/uv

# Install Python build tool
RUN pip install --no-cache-dir hatchling

# Copy project files
COPY pyproject.toml pyproject.toml
COPY uv.lock uv.lock
COPY src src
COPY README.md README.md
COPY .env.example .env.example

# Install the exact runtime dependency versions from uv.lock, then the package itself
RUN uv export --locked --no-dev --no-emit-project -o requirements.txt \
    && pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir --no-deps .

# Run as an unprivileged user; /data holds the hosted-mode SQLite database
RUN useradd --create-home --uid 1000 app \
    && mkdir -p /data \
    && chown app:app /data
USER app

# Default command to run the MCP server using stdio transport.
# Hosted (multi-user) mode overrides this; see deploy/docker-compose.yml.
CMD ["mcp", "run", "src/intervals_mcp_server/server.py"]
