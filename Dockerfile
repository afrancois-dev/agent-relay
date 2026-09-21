# syntax=docker/dockerfile:1

# uv's official image ships uv plus a matching CPython (3.11 per .python-version).
FROM ghcr.io/astral-sh/uv:python3.11-bookworm-slim

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PYTHONUNBUFFERED=1 \
    RELAY_DATABASE_URL=sqlite:////data/agent-relay.db

WORKDIR /app

# Dependencies first so editing application code does not invalidate this layer.
# pyproject.toml has no [build-system], so `uv sync` only provisions the venv;
# it never tries to build/install the project itself.
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen

# Application source. `.dockerignore` keeps tests, git metadata, and the host
# venv out of the build context.
COPY main.py database.py storage.py schemas.py worker.py dashboard.py errors.py dashboard.html ./

# Keep the SQLite queue on a volume so queued/processing tasks survive restarts.
RUN mkdir -p /data
VOLUME ["/data"]

EXPOSE 8000

# /health is the documented liveness check and needs no credentials.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).status == 200 else 1)"

# Call the venv directly so the runtime image does not depend on uv re-resolving.
CMD [".venv/bin/uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
