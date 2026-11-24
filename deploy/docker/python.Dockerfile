# Skyline API and worker images (one build, two targets). Build from the repo root:
#   docker build -f deploy/docker/python.Dockerfile --target api .
#
# * Base images are pinned by digest in literal FROM lines (ADR-0010; Dependabot updates them).
# * Dependencies come from uv.lock only (--frozen), without dev tools, installed
#   non-editable into /opt/venv. No compilers or package managers in the final image.
# * Runs as an unprivileged user (uid 10001) on a read-only root filesystem (Compose / Helm).

FROM ghcr.io/astral-sh/uv:0.13.9@sha256:d3b601f0c7b118bc1753febf7c41cc80981df678445e0254284eecf84db79a7d AS uv

FROM python:3.13-slim-bookworm@sha256:c3f3ace1c09d3d90cb79b17c6a1037282e82df75a8870929b2cbc667ddb7898e AS build
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv
WORKDIR /src
COPY pyproject.toml uv.lock README.md ./
COPY packages ./packages
COPY apps/api ./apps/api
COPY apps/worker ./apps/worker
RUN uv sync --frozen --no-dev --no-editable \
    # The check catalogue hashes evaluator source code (L9): prove it loads in the image.
    && /opt/venv/bin/python -c "from skyline_checks.loader import load_checks; load_checks()"

FROM python:3.13-slim-bookworm@sha256:c3f3ace1c09d3d90cb79b17c6a1037282e82df75a8870929b2cbc667ddb7898e AS runtime
# No package manager at runtime: pip (and its vendored urllib3/msgpack) is attack surface and
# shows up in image scans; everything the app needs is already in /opt/venv.
RUN groupadd --system --gid 10001 skyline \
    && useradd --system --uid 10001 --gid skyline --no-create-home --home-dir /nonexistent \
       --shell /usr/sbin/nologin skyline \
    && rm -rf /usr/local/lib/python3.13/site-packages/pip \
              /usr/local/lib/python3.13/site-packages/pip-*.dist-info \
              /usr/local/lib/python3.13/site-packages/setuptools* \
              /usr/local/lib/python3.13/ensurepip \
              /usr/local/bin/pip /usr/local/bin/pip3*
# Root-owned code: the runtime user can read it but not change it.
COPY --from=build /opt/venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
USER 10001:10001
WORKDIR /tmp

FROM runtime AS api
EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=5 \
    CMD ["python", "-c", "import sys, urllib.request; sys.exit(urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2).status != 200)"]
CMD ["skyline-api"]

FROM runtime AS worker
HEALTHCHECK --interval=15s --timeout=3s --start-period=30s --retries=5 \
    CMD ["python", "-c", "import pathlib, sys, time; p = pathlib.Path('/tmp/skyline-worker-heartbeat'); sys.exit(time.time() - int(p.read_text()) > 60)"]
CMD ["skyline-worker"]
