# syntax=docker/dockerfile:1
# Official Ubuntu 24.04 multi-platform digest, resolved 2026-10-19.
FROM ubuntu:24.04@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac AS base

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# capinfos is provided by wireshark-common. No privileged live capture is enabled.
RUN echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
       ca-certificates python3.12 python3.12-venv tshark wireshark-common \
    && test -x /usr/bin/tshark \
    && test -x /usr/bin/capinfos \
    && test ! -u /usr/bin/dumpcap \
    && test ! -g /usr/bin/dumpcap \
    && rm -rf /var/lib/apt/lists/*

FROM base AS builder
COPY --from=ghcr.io/astral-sh/uv:0.12.5@sha256:e85be844203885286c60ffad8a858d48afb6c5a5c237ca0e67f12e74b8f174b1 /uv /usr/local/bin/uv
ENV UV_PYTHON_DOWNLOADS=never UV_LINK_MODE=copy
WORKDIR /app
COPY pyproject.toml uv.lock README.md .python-version ./
COPY src/ ./src/
RUN uv sync --locked --no-dev --no-editable --python /usr/bin/python3.12 --no-cache

FROM base AS runtime
RUN groupadd --gid 10001 securemailscope \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent securemailscope \
    && install -d -m 0700 -o 10001 -g 10001 /tmp/securemailscope
WORKDIR /app
COPY --from=builder /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH" \
    TMPDIR=/tmp/securemailscope \
    PORT=10000
USER 10001:10001
EXPOSE 10000
# Python validates PORT; no shell expansion. Uvicorn runs one worker and receives signals.
CMD ["/app/.venv/bin/python", "-m", "securemailscope.deployment"]
