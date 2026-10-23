# ADIS Python services (api, normalizer, agent...); the command picks the service.
#
# Build from the repository root (docker compose --profile app build, or
#   docker build -f infrastructure/docker/Dockerfile -t adis-phase1-copy:local .).
# Configuration comes from environment variables only: no .env or secret is copied in.

FROM python:3.12-slim AS build
ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /src
COPY pyproject.toml README.md ./
COPY apps ./apps
COPY packages ./packages
RUN python -m venv /opt/adis \
    && /opt/adis/bin/pip install .

FROM python:3.12-slim
ENV PATH=/opt/adis/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
# libpcap lets the agent's live capture collector open an interface it is authorized to use.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*
RUN groupadd --system --gid 10001 adis \
    && useradd --system --uid 10001 --gid adis --home-dir /app --shell /usr/sbin/nologin adis
COPY --from=build /opt/adis /opt/adis
WORKDIR /app
USER adis:adis
CMD ["python", "-m", "apps.api"]
