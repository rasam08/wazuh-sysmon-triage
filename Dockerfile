# syntax=docker/dockerfile:1.7

FROM python:3.14-slim AS python-builder
WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m pip install --upgrade pip \
    && python -m pip wheel --no-cache-dir --wheel-dir /wheels .

FROM python:3.14-slim AS runtime
WORKDIR /app
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY --from=python-builder /wheels /tmp/wheels
RUN python -m pip install --upgrade pip \
    && python -m pip install --no-cache-dir /tmp/wheels/*.whl \
    && rm -rf /tmp/wheels

COPY samples ./samples
COPY config.example.yaml ./config.example.yaml

RUN addgroup --system triage \
    && adduser --system --ingroup triage --home /app triage \
    && mkdir -p /app/out \
    && chown triage:triage /app/out

USER triage

ENTRYPOINT ["triage"]
CMD ["--help"]
