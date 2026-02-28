# syntax=docker/dockerfile:1.7

FROM python:3.12-slim AS python-builder
WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m pip install --upgrade pip \
    && python -m pip wheel --no-cache-dir --wheel-dir /wheels .

FROM node:20-bookworm-slim AS ui-builder
WORKDIR /app/ui

COPY ui/package.json ui/package-lock.json ./
RUN npm ci
COPY ui ./
RUN npm run build

FROM python:3.12-slim AS runtime
WORKDIR /app
ENV PYTHONUNBUFFERED=1
ENV PORT=4173

RUN apt-get update \
    && apt-get install -y --no-install-recommends nodejs npm ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=python-builder /wheels /tmp/wheels
RUN python -m pip install --upgrade pip \
    && python -m pip install --no-cache-dir /tmp/wheels/*.whl \
    && rm -rf /tmp/wheels

COPY src ./src
COPY samples ./samples
COPY config.example.yaml ./config.example.yaml

COPY ui/package.json ui/package-lock.json ./ui/
RUN npm --prefix ui ci --omit=dev
COPY ui/server ./ui/server
COPY --from=ui-builder /app/ui/dist ./ui/dist

RUN mkdir -p /app/out
EXPOSE 4173

CMD ["npm", "--prefix", "ui", "start"]
