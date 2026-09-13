FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /srv

COPY pyproject.toml README.md ./
COPY app ./app
COPY upstream ./upstream
COPY scripts ./scripts

RUN pip install --no-cache-dir . && \
    adduser --disabled-password --gecos "" --uid 10001 gateway && \
    mkdir -p /srv/data && chown -R gateway /srv

USER gateway

EXPOSE 8080
CMD ["uvicorn", "app.main:build", "--factory", "--host", "0.0.0.0", "--port", "8080"]
