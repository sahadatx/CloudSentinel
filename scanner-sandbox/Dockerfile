FROM aquasec/trivy:0.76.2 AS trivy

FROM python:3.12-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TRIVY_CACHE_DIR=/opt/trivy-cache
WORKDIR /opt/cloudsentinel
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && python -m pip install --no-cache-dir --disable-pip-version-check 'checkov==3.4.3' \
    && mkdir -p /opt/trivy-cache /tmp/cloudsentinel-scan \
    && trivy --cache-dir /opt/trivy-cache --download-db-only \
    && trivy --cache-dir /opt/trivy-cache --download-java-db-only \
    && mkdir -p /tmp/empty-checks \
    && trivy --cache-dir /opt/trivy-cache config /tmp/empty-checks --format json >/dev/null \
    && chmod -R a+rX /opt/trivy-cache \
    && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin scanner \
    && chown -R 10001:10001 /tmp/cloudsentinel-scan
COPY --chown=10001:10001 entrypoint.py /opt/cloudsentinel/entrypoint.py
USER 10001:10001
ENTRYPOINT ["python", "/opt/cloudsentinel/entrypoint.py"]
