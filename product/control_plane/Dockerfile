ARG PYTHON_BASE=python:3.12-alpine@sha256:c5ba3deef00c7758561a0f03c26f44f10589263d40e732b8748e0d1f38f6dd89
FROM ${PYTHON_BASE}
ARG RUNTIME_UID=10001
WORKDIR /app
COPY --chmod=0444 requirements.txt ./
RUN --mount=type=bind,from=wheelhouse,target=/wheels pip install --no-cache-dir --no-compile --no-index --find-links=/wheels --require-hashes -r requirements.txt \
    && mkdir /data /artifacts \
    && chown "${RUNTIME_UID}" /data /artifacts \
    && chmod 0700 /data /artifacts
COPY --chmod=0444 api.py customer_ops.py store.py worker.py ./
USER ${RUNTIME_UID}
ENV PYTHONDONTWRITEBYTECODE=1 ADA_CONFIG=/secrets/tenants.json ADA_DATA=/data ADA_ARTIFACTS=/artifacts
