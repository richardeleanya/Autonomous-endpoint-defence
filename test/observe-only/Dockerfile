FROM python:3.12-alpine@sha256:c5ba3deef00c7758561a0f03c26f44f10589263d40e732b8748e0d1f38f6dd89
WORKDIR /app
RUN adduser -D -H -u 10001 observe && mkdir /state && chown observe /state
COPY --chmod=0444 control_plane.py agent.py test_lifecycle.py ./
USER observe
