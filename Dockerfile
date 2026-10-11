FROM ghcr.io/astral-sh/uv:0.9.27 AS uv
FROM python:3.12-slim
COPY --from=uv /uv /usr/local/bin/uv
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 UV_PYTHON_DOWNLOADS=never
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY external_proxy.py container_health.py LICENSE ./
USER 65532:65532
EXPOSE 18001-18050 19000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/app/.venv/bin/python", "/app/container_health.py"]
ENTRYPOINT ["/app/.venv/bin/python", "/app/external_proxy.py"]
CMD ["--config", "/config/config.json"]
