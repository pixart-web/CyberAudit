FROM python:3.12.14-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
COPY apps/api/pyproject.toml apps/api/README.md /app/apps/api/
RUN pip install --no-cache-dir -e "/app/apps/api"
COPY apps/api /app/apps/api
RUN groupadd --system --gid 10001 cyberaudit \
    && useradd --system --uid 10001 --gid cyberaudit --home-dir /nonexistent cyberaudit \
    && chown -R cyberaudit:cyberaudit /app
WORKDIR /app/apps/api
USER 10001:10001
CMD ["uvicorn", "cyberaudit.main:app", "--host", "0.0.0.0", "--port", "8000"]
