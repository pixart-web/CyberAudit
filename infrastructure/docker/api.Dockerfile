FROM python:3.12-slim
WORKDIR /app
COPY apps/api/pyproject.toml apps/api/README.md /app/apps/api/
RUN pip install --no-cache-dir -e "/app/apps/api"
COPY apps/api /app/apps/api
WORKDIR /app/apps/api
CMD ["uvicorn", "cyberaudit.main:app", "--host", "0.0.0.0", "--port", "8000"]
