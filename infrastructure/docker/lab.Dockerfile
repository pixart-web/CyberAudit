FROM python:3.12-slim
RUN pip install --no-cache-dir "cryptography>=46,<47"
USER 65534:65534
