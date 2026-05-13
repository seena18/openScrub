FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

WORKDIR /app

COPY core/requirements.txt /app/core-requirements.txt
COPY tests/requirements.txt /app/tests-requirements.txt
RUN pip install --no-cache-dir -r /app/core-requirements.txt -r /app/tests-requirements.txt

COPY core /app/core
COPY workers /app/workers
COPY docs /app/docs
COPY adapters /app/adapters
COPY tests /app/tests

CMD ["pytest", "-q", "tests/integration"]
