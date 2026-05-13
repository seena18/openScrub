FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

WORKDIR /app

COPY core/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY core /app/core
COPY workers /app/workers
COPY docs /app/docs
COPY adapters /app/adapters

CMD ["uvicorn", "core.api.main:app", "--host", "0.0.0.0", "--port", "8080"]
