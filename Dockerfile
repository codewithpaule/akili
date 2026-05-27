FROM python:3.11-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

COPY backend/requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ /app/

EXPOSE 8080

CMD sh -c "gunicorn main:app -k uvicorn.workers.UvicornWorker -w ${WEB_CONCURRENCY:-1} --timeout ${WEB_TIMEOUT:-180} --graceful-timeout 30 -b 0.0.0.0:${PORT:-8080}"
