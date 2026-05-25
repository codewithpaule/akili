FROM python:3.11-slim

WORKDIR /app

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ .

EXPOSE 8080

# Use the PORT env var if provided by the platform (Fly sets $PORT). Fall back to 8080.
# Use shell form so environment variable expansion works.
CMD sh -c "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8080}"