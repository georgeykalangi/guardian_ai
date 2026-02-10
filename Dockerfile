# --- Builder stage ---
FROM python:3.14-slim AS builder

WORKDIR /app

COPY pyproject.toml .
COPY src/ src/
COPY policies/ policies/
COPY migrations/ migrations/
COPY alembic.ini .

RUN pip install --no-cache-dir .

# --- Runtime stage ---
FROM python:3.14-slim

WORKDIR /app

COPY --from=builder /usr/local/lib/python3.14/site-packages /usr/local/lib/python3.14/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin
COPY --from=builder /app /app

EXPOSE 8000

CMD ["uvicorn", "guardian.main:app", "--host", "0.0.0.0", "--port", "8000"]
