FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FISHINGMAILS_DB_PATH=/data/fishingmails.db

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY apps ./apps
COPY packages ./packages
RUN useradd --system --uid 10001 fishingmails && mkdir -p /data && chown fishingmails /data
USER fishingmails

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3)"
CMD ["uvicorn", "apps.server:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
