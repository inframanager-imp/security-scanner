# ── ASPM backend (FastAPI) — part of the unified VAPT platform ────────────────
# Build context = services/aspm (contains backend/). The app is imported as the
# package  backend.main:app  and runs from /app. Talks to the shared Postgres
# (schema "aspm") via DATABASE_URL / DB_SCHEMA.
FROM python:3.12-slim

WORKDIR /app

# Optional real pentest tooling. The scanners auto-detect binaries via shutil.which
# and fall back to a built-in simulation when absent, so this is opt-in:
#   docker build --build-arg INSTALL_SCANNERS=true ...
ARG INSTALL_SCANNERS=false
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git \
    && if [ "$INSTALL_SCANNERS" = "true" ]; then \
         apt-get install -y --no-install-recommends nmap nikto; \
       fi \
    && rm -rf /var/lib/apt/lists/*

# Python dependencies
COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

# Application code (database.py runs init_db() on import, creating the aspm schema
# + tables in Postgres on first start).
COPY backend ./backend

EXPOSE 8000
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
