# Docker Registry MiniHub

A tiny Docker Hub–style UI for a Registry v2 instance. Shows repositories, tags, sizes, build/push dates (best‑effort), optional pulls, and supports delete tag/repo.

## Quick start (docker compose)

```bash
cp app/env app/.env  # optional
docker compose up --build -d
# App on http://localhost:5000
# Nginx proxy on http://localhost:8088
```

## Environment

See `app/env` for variables. Minimal requirement:
```
REGISTRY_URL=http://192.168.68.64:8080
```

For deletions you must also set:
```
ENABLE_DELETE=1
ADMIN_TOKEN=supersecret
```
And ensure your registry was started with `REGISTRY_STORAGE_DELETE_ENABLED=true`. After deletions, run the registry garbage collector to reclaim disk space.

## Dev

```bash
cd app
pip install -r requirements.txt
export REGISTRY_URL="http://192.168.68.64:8080"
FLASK_APP=app.py flask run -h 0.0.0.0 -p 5000
```
