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




@@ make argocd pull from privet castum repo


containers:
- name: minihub
image: 192.168.68.64:5000/minihub:amd64_latest

kubectl create secret docker-registry regcred \
  --docker-server=192.168.68.64:5000 \
  --docker-username=admin \
  --docker-password='Admin123' \
  --docker-email='its_a_vio@hotmail.com' \
  -n argocd

sudo mkdir -p /etc/rancher/k3s

sudo tee /etc/rancher/k3s/registries.yaml >/dev/null <<'EOF'
mirrors:
  "192.168.68.64:5000":
    endpoint:
      - "http://192.168.68.64:5000"

# If your registry requires auth, uncomment and fill:
#configs:
#  "192.168.68.64:5000":
#    auth:
#      username: admin
#      password: Admin123
#    # Only for self-signed HTTPS (NOT needed for plain HTTP):
#    #tls:
#    #  insecure_skip_verify: true
EOF

sudo systemctl restart k3s