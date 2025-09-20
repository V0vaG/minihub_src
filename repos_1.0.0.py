#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Docker Registry MiniHub — a tiny Flask web UI (Docker Hub–style)
Lists repositories, tags, sizes, and (when possible) dates. Also supports
optional delete actions.

Quick start:
    export REGISTRY_URL="http://192.168.68.64:8080"
    # optional basic auth if your registry needs it
    # export REGISTRY_USER="admin"; export REGISTRY_PASS="pass"
    # optional delete protection (required for delete actions)
    # export ENABLE_DELETE=1
    # export ADMIN_TOKEN="supersecret"   # required to authorize deletes
    # optional pulls counter file (JSON: {"repo:tag": 123, ...})
    # export PULLS_DB="/path/to/pulls.json"

    pip install flask requests
    python app.py

Then open: http://127.0.0.1:5000

What you’ll see per tag (best‑effort):
- Size (sum of layer sizes; multi‑arch picks a preferred platform).
- Created (from image config JSON, if present) — this is the image build time.
- Pushed (best‑effort: HTTP Last‑Modified of manifest; may be unavailable).
- Pulls (optional, from a JSON file you maintain; see PULLS_DB).
- Actions: Delete tag (by manifest digest), Delete repo (delete all tag manifests).

Notes/limits (truth in advertising):
- Vanilla Docker Registry v2 does NOT expose download counts or push timestamps
  via API. We surface Created from the config blob, and show Pushed only if
  the registry/storage returns a Last‑Modified header. Pull counts can be
  integrated via a simple JSON file (PULLS_DB) or you can extend this to parse
  proxy logs/Prometheus.
- Deletion requires REGISTRY to be started with REGISTRY_STORAGE_DELETE_ENABLED=true
  and you’ll still need to run the registry garbage‑collector to free disk.
- For multi‑arch tags, size/created come from your preferred platform
  (env: PLATFORM_OS / PLATFORM_ARCH, defaults linux/amd64). The delete action
  removes the tag by deleting the tag’s top‑level manifest digest.
"""

import os
import re
import io
import json
import time
import math
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple

import requests
from flask import (
    Flask,
    request,
    redirect,
    url_for,
    render_template_string,
    abort,
    flash,
)

# -----------------------------
# Config
# -----------------------------
REGISTRY_URL = os.getenv("REGISTRY_URL", "http://192.168.68.64:8080").rstrip('/')
REGISTRY_USER = os.getenv("REGISTRY_USER")
REGISTRY_PASS = os.getenv("REGISTRY_PASS")
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "12"))
CACHE_TTL = int(os.getenv("CACHE_TTL", "60"))
MAX_WORKERS = int(os.getenv("MAX_WORKERS", "12"))
PREFERRED_PLATFORM = (os.getenv("PLATFORM_OS", "linux"), os.getenv("PLATFORM_ARCH", "amd64"))
PAGE_SIZE = int(os.getenv("PAGE_SIZE", "50"))

ENABLE_DELETE = os.getenv("ENABLE_DELETE", "0") in ("1", "true", "TRUE", "yes", "on")
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN")  # required if ENABLE_DELETE
PULLS_DB = os.getenv("PULLS_DB")  # optional JSON file with {"repo:tag": int}

SESSION = requests.Session()
if REGISTRY_USER and REGISTRY_PASS:
    SESSION.auth = (REGISTRY_USER, REGISTRY_PASS)

# Registry headers
H_MANIFEST_V2 = {"Accept": "application/vnd.docker.distribution.manifest.v2+json"}
H_MANIFEST_LIST = {"Accept": "application/vnd.docker.distribution.manifest.list.v2+json"}
H_BOTH = {"Accept": ", ".join([
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.docker.distribution.manifest.v2+json",
])}

# -----------------------------
# Simple in-memory cache
# -----------------------------
class TTLCache:
    def __init__(self, ttl: int = 60):
        self.ttl = ttl
        self._store: Dict[str, Tuple[float, object]] = {}
        self._lock = threading.Lock()

    def get(self, key: str):
        with self._lock:
            item = self._store.get(key)
            if not item:
                return None
            ts, val = item
            if time.time() - ts > self.ttl:
                self._store.pop(key, None)
                return None
            return val

    def set(self, key: str, val):
        with self._lock:
            self._store[key] = (time.time(), val)

cache = TTLCache(ttl=CACHE_TTL)

# -----------------------------
# Helpers
# -----------------------------

def _url(path: str) -> str:
    return f"{REGISTRY_URL}{path}"


def _get(path: str, headers: Optional[Dict[str, str]] = None) -> requests.Response:
    h = headers or {}
    r = SESSION.get(_url(path), headers=h, timeout=REQUEST_TIMEOUT)
    r.raise_for_status()
    return r


def _head(path: str, headers: Optional[Dict[str, str]] = None) -> requests.Response:
    h = headers or {}
    r = SESSION.head(_url(path), headers=h, timeout=REQUEST_TIMEOUT)
    r.raise_for_status()
    return r


def list_repositories() -> List[str]:
    cache_key = "repos:list"
    cached = cache.get(cache_key)
    if cached is not None:
        return cached

    repos: List[str] = []
    last = None
    while True:
        q = f"/v2/_catalog?n=1000"
        if last:
            q += f"&last={last}"
        resp = _get(q)
        data = resp.json()
        repos.extend(data.get("repositories", []))
        link = resp.headers.get("Link")
        if link and 'rel="next"' in link:
            m = re.search(r"[?&]last=([^&>]+)", link)
            last = m.group(1) if m else None
        else:
            break

    repos.sort()
    cache.set(cache_key, repos)
    return repos


def list_tags(repo: str) -> List[str]:
    cache_key = f"tags:{repo}"
    cached = cache.get(cache_key)
    if cached is not None:
        return cached

    try:
        data = _get(f"/v2/{repo}/tags/list").json()
    except requests.HTTPError as e:
        if e.response is not None and e.response.status_code == 404:
            cache.set(cache_key, [])
            return []
        raise

    tags = data.get("tags") or []
    tags = sorted(tags)
    cache.set(cache_key, tags)
    return tags


def _sum_layer_sizes(manifest_json: dict) -> Optional[int]:
    layers = manifest_json.get("layers")
    if not layers:
        return None
    total = 0
    for l in layers:
        sz = l.get("size")
        if isinstance(sz, int):
            total += sz
        else:
            return None
    return total


def _choose_manifest_from_list(repo: str, manifest_list: dict) -> Optional[dict]:
    manifests = manifest_list.get("manifests") or []
    os_pref, arch_pref = PREFERRED_PLATFORM

    chosen = None
    for m in manifests:
        plat = m.get("platform", {})
        if plat.get("os") == os_pref and plat.get("architecture") == arch_pref:
            chosen = m
            break
    if not chosen:
        for m in manifests:
            if m.get("platform", {}).get("os") == "linux":
                chosen = m
                break
    if not chosen and manifests:
        chosen = manifests[0]

    if not chosen:
        return None

    digest = chosen.get("digest")
    if not digest:
        return None

    r = _get(f"/v2/{repo}/manifests/{digest}", headers=H_MANIFEST_V2)
    return r.json()


def _get_manifest(repo: str, ref: str) -> Tuple[dict, dict, str]:
    """Return (json, headers, media_type) for a tag or digest ref.
    Accept both manifest list and v2 manifest.
    """
    r = _get(f"/v2/{repo}/manifests/{ref}", headers=H_BOTH)
    media_type = r.headers.get("Content-Type", "")
    return r.json(), r.headers, media_type


def _get_config_json(repo: str, manifest_json: dict) -> Optional[dict]:
    cfg = manifest_json.get("config") or {}
    digest = cfg.get("digest")
    if not digest:
        return None
    r = _get(f"/v2/{repo}/blobs/{digest}")
    try:
        return r.json()
    except Exception:
        return None


def fmt_size(bytes_val: Optional[int]) -> str:
    if bytes_val is None:
        return "—"
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(bytes_val)
    idx = 0
    while size >= 1024.0 and idx < len(units) - 1:
        size /= 1024.0
        idx += 1
    if idx == 0:
        return f"{int(size)} {units[idx]}"
    return f"{size:.2f} {units[idx]}"


def fmt_dt(dt_str: Optional[str]) -> str:
    if not dt_str:
        return "—"
    try:
        # Try to parse common ISO 8601 formats
        dt = datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
        return dt.strftime('%Y-%m-%d %H:%M:%S %z')
    except Exception:
        return dt_str


def get_pulls(repo: str, tag: str) -> Optional[int]:
    if not PULLS_DB:
        return None
    try:
        cache_key = f"pullsdb:{PULLS_DB}"
        data = cache.get(cache_key)
        if data is None:
            with open(PULLS_DB, 'r', encoding='utf-8') as f:
                data = json.load(f)
            cache.set(cache_key, data)
        return int(data.get(f"{repo}:{tag}")) if f"{repo}:{tag}" in data else None
    except Exception:
        return None


def get_tag_info(repo: str, tag: str) -> dict:
    """Gather digest, size, created (from config), pushed (Last-Modified), platform."""
    info = {
        "tag": tag,
        "digest": None,
        "size_bytes": None,
        "created": None,
        "pushed": None,
        "platform": None,
        "pulls": get_pulls(repo, tag),
    }

    doc, headers, media_type = _get_manifest(repo, tag)
    digest = headers.get("Docker-Content-Digest")
    info["digest"] = digest

    # Best-effort pushed date from HTTP Last-Modified header
    pushed = headers.get("Last-Modified")
    if pushed:
        try:
            # Convert to ISO-like format
            info["pushed"] = pushed
        except Exception:
            info["pushed"] = pushed

    if "manifest.list.v2+json" in media_type:
        chosen = _choose_manifest_from_list(repo, doc)
        if chosen:
            info["size_bytes"] = _sum_layer_sizes(chosen)
            cfg = _get_config_json(repo, chosen)
            if cfg:
                info["created"] = cfg.get("created")
                plat = []
                if cfg.get("os"):
                    plat.append(cfg.get("os"))
                if cfg.get("architecture"):
                    plat.append(cfg.get("architecture"))
                info["platform"] = "/".join(plat) if plat else None
    elif "manifest.v2+json" in media_type:
        info["size_bytes"] = _sum_layer_sizes(doc)
        cfg = _get_config_json(repo, doc)
        if cfg:
            info["created"] = cfg.get("created")
            plat = []
            if cfg.get("os"):
                plat.append(cfg.get("os"))
            if cfg.get("architecture"):
                plat.append(cfg.get("architecture"))
            info["platform"] = "/".join(plat) if plat else None

    return info

# -----------------------------
# Flask app
# -----------------------------
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET", "minihub-dev")

BASE_TMPL = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Docker Registry MiniHub</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body { padding: 1.2rem; }
    .repo-card { border-radius: 1rem; box-shadow: 0 1px 6px rgba(0,0,0,0.08); }
    .tag-pill { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
    .muted { color: #6c757d; }
    .nowrap { white-space: nowrap; }
    .search-input { max-width: 460px; }
    .digest { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .9rem; }
  </style>
</head>
<body>
  <div class="container-xxl">
    <div class="d-flex align-items-center mb-4">
      <h1 class="me-auto">📦 Docker Registry MiniHub</h1>
      <form class="d-flex" method="get" action="{{ url_for('home') }}">
        <input class="form-control me-2 search-input" type="search" placeholder="Search repositories…" aria-label="Search" name="q" value="{{ q }}">
        <button class="btn btn-primary" type="submit">Search</button>
      </form>
    </div>
    <div class="mb-3 small text-muted">Registry: <code>{{ registry_url }}</code>{% if auth %} · Auth: <span class="text-success">enabled</span>{% endif %}
      {% if enable_delete %}· Delete: <span class="text-danger">ENABLED</span>{% else %}· Delete: <span class="text-muted">disabled</span>{% endif %}
    </div>
    {% with messages = get_flashed_messages(with_categories=true) %}
      {% if messages %}
        {% for category, msg in messages %}
          <div class="alert alert-{{ category }}">{{ msg }}</div>
        {% endfor %}
      {% endif %}
    {% endwith %}
    {% block body %}{% endblock %}
  </div>
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
"""

HOME_TMPL = """
{% extends 'base.html' %}
{% block body %}
  {% if repos|length == 0 %}
    <div class="alert alert-warning">No repositories found.</div>
  {% endif %}
  <div class="row g-3">
  {% for repo in repos %}
    <div class="col-12 col-md-6 col-lg-4">
      <div class="card repo-card">
        <div class="card-body">
          <h5 class="card-title"><a href="{{ url_for('repo_detail', name=repo) }}" class="text-decoration-none">{{ repo }}</a></h5>
          <p class="card-text small text-muted mb-1">{{ tag_counts.get(repo, 0) }} tag{{ '' if tag_counts.get(repo, 0)==1 else 's' }}</p>
          <div class="d-flex gap-2">
            <a href="{{ url_for('repo_detail', name=repo) }}" class="btn btn-sm btn-outline-primary">View tags</a>
            {% if enable_delete and admin_token %}
            <form method="post" action="{{ url_for('delete_repo', name=repo) }}" onsubmit="return confirm('Delete ENTIRE repository {{ repo }}? This removes all tags (space is reclaimed only after GC).');">
              <input type="hidden" name="token" value="{{ admin_token }}">
              <button class="btn btn-sm btn-outline-danger" type="submit">Delete repo</button>
            </form>
            {% endif %}
          </div>
        </div>
      </div>
    </div>
  {% endfor %}
  </div>

  {% if pages > 1 %}
  <nav class="mt-4" aria-label="Repo pagination">
    <ul class="pagination">
      <li class="page-item {% if page<=1 %}disabled{% endif %}"><a class="page-link" href="{{ url_for('home', q=q, page=page-1) }}">Previous</a></li>
      {% for p in range(1, pages+1) %}
        <li class="page-item {% if p==page %}active{% endif %}"><a class="page-link" href="{{ url_for('home', q=q, page=p) }}">{{ p }}</a></li>
      {% endfor %}
      <li class="page-item {% if page>=pages %}disabled{% endif %}"><a class="page-link" href="{{ url_for('home', q=q, page=page+1) }}">Next</a></li>
    </ul>
  </nav>
  {% endif %}
{% endblock %}
"""

REPO_TMPL = """
{% extends 'base.html' %}
{% block body %}
  <div class="mb-3 d-flex align-items-center gap-3">
    <a href="{{ url_for('home') }}" class="text-decoration-none">← Back</a>
    <h2 class="mb-0">{{ name }}</h2>
    <span class="ms-auto small text-muted">Preferred platform: {{ pref_os }}/{{ pref_arch }}</span>
  </div>

  {% if tags|length == 0 %}
    <div class="alert alert-info">This repository has no tags.</div>
  {% else %}
  <div class="table-responsive">
    <table class="table align-middle">
      <thead>
        <tr>
          <th scope="col">Tag</th>
          <th scope="col">Digest</th>
          <th scope="col" class="text-end">Size</th>
          <th scope="col">Created</th>
          <th scope="col">Pushed</th>
          <th scope="col" class="text-end">Pulls</th>
          {% if enable_delete %}<th scope="col" class="text-end">Actions</th>{% endif %}
        </tr>
      </thead>
      <tbody>
        {% for row in rows %}
        <tr>
          <td><span class="badge text-bg-light tag-pill">{{ row.tag }}</span></td>
          <td class="digest">{{ row.digest_short }}</td>
          <td class="text-end nowrap">{{ row.size_h }}</td>
          <td class="nowrap">{{ row.created_h }}</td>
          <td class="nowrap">{{ row.pushed_h }}</td>
          <td class="text-end">{{ row.pulls_h }}</td>
          {% if enable_delete %}
          <td class="text-end">
            {% if admin_token %}
            <form method="post" action="{{ url_for('delete_tag', name=name) }}" onsubmit="return confirm('Delete tag {{ row.tag }}?');" class="d-inline">
              <input type="hidden" name="tag" value="{{ row.tag }}">
              <input type="hidden" name="digest" value="{{ row.digest }}">
              <input type="hidden" name="token" value="{{ admin_token }}">
              <button class="btn btn-sm btn-outline-danger" type="submit">Delete tag</button>
            </form>
            {% else %}
              <span class="text-muted small">Set ADMIN_TOKEN to enable delete.</span>
            {% endif %}
          </td>
          {% endif %}
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
  {% endif %}
{% endblock %}
"""

# Register templates with Flask's loader via a dict loader
from jinja2 import DictLoader
app.jinja_loader = DictLoader({
    'base.html': BASE_TMPL,
    'home.html': HOME_TMPL,
    'repo.html': REPO_TMPL,
})

# -----------------------------
# Routes
# -----------------------------
@app.route('/')
def home():
    q = (request.args.get('q') or '').strip().lower()
    page = max(1, int(request.args.get('page', '1') or '1'))

    repos = list_repositories()
    if q:
        repos = [r for r in repos if q in r.lower()]

    total = len(repos)
    pages = max(1, math.ceil(total / PAGE_SIZE))
    start = (page-1)*PAGE_SIZE
    end = start + PAGE_SIZE
    repos_page = repos[start:end]

    # Pre-compute tag counts concurrently for the visible page only
    tag_counts: Dict[str, int] = {}
    with ThreadPoolExecutor(max_workers=min(len(repos_page) or 1, MAX_WORKERS)) as ex:
        futs = {ex.submit(list_tags, repo): repo for repo in repos_page}
        for fut in as_completed(futs):
            repo = futs[fut]
            try:
                tag_counts[repo] = len(fut.result())
            except Exception:
                tag_counts[repo] = 0

    return render_template_string(
        HOME_TMPL,
        repos=repos_page,
        tag_counts=tag_counts,
        registry_url=REGISTRY_URL,
        auth=bool(REGISTRY_USER and REGISTRY_PASS),
        q=q,
        page=page,
        pages=pages,
        enable_delete=ENABLE_DELETE,
        admin_token=ADMIN_TOKEN if ENABLE_DELETE else None,
    )


@app.route('/r/<path:name>')
def repo_detail(name: str):
    repos = list_repositories()
    if name not in repos:
        abort(404)

    tags = list_tags(name)

    rows: List[dict] = []
    with ThreadPoolExecutor(max_workers=min(len(tags) or 1, MAX_WORKERS)) as ex:
        futs = {ex.submit(get_tag_info, name, t): t for t in tags}
        for fut in as_completed(futs):
            t = futs[fut]
            try:
                info = fut.result()
            except Exception:
                info = {"tag": t, "digest": None, "size_bytes": None, "created": None, "pushed": None, "platform": None, "pulls": None}

            digest_short = (info.get("digest") or "—")
            if isinstance(digest_short, str) and digest_short.startswith("sha256:"):
                digest_short = digest_short[:20] + "…"

            rows.append({
                "tag": info.get("tag"),
                "digest": info.get("digest"),
                "digest_short": digest_short,
                "size_h": fmt_size(info.get("size_bytes")),
                "created_h": fmt_dt(info.get("created")),
                "pushed_h": info.get("pushed") or "—",
                "pulls_h": (info.get("pulls") if info.get("pulls") is not None else "—"),
            })

    rows.sort(key=lambda x: x["tag"])  # stable order

    return render_template_string(
        REPO_TMPL,
        name=name,
        tags=tags,
        rows=rows,
        registry_url=REGISTRY_URL,
        auth=bool(REGISTRY_USER and REGISTRY_PASS),
        pref_os=PREFERRED_PLATFORM[0],
        pref_arch=PREFERRED_PLATFORM[1],
        enable_delete=ENABLE_DELETE,
        admin_token=ADMIN_TOKEN if ENABLE_DELETE else None,
    )


# Health endpoint
@app.route('/healthz')
def healthz():
    return {"ok": True, "registry": REGISTRY_URL}


# ---- Delete endpoints ----

def _require_delete_enabled():
    if not ENABLE_DELETE:
        abort(403, description="Delete disabled. Set ENABLE_DELETE=1.")
    if not ADMIN_TOKEN:
        abort(403, description="ADMIN_TOKEN not set.")


def _check_token(form):
    tok = form.get('token')
    if not tok or tok != ADMIN_TOKEN:
        abort(403, description="Invalid admin token.")


@app.post('/r/<path:name>/delete_tag')
def delete_tag(name: str):
    _require_delete_enabled()
    _check_token(request.form)

    tag = request.form.get('tag')
    digest = request.form.get('digest')

    if not tag:
        abort(400, description="Missing tag")

    # If digest not provided, look it up to ensure we delete by digest
    if not digest:
        try:
            _, headers, _ = _get_manifest(name, tag)
            digest = headers.get("Docker-Content-Digest")
        except Exception as e:
            abort(400, description=f"Unable to resolve digest for {tag}: {e}")

    if not digest:
        abort(400, description="Digest not found for tag")

    # DELETE manifest by digest
    try:
        r = SESSION.delete(_url(f"/v2/{name}/manifests/{digest}"), timeout=REQUEST_TIMEOUT, headers=H_MANIFEST_V2)
        if r.status_code in (202, 200):
            flash(f"Deleted tag '{tag}' (manifest {digest[:20]}…)", "success")
        else:
            flash(f"Delete failed: HTTP {r.status_code} — {r.text}", "danger")
    except Exception as e:
        flash(f"Delete failed: {e}", "danger")

    return redirect(url_for('repo_detail', name=name))


@app.post('/r/<path:name>/delete_repo')
def delete_repo(name: str):
    _require_delete_enabled()
    _check_token(request.form)

    tags = list_tags(name)
    errors = 0
    for t in tags:
        try:
            _, headers, _ = _get_manifest(name, t)
            digest = headers.get("Docker-Content-Digest")
            if not digest:
                errors += 1
                continue
            r = SESSION.delete(_url(f"/v2/{name}/manifests/{digest}"), timeout=REQUEST_TIMEOUT, headers=H_MANIFEST_V2)
            if r.status_code not in (202, 200):
                errors += 1
        except Exception:
            errors += 1

    if errors:
        flash(f"Repo delete completed with {errors} error(s).", "warning")
    else:
        flash("Repository deleted (all tags removed).", "success")

    return redirect(url_for('home'))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', '5000')), debug=os.getenv('FLASK_DEBUG', '0') == '1')
