#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Docker Registry MiniHub — a tiny Flask web UI (Docker Hub–style)
Lists repositories, tags, and image sizes from a Docker Registry v2.

Quick start:
    export REGISTRY_URL="http://192.168.68.64:8080"
    # optional basic auth if your registry needs it
    # export REGISTRY_USER="admin"; export REGISTRY_PASS="pass"
    pip install flask requests
    python app.py

Then open: http://127.0.0.1:5000

Notes:
- Handles both single-platform manifests and multi-arch manifest lists (prefers linux/amd64).
- Caches responses for 60s to keep the UI snappy.
- Supports basic search/filter on the page.
- No DB required; purely live data from the registry API.
"""

import os
import time
import math
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple

import requests
from flask import Flask, request, redirect, url_for, render_template_string, abort

# -----------------------------
# Config
# -----------------------------
REGISTRY_URL = os.getenv("REGISTRY_URL", "http://192.168.68.64:8080").rstrip('/')
REGISTRY_USER = os.getenv("REGISTRY_USER")
REGISTRY_PASS = os.getenv("REGISTRY_PASS")
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "10"))
CACHE_TTL = int(os.getenv("CACHE_TTL", "60"))
MAX_WORKERS = int(os.getenv("MAX_WORKERS", "12"))
PREFERRED_PLATFORM = (os.getenv("PLATFORM_OS", "linux"), os.getenv("PLATFORM_ARCH", "amd64"))
PAGE_SIZE = int(os.getenv("PAGE_SIZE", "50"))

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
                # expired
                self._store.pop(key, None)
                return None
            return val

    def set(self, key: str, val):
        with self._lock:
            self._store[key] = (time.time(), val)

cache = TTLCache(ttl=CACHE_TTL)

# -----------------------------
# Registry helpers
# -----------------------------

def _url(path: str) -> str:
    return f"{REGISTRY_URL}{path}"


def _get(path: str, headers: Optional[Dict[str, str]] = None) -> requests.Response:
    h = headers or {}
    r = SESSION.get(_url(path), headers=h, timeout=REQUEST_TIMEOUT)
    # Raise for 4xx/5xx to simplify error paths; callers will catch.
    r.raise_for_status()
    return r


def list_repositories() -> List[str]:
    cache_key = "repos:list"
    cached = cache.get(cache_key)
    if cached is not None:
        return cached

    repos: List[str] = []
    # Handle pagination with ?n=...&last=...
    last = None
    while True:
        q = f"/v2/_catalog?n=1000"
        if last:
            q += f"&last={last}"
        resp = _get(q)
        data = resp.json()
        repos.extend(data.get("repositories", []))
        # Docker Registry may send Link header like: <...&_catalog?last=foo&n=100>; rel="next"
        link = resp.headers.get("Link")
        if link and 'rel="next"' in link:
            # extract last from the link (best-effort)
            try:
                # naive parse
                import re
                m = re.search(r"[?&]last=([^&>]+)", link)
                last = m.group(1) if m else None
            except Exception:
                last = None
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
        # repo might be empty or deleted
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
    """Given a manifest list, choose preferred platform, then fetch that manifest."""
    manifests = manifest_list.get("manifests") or []
    os_pref, arch_pref = PREFERRED_PLATFORM

    # Try exact match first
    chosen = None
    for m in manifests:
        plat = m.get("platform", {})
        if plat.get("os") == os_pref and plat.get("architecture") == arch_pref:
            chosen = m
            break
    # Fallback: first linux manifest
    if not chosen and manifests:
        for m in manifests:
            if m.get("platform", {}).get("os") == "linux":
                chosen = m
                break
    # Last fallback: first entry
    if not chosen and manifests:
        chosen = manifests[0]

    if not chosen:
        return None

    digest = chosen.get("digest")
    if not digest:
        return None

    # Fetch the chosen platform manifest
    r = _get(f"/v2/{repo}/manifests/{digest}", headers=H_MANIFEST_V2)
    return r.json()


def get_tag_size_bytes(repo: str, tag: str) -> Optional[int]:
    """Return total size in bytes for a tag (sum of layer sizes)."""
    cache_key = f"size:{repo}:{tag}"
    cached = cache.get(cache_key)
    if cached is not None:
        return cached

    try:
        r = _get(f"/v2/{repo}/manifests/{tag}", headers=H_BOTH)
    except requests.HTTPError as e:
        if e.response is not None and e.response.status_code == 404:
            cache.set(cache_key, None)
            return None
        raise

    doc = r.json()
    media_type = doc.get("mediaType") or r.headers.get("Content-Type", "")

    size_bytes: Optional[int] = None
    try:
        if "manifest.list.v2+json" in media_type:
            # Multi-arch list — choose a platform and then sum sizes
            chosen_manifest = _choose_manifest_from_list(repo, doc)
            if chosen_manifest:
                size_bytes = _sum_layer_sizes(chosen_manifest)
        elif "manifest.v2+json" in media_type:
            size_bytes = _sum_layer_sizes(doc)
        else:
            # Unknown/legacy schema
            size_bytes = None
    except Exception:
        size_bytes = None

    cache.set(cache_key, size_bytes)
    return size_bytes


def fmt_size(bytes_val: Optional[int]) -> str:
    if bytes_val is None:
        return "—"
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(bytes_val)
    idx = 0
    while size >= 1024.0 and idx < len(units) - 1:
        size /= 1024.0
        idx += 1
    # Display two decimals for KB and above
    if idx == 0:
        return f"{int(size)} {units[idx]}"
    return f"{size:.2f} {units[idx]}"

# -----------------------------
# Flask app
# -----------------------------
app = Flask(__name__)

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
    <div class="mb-3 small text-muted">Registry: <code>{{ registry_url }}</code>{% if auth %} · Auth: <span class="text-success">enabled</span>{% endif %}</div>
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
          <a href="{{ url_for('repo_detail', name=repo) }}" class="btn btn-sm btn-outline-primary">View tags</a>
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
  <div class="mb-3">
    <a href="{{ url_for('home') }}" class="text-decoration-none">← Back</a>
  </div>
  <h2 class="mb-3">{{ name }}</h2>

  {% if tags|length == 0 %}
    <div class="alert alert-info">This repository has no tags.</div>
  {% else %}
  <div class="table-responsive">
    <table class="table align-middle">
      <thead>
        <tr>
          <th scope="col">Tag</th>
          <th scope="col" class="text-end">Size</th>
        </tr>
      </thead>
      <tbody>
        {% for t, size in rows %}
        <tr>
          <td><span class="badge text-bg-light tag-pill">{{ t }}</span></td>
          <td class="text-end nowrap">{{ size }}</td>
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

    # Pre-compute tag counts concurrently for the visible page only (fast)
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
    )


@app.route('/r/<path:name>')
def repo_detail(name: str):
    # Validate the repo exists quickly; if not, 404
    repos = list_repositories()
    if name not in repos:
        abort(404)

    tags = list_tags(name)

    # Fetch sizes concurrently
    rows: List[Tuple[str, str]] = []
    with ThreadPoolExecutor(max_workers=min(len(tags) or 1, MAX_WORKERS)) as ex:
        futs = {ex.submit(get_tag_size_bytes, name, t): t for t in tags}
        for fut in as_completed(futs):
            t = futs[fut]
            try:
                size_b = fut.result()
                rows.append((t, fmt_size(size_b)))
            except Exception:
                rows.append((t, "—"))

    # Keep stable order by tag name
    rows.sort(key=lambda x: x[0])

    return render_template_string(
        REPO_TMPL,
        name=name,
        tags=tags,
        rows=rows,
        registry_url=REGISTRY_URL,
        auth=bool(REGISTRY_USER and REGISTRY_PASS),
        q="",
    )


# Health endpoint for load balancers
@app.route('/healthz')
def healthz():
    return {"ok": True, "registry": REGISTRY_URL}


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', '5000')), debug=os.getenv('FLASK_DEBUG', '0') == '1')
