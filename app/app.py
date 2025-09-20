#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Docker Registry MiniHub — Flask UI (Docker Hub–style)
- HTML login page stores username/password in the Flask session (no shell prompts).
- Lists repositories, tags, sizes, build/push dates (best-effort), optional pulls.
- Supports delete tag/repo (opt-in).

ENV (minimal):
  REGISTRY_URL (required) e.g. http://192.168.68.64:5000
  FLASK_SECRET (cookie signing; default: minihub-dev)
  ENABLE_DELETE=1 (enable delete endpoints)
  ADMIN_TOKEN=... (required when delete is enabled)
  DELETE_WHEN_AUTH=1 (auto-enable delete for logged-in users; no ADMIN_TOKEN required)
  PULLS_DB=/path/to/pulls.json  (optional local JSON: {"repo:tag": 123})

Notes:
- If REGISTRY_USER/REGISTRY_PASS env vars are set, they’re used as fallback auth.
- Push time shows HTTP Last-Modified when the backend provides it.
- Created time is read from the image config JSON (if available).

Run (dev): FLASK_APP=app.py flask run -h 0.0.0.0 -p 5000
"""

import os
import re
import json
import time
import math
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple

import requests
from flask import (
    Flask, request, redirect, url_for, render_template,
    abort, flash, session
)

# -----------------------------
# Config
# -----------------------------
alias = "minihub"
HOME_DIR = os.path.expanduser("~")
FILES_PATH = os.path.join(HOME_DIR, "script_files", alias)
DATA_DIR = os.path.join(FILES_PATH, "data")
os.makedirs(DATA_DIR, exist_ok=True)

version = os.getenv('VERSION', 'N/A')
branch = os.getenv('BRANCH','N/A')

# IMPORTANT: default to talking directly to the registry (5000).
REGISTRY_URL = os.getenv("REGISTRY_URL", "http://192.168.68.64:5000").rstrip('/')

REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "12"))
CACHE_TTL = int(os.getenv("CACHE_TTL", "10"))
MAX_WORKERS = int(os.getenv("MAX_WORKERS", "12"))
PREFERRED_PLATFORM = (os.getenv("PLATFORM_OS", "linux"), os.getenv("PLATFORM_ARCH", "amd64"))
PAGE_SIZE = int(os.getenv("PAGE_SIZE", "50"))

ENABLE_DELETE = os.getenv("ENABLE_DELETE", "1").lower() in ("1", "true", "yes", "on")
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN")
PULLS_DB = os.getenv("PULLS_DB")
DELETE_WHEN_AUTH = os.getenv("DELETE_WHEN_AUTH", "1").lower() in ("1", "true", "yes", "on")

# Media types
MT_DOCKER_LIST = "application/vnd.docker.distribution.manifest.list.v2+json"
MT_DOCKER_MAN  = "application/vnd.docker.distribution.manifest.v2+json"
MT_OCI_INDEX   = "application/vnd.oci.image.index.v1+json"
MT_OCI_MAN     = "application/vnd.oci.image.manifest.v1+json"
MT_SCHEMA1     = "application/vnd.docker.distribution.manifest.v1+json"
MT_SCHEMA1_PJ  = "application/vnd.docker.distribution.manifest.v1+prettyjws"

H_MANIFEST_V2 = {"Accept": MT_DOCKER_MAN}
H_BOTH = {"Accept": ", ".join([MT_OCI_INDEX, MT_OCI_MAN, MT_DOCKER_LIST, MT_DOCKER_MAN])}

# -----------------------------
# Cache
# -----------------------------
class TTLCache:
    def __init__(self, ttl: int = 60):
        self.ttl = ttl
        self._store: Dict[str, Tuple[float, object]] = {}
        self._lock = threading.Lock()

    def get(self, key: str):
        if self.ttl <= 0:
            return None
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
        if self.ttl <= 0:
            return
        with self._lock:
            self._store[key] = (time.time(), val)

    def delete(self, key: str):
        with self._lock:
            self._store.pop(key, None)

    def clear_prefix(self, prefix: str):
        with self._lock:
            for k in list(self._store.keys()):
                if k.startswith(prefix):
                    self._store.pop(k, None)

cache = TTLCache(ttl=CACHE_TTL)

# -----------------------------
# Tombstones (hide deleted repos immediately)
# -----------------------------
TOMBSTONE_TTL = int(os.getenv("TOMBSTONE_TTL", "300"))  # seconds
_repo_tombstones: Dict[str, float] = {}
_repo_tomb_lock = threading.Lock()

def _tombstone_cleanup():
    now = time.time()
    with _repo_tomb_lock:
        for k in list(_repo_tombstones.keys()):
            if _repo_tombstones[k] <= now:
                _repo_tombstones.pop(k, None)

def mark_repo_tombstoned(name: str):
    with _repo_tomb_lock:
        _repo_tombstones[name] = time.time() + TOMBSTONE_TTL

def is_repo_tombstoned(name: str) -> bool:
    _tombstone_cleanup()
    with _repo_tomb_lock:
        exp = _repo_tombstones.get(name)
        if not exp:
            return False
        if exp <= time.time():
            _repo_tombstones.pop(name, None)
            return False
        return True

# -----------------------------
# Helpers
# -----------------------------
def get_manifest_v2like(repo: str, ref: str) -> Tuple[Optional[dict], str, dict]:
    """
    Try GET in order: OCI index, Docker list, OCI manifest, Docker manifest.
    Returns (json or None, content_type, headers).
    """
    for acc in (MT_OCI_INDEX, MT_DOCKER_LIST, MT_OCI_MAN, MT_DOCKER_MAN):
        try:
            r = _get(f"/v2/{repo}/manifests/{ref}", headers={"Accept": acc})
            return r.json(), (r.headers.get("Content-Type") or "").lower(), r.headers
        except requests.HTTPError as e:
            # Try next on 404/406; re-raise other HTTP errors
            if getattr(e.response, "status_code", None) in (404, 406):
                continue
            raise
    return None, "", {}



def _url(path: str) -> str:
    return f"{REGISTRY_URL}{path}"

def _clean_ref(x):
    if x is None:
        return None
    v = str(x).strip()
    if v == "" or v.lower() == "none":
        return None
    return v

def is_logged_in() -> bool:
    return bool(session.get("reg_user") and session.get("reg_pass"))

def delete_enabled_now() -> bool:
    return ENABLE_DELETE or (DELETE_WHEN_AUTH and is_logged_in())

def token_required_now() -> bool:
    return ENABLE_DELETE and not (DELETE_WHEN_AUTH and is_logged_in())

def _build_requests_session() -> requests.Session:
    s = requests.Session()
    u = session.get("reg_user") or os.getenv("REGISTRY_USER")
    p = session.get("reg_pass") or os.getenv("REGISTRY_PASS")
    if u and p:
        s.auth = (u, p)
    return s

class AuthRequired(Exception):
    pass

def _get(path: str, headers: Optional[Dict[str, str]] = None) -> requests.Response:
    s = _build_requests_session()
    r = s.get(_url(path), headers=headers or {}, timeout=REQUEST_TIMEOUT)
    if r.status_code == 401:
        raise AuthRequired()
    r.raise_for_status()
    return r

def _head(path: str, headers: Optional[Dict[str, str]] = None) -> requests.Response:
    s = _build_requests_session()
    r = s.head(_url(path), headers=headers or {}, timeout=REQUEST_TIMEOUT)
    if r.status_code == 401:
        raise AuthRequired()
    r.raise_for_status()
    return r

# -----------------------------
# Manifest helpers
# -----------------------------
def get_manifest_json_with_accept(repo: str, ref: str, accept: Optional[str]) -> Optional[dict]:
    try:
        headers = {"Accept": accept} if accept else None
        r = _get(f"/v2/{repo}/manifests/{ref}", headers=headers)
        return r.json()
    except requests.HTTPError as e:
        if e.response is not None and e.response.status_code in (404, 406):
            return None
        raise

def head_manifest(repo: str, ref: str):
    """Try HEAD for metadata, but never fail hard."""
    accepts = [MT_OCI_INDEX, MT_OCI_MAN, MT_DOCKER_LIST, MT_DOCKER_MAN]
    for acc in accepts:
        try:
            r = _head(f"/v2/{repo}/manifests/{ref}", headers={"Accept": acc})
            ctype = (r.headers.get("Content-Type") or "").lower()
            if any(t in ctype for t in (MT_OCI_INDEX, MT_OCI_MAN, MT_DOCKER_LIST, MT_DOCKER_MAN)):
                return acc, ctype, r.headers
        except requests.HTTPError as e:
            # Treat 404/406/405 as “try next”, anything else re-raise
            sc = getattr(e.response, "status_code", None)
            if sc not in (404, 406, 405):
                raise
        except requests.RequestException:
            # Network/timeout etc — just give up on HEAD
            break
    return None, "", {}

def _fetch_single_manifest(repo: str, digest_or_ref: str) -> Optional[dict]:
    """Fetch a single (non-list/index) manifest trying OCI then Docker v2."""
    for acc in (MT_OCI_MAN, MT_DOCKER_MAN):
        doc = get_manifest_json_with_accept(repo, digest_or_ref, acc)
        if doc is not None:
            return doc
    return None

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
    """Pick a child manifest from an OCI index or Docker manifest list and return its JSON."""
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

    # Fetch the actual child manifest (try OCI then Docker v2)
    return _fetch_single_manifest(repo, digest)

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

def _get_manifest_v1(repo: str, ref: str) -> Optional[dict]:
    for acc in (MT_SCHEMA1, MT_SCHEMA1_PJ):
        try:
            r = _get(f"/v2/{repo}/manifests/{ref}", headers={"Accept": acc})
            return r.json()
        except requests.HTTPError as e:
            if e.response is not None and e.response.status_code in (404, 406):
                continue
            raise
        except Exception:
            continue
    return None

def _estimate_size_from_v1(repo: str, v1doc: dict) -> Optional[int]:
    layers = v1doc.get("fsLayers") or []
    digests = [l.get("blobSum") for l in layers if l.get("blobSum")]
    seen = set()
    uniq = []
    for d in digests:
        if d not in seen:
            seen.add(d)
            uniq.append(d)
    total = 0
    s = _build_requests_session()
    for dg in uniq:
        try:
            r = s.head(_url(f"/v2/{repo}/blobs/{dg}"), timeout=REQUEST_TIMEOUT)
            if r.status_code == 401:
                raise AuthRequired()
            r.raise_for_status()
            cl = r.headers.get("Content-Length")
            if cl:
                total += int(cl)
        except Exception:
            pass
    return total or None

def _extract_created_platform_from_v1(v1doc: dict) -> Tuple[Optional[str], Optional[str]]:
    try:
        hist = v1doc.get("history") or []
        if not hist:
            return None, None
        v1c = hist[0].get("v1Compatibility")
        if not v1c:
            return None, None
        data = json.loads(v1c)
        created = data.get("created")
        osv = data.get("os")
        arch = data.get("architecture")
        platform = "/".join([v for v in (osv, arch) if v]) if (osv or arch) else None
        return created, platform
    except Exception:
        return None, None

def fmt_size(bytes_val: Optional[int]) -> str:
    if bytes_val is None:
        return "—"
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(bytes_val)
    idx = 0
    while size >= 1024.0 and idx < len(units) - 1:
        size /= 1024.0
        idx += 1
    return f"{int(size)} {units[idx]}" if idx == 0 else f"{size:.2f} {units[idx]}"

def fmt_dt(dt_str: Optional[str]) -> str:
    if not dt_str:
        return "—"
    try:
        dt = datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
        return dt.strftime('%Y-%m-%d %H:%M:%S %z')
    except Exception:
        return dt_str

def get_pulls(repo: str, tag: str) -> Optional[int]:
    if not PULLS_DB:
        return None
    try:
        ck = f"pullsdb:{PULLS_DB}"
        data = cache.get(ck)
        if data is None:
            with open(PULLS_DB, 'r', encoding='utf-8') as f:
                data = json.load(f)
            cache.set(ck, data)
        key = f"{repo}:{tag}"
        return int(data.get(key)) if key in data else None
    except Exception:
        return None

# -----------------------------
# High-level: tag info
# -----------------------------
def get_tag_info(repo: str, tag: str) -> dict:
    info = {
        "tag": tag,
        "digest": None,
        "size_bytes": None,
        "created": None,
        "pushed": None,
        "platform": None,
        "pulls": get_pulls(repo, tag),
    }

    # Prefer GET (some proxies mishandle HEAD); still try HEAD later for extra hints.
    doc, ctype, hdrs = get_manifest_v2like(repo, tag)

    # If GET found something, take digest/pushed from those headers.
    if hdrs:
        dcd = (hdrs.get("Docker-Content-Digest") or "").strip()
        if dcd.startswith("sha256:"):
            info["digest"] = dcd
        lm = hdrs.get("Last-Modified")
        if lm:
            info["pushed"] = lm

    # Optional: try a HEAD for pushed/digest if still missing, but ignore failures.
    if not info["digest"] or not info["pushed"]:
        try:
            _, _, hh = head_manifest(repo, tag)
            if hh:
                dcd = (hh.get("Docker-Content-Digest") or "").strip()
                if dcd.startswith("sha256:"):
                    info["digest"] = info["digest"] or dcd
                lm = hh.get("Last-Modified")
                if lm:
                    info["pushed"] = info["pushed"] or lm
        except Exception:
            pass

    # Parse the manifest we fetched
    if doc is not None:
        if MT_OCI_INDEX in ctype or MT_DOCKER_LIST in ctype:
            # Multi-platform index/list: pick best child, then fetch that child manifest
            chosen = _choose_manifest_from_list(repo, doc)
            if chosen:
                info["size_bytes"] = _sum_layer_sizes(chosen)
                cfg = _get_config_json(repo, chosen)
                if cfg:
                    info["created"] = cfg.get("created")
                    osv = cfg.get("os"); arch = cfg.get("architecture")
                    info["platform"] = "/".join([v for v in (osv, arch) if v])
            return info

        if MT_DOCKER_MAN in ctype or MT_OCI_MAN in ctype:
            info["size_bytes"] = _sum_layer_sizes(doc)
            cfg = _get_config_json(repo, doc)
            if cfg:
                info["created"] = cfg.get("created")
                osv = cfg.get("os"); arch = cfg.get("architecture")
                info["platform"] = "/".join([v for v in (osv, arch) if v])
            return info

    # Schema1 fallback
    v1 = _get_manifest_v1(repo, tag)
    if v1:
        info["size_bytes"] = _estimate_size_from_v1(repo, v1)
        created, platform = _extract_created_platform_from_v1(v1)
        if created:
            info["created"] = created
        if platform:
            info["platform"] = platform

    return info

# -----------------------------
# Registry listing
# -----------------------------
def list_repositories() -> List[str]:
    ck = "repos:list"
    cached = cache.get(ck)
    if cached is not None:
        return cached

    repos: List[str] = []
    last = None
    while True:
        q = "/v2/_catalog?n=1000"
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
    cache.set(ck, repos)
    return repos

def list_tags(repo: str) -> List[str]:
    ck = f"tags:{repo}"
    cached = cache.get(ck)
    if cached is not None:
        return cached

    try:
        data = _get(f"/v2/{repo}/tags/list").json()
    except requests.HTTPError as e:
        if e.response is not None and e.response.status_code == 404:
            cache.set(ck, [])
            return []
        raise

    tags = sorted(data.get("tags") or [])
    cache.set(ck, tags)
    return tags

# -----------------------------
# Flask app
# -----------------------------
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET", "minihub-dev")

@app.after_request
def add_no_cache_headers(resp):
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0, private"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp

# ---- Auth pages (HTML login) ----
@app.route("/login", methods=["GET", "POST"])
def login():
    next_url = request.args.get("next") or request.form.get("next") or url_for("home")
    if request.method == "POST":
        session["reg_user"] = (request.form.get("username") or "").strip() or None
        session["reg_pass"] = request.form.get("password") or None
        try:
            _ = _get("/v2/_catalog?n=1")
            flash("Logged in.", "success")
            return redirect(next_url)
        except AuthRequired:
            flash("Unauthorized — check username/password.", "danger")
        except Exception:
            return redirect(next_url)
    return render_template("login.html", next=next_url)

@app.route("/logout")
def logout():
    session.pop("reg_user", None)
    session.pop("reg_pass", None)
    flash("Logged out.", "success")
    return redirect(url_for("home"))

# ---- Views ----
@app.route("/")
def home():
    q = (request.args.get('q') or '').strip().lower()
    page = max(1, int(request.args.get('page', '1') or '1'))

    try:
        repos = list_repositories()
        repos = [r for r in repos if not is_repo_tombstoned(r)]
    except AuthRequired:
        return redirect(url_for("login", next=request.full_path or url_for("home")))

    if q:
        repos = [r for r in repos if q in r.lower()]

    total = len(repos)
    pages = max(1, math.ceil(total / PAGE_SIZE))
    start = (page-1)*PAGE_SIZE
    end = start + PAGE_SIZE
    repos_page = repos[start:end]

    tag_counts: Dict[str, int] = {}
    with ThreadPoolExecutor(max_workers=min(len(repos_page) or 1, MAX_WORKERS)) as ex:
        futs = {ex.submit(list_tags, repo): repo for repo in repos_page}
        for fut in as_completed(futs):
            repo = futs[fut]
            try:
                tag_counts[repo] = len(fut.result())
            except AuthRequired:
                return redirect(url_for("login", next=request.full_path or url_for("home")))
            except Exception:
                tag_counts[repo] = 0

    return render_template(
        "home.html",
        repos=repos_page,
        tag_counts=tag_counts,
        registry_url=REGISTRY_URL,
        auth=is_logged_in(),
        q=q, page=page, pages=pages,
        enable_delete=delete_enabled_now(),
        admin_token_required=token_required_now(),
        admin_token=ADMIN_TOKEN if token_required_now() else None,
        version=version, branch=branch,
    )

@app.route("/r/<path:name>")
def repo_detail(name: str):
    if is_repo_tombstoned(name):
        abort(404)
    try:
        repos = list_repositories()
    except AuthRequired:
        return redirect(url_for("login", next=request.full_path or url_for("home")))
    if name not in repos:
        abort(404)

    try:
        tags = list_tags(name)
    except AuthRequired:
        return redirect(url_for("login", next=request.full_path or url_for("home")))

    rows = []
    with ThreadPoolExecutor(max_workers=min(len(tags) or 1, MAX_WORKERS)) as ex:
        futs = {ex.submit(get_tag_info, name, t): t for t in tags}
        for fut in as_completed(futs):
            t = futs[fut]
            try:
                info = fut.result()
            except AuthRequired:
                return redirect(url_for("login", next=request.full_path or url_for("home")))
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

    rows.sort(key=lambda x: x["tag"])

    return render_template(
        "repo.html",
        name=name,
        tags=tags,
        rows=rows,
        registry_url=REGISTRY_URL,
        auth=is_logged_in(),
        pref_os=PREFERRED_PLATFORM[0],
        pref_arch=PREFERRED_PLATFORM[1],
        enable_delete=delete_enabled_now(),
        admin_token_required=token_required_now(),
        admin_token=ADMIN_TOKEN if token_required_now() else None,
        version=version, branch=branch,
    )

@app.get("/healthz")
def healthz():
    return {"ok": True, "registry": REGISTRY_URL}

# ---- Delete endpoints ----
def _require_delete_enabled():
    if not delete_enabled_now():
        abort(403, description="Delete disabled. Log in or set ENABLE_DELETE=1.")

def _check_token_if_required(form):
    if token_required_now():
        tok = form.get('token')
        if not tok or tok != ADMIN_TOKEN:
            abort(403, description="Invalid admin token.")

@app.post("/r/<path:name>/delete_tag")
def delete_tag(name: str):
    _require_delete_enabled()
    _check_token_if_required(request.form)

    tag = _clean_ref(request.form.get('tag'))
    digest_in = _clean_ref(request.form.get('digest'))
    if not tag:
        abort(400, description="Missing tag")

    ref = digest_in if (digest_in and digest_in.startswith("sha256:")) else tag
    digest = resolve_manifest_digest(name, ref)
    if not digest:
        abort(400, description=f"Could not resolve digest for tag '{tag}'.")

    try:
        s = _build_requests_session()
        r = s.delete(_url(f"/v2/{name}/manifests/{digest}"), timeout=REQUEST_TIMEOUT)
        if r.status_code in (202, 200):
            flash(f"Deleted tag '{tag}' (manifest {digest[:20]}…)", "success")
        else:
            flash(f"Delete failed: HTTP {r.status_code} — {r.text}", "danger")
    except Exception as e:
        flash(f"Delete failed: {e}", "danger")
    finally:
        cache.delete(f"tags:{name}")

    return redirect(url_for('repo_detail', name=name, _=int(time.time())))

def resolve_manifest_digest(repo: str, ref: str) -> Optional[str]:
    """Return the digest expected for DELETE. Prefer index/list, then schema2."""
    if isinstance(ref, str) and ref.startswith("sha256:") and len(ref) > 20:
        return ref

    def _try(head_accept: Optional[str]) -> Optional[str]:
        headers = {"Accept": head_accept} if head_accept else None
        r = _head(f"/v2/{repo}/manifests/{ref}", headers=headers)
        ctype = (r.headers.get("Content-Type") or "").lower()
        dcd = (r.headers.get("Docker-Content-Digest") or "").strip()
        if (MT_DOCKER_LIST in ctype) or (MT_DOCKER_MAN in ctype) or (MT_OCI_INDEX in ctype) or (MT_OCI_MAN in ctype):
            return dcd if dcd.startswith("sha256:") else None
        return None

    for accept in (MT_OCI_INDEX, MT_DOCKER_LIST, MT_OCI_MAN, MT_DOCKER_MAN):
        try:
            digest = _try(accept)
            if digest:
                return digest
        except requests.HTTPError as e:
            if not (e.response is not None and e.response.status_code in (404, 406)):
                raise
        except AuthRequired:
            raise

    # Last resort: GET schema2
    try:
        r = _get(f"/v2/{repo}/manifests/{ref}", headers={"Accept": MT_DOCKER_MAN})
        ctype = (r.headers.get("Content-Type") or "").lower()
        dcd = (r.headers.get("Docker-Content-Digest") or "").strip()
        if MT_DOCKER_MAN in ctype and dcd.startswith("sha256:"):
            return dcd
    except requests.HTTPError as e:
        if not (e.response is not None and e.response.status_code in (404, 406)):
            raise
    except AuthRequired:
        raise

    return None

@app.post("/r/<path:name>/delete_repo")
def delete_repo(name: str):
    _require_delete_enabled()
    _check_token_if_required(request.form)

    try:
        tags = list_tags(name)
    except AuthRequired:
        return redirect(url_for("login", next=request.full_path or url_for("home")))

    errors = 0
    s = _build_requests_session()
    for t in tags:
        try:
            digest = resolve_manifest_digest(name, t)
            if not digest:
                errors += 1; continue
            r = s.delete(_url(f"/v2/{name}/manifests/{digest}"), timeout=REQUEST_TIMEOUT)
            if r.status_code not in (202, 200):
                errors += 1
        except Exception:
            errors += 1

    cache.delete(f"tags:{name}")
    cache.delete("repos:list")
    if errors == 0:
        mark_repo_tombstoned(name)

    flash("Repository deleted (all tags removed)." if errors == 0
          else f"Repo delete completed with {errors} error(s).",
          "success" if errors == 0 else "warning")
    return redirect(url_for('home', _=int(time.time())))

# -----------------------------
# Main
# -----------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=os.getenv("FLASK_DEBUG", "0") == "1")
