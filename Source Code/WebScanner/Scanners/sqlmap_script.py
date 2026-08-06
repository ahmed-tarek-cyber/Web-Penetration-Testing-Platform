#!/usr/bin/env python3
"""
SQLMap API Scanner — crawls a target, discovers GET/POST endpoints,
and runs sqlmap on each one via the sqlmap REST API.
"""

import json
import sys
import time
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

import requests
from bs4 import BeautifulSoup

API_URL = "http://127.0.0.1:8775"
REQUEST_TIMEOUT = 10   # seconds per API call


# ─── Logging ─────────────────────────────────────────────────────────────────
# All debug/progress output goes to stderr so stdout stays clean JSON.

def _log(msg: str):
    print(msg, file=sys.stderr)


# ─── sqlmap API helpers ───────────────────────────────────────────────────────

def _new_task() -> str | None:
    """Create a new sqlmap task and return its taskid."""
    try:
        resp = requests.get(f"{API_URL}/task/new", timeout=REQUEST_TIMEOUT).json()
        return resp.get("taskid")
    except Exception as e:
        _log(f"[!] task/new failed: {e}")
        return None


def _start_task(taskid: str, options: dict) -> bool:
    """Start a sqlmap task with the given options dict."""
    try:
        resp = requests.post(
            f"{API_URL}/scan/{taskid}/start",
            json=options,
            timeout=REQUEST_TIMEOUT,
        ).json()
        return bool(resp.get("success"))
    except Exception as e:
        _log(f"[!] scan/start failed: {e}")
        return False


def _poll_task(taskid: str, max_wait: int = 300, poll_interval: int = 5) -> bool:
    """
    Block until the task finishes (or times out).
    Returns True on clean termination, False otherwise.
    """
    elapsed = 0
    while elapsed < max_wait:
        try:
            status = requests.get(
                f"{API_URL}/scan/{taskid}/status",
                timeout=REQUEST_TIMEOUT,
            ).json().get("status", "")
        except Exception as e:
            _log(f"[!] Status poll failed: {e}")
            return False

        _log(f"    [*] {taskid[:8]}… status: {status}")

        if status == "terminated":
            return True
        if status == "not running":
            _log(f"[!] Task {taskid[:8]} stopped unexpectedly")
            return False

        time.sleep(poll_interval)
        elapsed += poll_interval

    _log(f"[!] Task {taskid[:8]} timed out after {max_wait}s")
    return False


def _fetch_data(taskid: str) -> dict | None:
    """Retrieve scan results for a finished task."""
    try:
        return requests.get(
            f"{API_URL}/scan/{taskid}/data",
            timeout=REQUEST_TIMEOUT,
        ).json()
    except Exception as e:
        _log(f"[!] data fetch failed: {e}")
        return None


def run_sqlmap_task(options: dict, label: str, max_wait: int = 300) -> dict | None:
    """
    Full lifecycle for a single sqlmap task:
      new → start → poll → fetch data.

    Args:
        options:  sqlmap option dict (must include 'url'; may include 'data', etc.)
        label:    Human-readable label for log messages
        max_wait: Max seconds to wait for completion

    Returns:
        Raw result dict from the sqlmap API, or None on any failure.
    """
    _log(f"\n[>] Starting task: {label}")

    taskid = _new_task()
    if not taskid:
        return None

    if not _start_task(taskid, options):
        _log(f"[!] Could not start task for: {label}")
        return None

    if not _poll_task(taskid, max_wait=max_wait):
        return None

    result = _fetch_data(taskid)
    if result:
        _log(f"[+] Task done: {label}")
    return result


# ─── Crawler ─────────────────────────────────────────────────────────────────

class EndpointCrawler:
    """
    Lightweight single-depth crawler.

    Discovers:
      - GET endpoints (URL + existing query params)
      - POST forms (action URL + field names/defaults)
    """

    def __init__(self, base_url: str, timeout: int = 10, max_pages: int = 30, max_depth: int = 2):
        self.base_url  = base_url
        self.base_host = urlparse(base_url).netloc
        self.timeout   = timeout
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.session   = requests.Session()
        self.session.headers["User-Agent"] = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SQLScanner/3.0"
        )
        self._visited: set[str] = set()

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _same_host(self, url: str) -> bool:
        return urlparse(url).netloc == self.base_host

    def _normalize(self, url: str) -> str:
        """Strip fragment; keep query string."""
        p = urlparse(url)
        return urlunparse((p.scheme, p.netloc, p.path, p.params, p.query, ""))

    def _get(self, url: str) -> requests.Response | None:
        try:
            return self.session.get(url, timeout=self.timeout, allow_redirects=True)
        except Exception:
            return None

    # ── Page parsing ──────────────────────────────────────────────────────────

    def _parse_links(self, html: str, page_url: str) -> list[str]:
        """Return all in-scope <a href> links found on the page."""
        soup  = BeautifulSoup(html, "html.parser")
        links = []
        for tag in soup.find_all("a", href=True):
            href = tag["href"].strip()
            if not href or href.startswith(("#", "javascript:", "mailto:")):
                continue
            abs_url = self._normalize(urljoin(page_url, href))
            if self._same_host(abs_url):
                links.append(abs_url)
        return links

    def _parse_forms(self, html: str, page_url: str) -> list[dict]:
        """
        Return a list of form descriptors:
            {
                "method": "GET" | "POST",
                "action": <absolute URL>,
                "data":   {field_name: default_value, ...}
            }
        """
        soup  = BeautifulSoup(html, "html.parser")
        forms = []

        for form in soup.find_all("form"):
            method = (form.get("method") or "GET").upper()
            action = form.get("action") or ""
            action = urljoin(page_url, action) if action else page_url

            fields = {}
            for tag in form.find_all(["input", "textarea", "select"]):
                name  = (tag.get("name") or "").strip()
                ftype = (tag.get("type") or "text").lower()
                if not name or ftype in {"submit", "button", "image", "file"}:
                    continue
                fields[name] = tag.get("value") or ""

            if fields:
                forms.append({"method": method, "action": action, "data": fields})

        return forms

    # ── Public API ────────────────────────────────────────────────────────────

    def crawl(self) -> dict:
        """
        Crawl the base URL (and one level of links).

        Returns:
            {
                "get_endpoints":  [ {"url": ..., "params": {...}}, ... ],
                "post_endpoints": [ {"url": ..., "data":   {...}}, ... ],
            }
        """
        get_endpoints:  list[dict] = []
        post_endpoints: list[dict] = []

        # ---- Track what we've already queued to avoid duplicates ----
        seen_get:  set[str] = set()
        seen_post: set[tuple] = set()

        def _queue_get(url: str):
            p = urlparse(url)
            if p.query and url not in seen_get:
                seen_get.add(url)
                params = {k: v[0] for k, v in parse_qs(p.query).items()}
                get_endpoints.append({"url": url, "params": params})
                _log(f"  [GET]  {url}")

        def _queue_post(action: str, fields: dict):
            key = (action, tuple(sorted(fields.keys())))
            if key not in seen_post:
                seen_post.add(key)
                post_endpoints.append({"url": action, "data": fields})
                _log(f"  [POST] {action}  fields={list(fields.keys())}")

        # ---- Seed queue with the base URL ----
        queue = [(self.base_url, 0)]

        while queue and len(self._visited) < self.max_pages:
            url, depth = queue.pop(0)
            norm = self._normalize(url)
            if norm in self._visited:
                continue
            self._visited.add(norm)

            _log(f"\n[~] Crawling: {url}")
            resp = self._get(url)
            if not resp or resp.status_code != 200:
                continue

            # Collect GET endpoint if this page has query params
            _queue_get(url)

            # Collect forms
            for form in self._parse_forms(resp.text, url):
                if form["method"] == "POST":
                    _queue_post(form["action"], form["data"])
                else:
                    # GET form — build the URL with params and queue as GET
                    base_action = form["action"].split("?")[0]
                    query       = urlencode(form["data"])
                    full_url    = f"{base_action}?{query}" if query else base_action
                    _queue_get(full_url)

            # Follow same-host links up to the configured crawl depth.
            if depth < self.max_depth:
                for link in self._parse_links(resp.text, url):
                    if link not in self._visited:
                        queue.append((link, depth + 1))

        _log(f"\n[+] Crawl complete — "
             f"{len(get_endpoints)} GET endpoint(s), "
             f"{len(post_endpoints)} POST endpoint(s)")

        return {"get_endpoints": get_endpoints, "post_endpoints": post_endpoints}


# ─── Main scanner ─────────────────────────────────────────────────────────────

def run_sqlmap_scan(target_url: str, max_wait: int = 300) -> dict:
    """
    Full scan workflow:
      1. Crawl target to discover GET & POST endpoints
      2. Run a sqlmap task for each endpoint
      3. Merge and return all vulnerability data

    Args:
        target_url: Base URL to start crawling from
        max_wait:   Per-task timeout in seconds

    Returns:
        {
            "success": True,
            "endpoints_tested": <int>,
            "data": [ <sqlmap result>, ... ],   # one entry per endpoint
        }
    """
    _log("=" * 60)
    _log(f"[+] SQLMap Scanner starting — target: {target_url}")
    _log("=" * 60)

    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url

    # ── Step 1: Crawl ─────────────────────────────────────────────────────────
    _log("\n[1] Crawling for endpoints…")
    crawler   = EndpointCrawler(target_url)
    endpoints = crawler.crawl()

    all_results:      list[dict] = []
    endpoints_tested: int        = 0

    # ── Step 2: GET endpoints ─────────────────────────────────────────────────
    _log("\n[2] Testing GET endpoints…")
    for ep in endpoints["get_endpoints"]:
        label   = f"GET {ep['url']}"
        options = {
            "url":   ep["url"],
            "level": 1,
            "risk":  1,
        }
        result = run_sqlmap_task(options, label, max_wait=max_wait)
        if result:
            result["_meta"] = {"method": "GET", "url": ep["url"]}
            all_results.append(result)
        endpoints_tested += 1

    # ── Step 3: POST endpoints ────────────────────────────────────────────────
    _log("\n[3] Testing POST endpoints…")
    for ep in endpoints["post_endpoints"]:
        label   = f"POST {ep['url']}  data={list(ep['data'].keys())}"

        # Build a POST data string with placeholder values so sqlmap knows
        # which parameters to fuzz (it replaces values itself).
        post_data = urlencode({k: v or "test" for k, v in ep["data"].items()})

        options = {
            "url":   ep["url"],
            "data":  post_data,
            "level": 1,
            "risk":  1,
        }
        result = run_sqlmap_task(options, label, max_wait=max_wait)
        if result:
            result["_meta"] = {
                "method": "POST",
                "url":    ep["url"],
                "fields": list(ep["data"].keys()),
            }
            all_results.append(result)
        endpoints_tested += 1

    # ── Step 4: Summary ───────────────────────────────────────────────────────
    _log("\n" + "=" * 60)
    _log(f"[+] Scan complete — {endpoints_tested} endpoint(s) tested")
    _log("=" * 60)

    return {
        "success":          True,
        "endpoints_tested": endpoints_tested,
        "data":             all_results,
    }


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    url = input("Enter target URL: ").strip()
    if not url:
        print("[-] No URL provided.", file=sys.stderr)
        sys.exit(1)

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    results = run_sqlmap_scan(url)

    # stdout = clean JSON for the wrapper
    print(json.dumps(results, indent=2))
