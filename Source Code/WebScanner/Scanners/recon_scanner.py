import re
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup


class ReconScanner:
    SECURITY_HEADERS = {
        "content-security-policy": "CSP",
        "x-frame-options": "X-Frame-Options",
        "x-content-type-options": "X-Content-Type-Options",
        "strict-transport-security": "HSTS",
        "referrer-policy": "Referrer-Policy",
    }

    COMMON_PATHS = (
        "robots.txt",
        "sitemap.xml",
        "security.txt",
        ".well-known/security.txt",
        "crossdomain.xml",
        "humans.txt",
    )

    def __init__(self, target_url, timeout=8):
        self.target_url = self._normalize_url(target_url)
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) WebScanner-Recon/1.0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            }
        )
        self.vulnerabilities = []
        self._seen = set()

    def _normalize_url(self, url):
        parsed = urlparse(url)
        if parsed.scheme and parsed.netloc:
            return url
        return f"http://{url}"

    def _safe_get(self, url):
        try:
            return self.session.get(url, timeout=self.timeout, allow_redirects=True)
        except requests.RequestException:
            return None

    def _add_finding(self, finding_type, severity, description, location=None, payload="", payload2=""):
        key = (finding_type, location or self.target_url, payload)
        if key in self._seen:
            return
        self._seen.add(key)

        self.vulnerabilities.append(
            {
                "type": finding_type,
                "severity": severity,
                "description": description,
                "location": location or self.target_url,
                "payload": payload,
                "payload2": payload2,
                "source": "Python: run_recon.py",
            }
        )

    def _check_security_headers(self, response):
        headers = {k.lower(): v for k, v in response.headers.items()}
        missing = [name for key, name in self.SECURITY_HEADERS.items() if key not in headers]

        if missing:
            self._add_finding(
                "Recon - Missing Security Headers",
                "Info",
                "Security headers missing: " + ", ".join(missing),
                location=response.url,
                payload=", ".join(missing),
            )

        server = response.headers.get("Server", "")
        powered = response.headers.get("X-Powered-By", "")
        if server or powered:
            self._add_finding(
                "Recon - Technology Fingerprint",
                "Info",
                "Server technology fingerprint exposed in response headers",
                location=response.url,
                payload=f"Server={server}" if server else "",
                payload2=f"X-Powered-By={powered}" if powered else "",
            )

    def _discover_common_files(self):
        for path in self.COMMON_PATHS:
            url = urljoin(self.target_url.rstrip("/") + "/", path)
            resp = self._safe_get(url)
            if not resp:
                continue
            if resp.status_code in {200, 401, 403}:
                self._add_finding(
                    "Recon - Interesting File",
                    "Info",
                    f"Discovered common reconnaissance file ({path}) with status {resp.status_code}",
                    location=url,
                    payload=f"status={resp.status_code}",
                )

    def _extract_internal_assets(self, html, base_url):
        soup = BeautifulSoup(html or "", "html.parser")
        base = urlparse(base_url)

        internal_links = set()
        js_files = set()
        forms = []

        for a in soup.find_all("a"):
            href = (a.get("href") or "").strip()
            if not href:
                continue
            abs_url = urljoin(base_url, href)
            p = urlparse(abs_url)
            if (p.scheme, p.netloc) == (base.scheme, base.netloc):
                internal_links.add(abs_url)

        for s in soup.find_all("script"):
            src = (s.get("src") or "").strip()
            if not src:
                continue
            abs_src = urljoin(base_url, src)
            p = urlparse(abs_src)
            if (p.scheme, p.netloc) == (base.scheme, base.netloc):
                js_files.add(abs_src)

        for form in soup.find_all("form"):
            action = (form.get("action") or "").strip()
            method = (form.get("method") or "GET").upper()
            target = urljoin(base_url, action) if action else base_url
            fields = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = (inp.get("name") or "").strip()
                if name:
                    fields.append(name)
            forms.append((method, target, fields))

        return list(internal_links)[:20], list(js_files)[:12], forms[:12]

    def _scan_homepage_structure(self, response):
        links, js_files, forms = self._extract_internal_assets(response.text, response.url)

        if links:
            sample = ", ".join(links[:5])
            self._add_finding(
                "Recon - Internal Endpoints",
                "Info",
                f"Discovered {len(links)} internal links on the page",
                location=response.url,
                payload=sample,
            )

        for js in js_files[:8]:
            self._add_finding(
                "Recon - JavaScript Asset",
                "Info",
                "Discovered JavaScript file for potential client-side analysis",
                location=js,
                payload=js,
            )

        for method, target, fields in forms[:6]:
            field_preview = ", ".join(fields[:8])
            self._add_finding(
                "Recon - Form Discovery",
                "Info",
                f"Discovered {method} form with {len(fields)} input fields",
                location=target,
                payload=field_preview,
            )

    def _detect_stack_hints(self, response):
        text = (response.text or "").lower()
        hints = []

        patterns = [
            (r"wp-content|wordpress", "WordPress"),
            (r"drupal-settings-json|drupal", "Drupal"),
            (r"/cdn-cgi/|cloudflare", "Cloudflare"),
            (r"__next|_next/static", "Next.js"),
            (r"ng-version|angular", "Angular"),
            (r"react|__react", "React"),
            (r"vue", "Vue"),
        ]

        for pattern, name in patterns:
            if re.search(pattern, text) and name not in hints:
                hints.append(name)

        if hints:
            self._add_finding(
                "Recon - Stack Hint",
                "Info",
                "Detected possible technology stack hints in response body",
                location=response.url,
                payload=", ".join(hints[:6]),
            )

    def scan(self):
        response = self._safe_get(self.target_url)
        if not response:
            self._add_finding(
                "Recon - Connection Failed",
                "Low",
                "Unable to reach target during reconnaissance",
                location=self.target_url,
            )
            return self.vulnerabilities

        self._check_security_headers(response)
        self._discover_common_files()
        self._scan_homepage_structure(response)
        self._detect_stack_hints(response)

        return self.vulnerabilities
