import html
import re
import uuid
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup


class UniversalXSSScanner:
    PARAM_PRIORITY = (
        "q", "query", "search", "keyword", "term",
        "name", "message", "comment", "text",
        "redirect", "url", "next", "return", "callback",
        "id", "user", "email", "username"
    )

    DOM_SOURCES = (
        "location.hash", "location.search", "location.href", "document.url",
        "document.referrer", "window.name", "document.cookie"
    )

    DOM_SINKS = (
        "document.write", "innerhtml", "outerhtml", "insertadjacenthtml",
        "eval(", "settimeout(", "setinterval(", "function(",
        "location=", "location.href=", "window.location", "jquery(" 
    )

    def __init__(self, target_url, timeout=10):
        self.target_url = target_url
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(
            {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) WebScanner-XSS/2.0"}
        )
        self.vulnerabilities = []
        self._seen_keys = set()
        self._base_host = ""

    def _payloads(self, marker):
        return [
            f'<script>alert("{marker}")</script>',
            f'\"><img src=x onerror=alert("{marker}")>',
            f"'><svg/onload=alert('{marker}')>",
            f'javascript:alert("{marker}")',
        ]

    def _marker(self):
        return f"xssc_{uuid.uuid4().hex[:8]}"

    def _normalize_url(self, url):
        parsed = urlparse(url)
        if parsed.scheme and parsed.netloc:
            return url
        return f"http://{url}"

    def _normalize_discovered_url(self, url):
        parsed = urlparse(url)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.params, parsed.query, ""))

    def _same_host(self, url):
        return urlparse(url).netloc == self._base_host

    def _safe_get(self, url):
        try:
            return self.session.get(url, timeout=self.timeout, allow_redirects=True)
        except requests.RequestException:
            return None

    def _safe_submit(self, method, url, data):
        try:
            if method == "POST":
                return self.session.post(url, data=data, timeout=self.timeout, allow_redirects=True)
            return self.session.get(url, params=data, timeout=self.timeout, allow_redirects=True)
        except requests.RequestException:
            return None

    def _add_vulnerability(self, vuln_type, severity, description, location=None, payload=None, payload2=None, **extra):
        key = (vuln_type, location or "", payload or "", payload2 or "")
        if key in self._seen_keys:
            return
        self._seen_keys.add(key)

        finding = {
            "type": vuln_type,
            "severity": severity,
            "description": description,
            "source": "Python: run_xss.py",
        }
        if location is not None:
            finding["location"] = location
        if payload is not None:
            finding["payload"] = payload
        if payload2 is not None:
            finding["payload2"] = payload2

        finding.update(extra)
        self.vulnerabilities.append(finding)

    def _prioritized_params(self, params):
        scored = []
        for name in params.keys():
            low = name.lower()
            score = 0
            for p in self.PARAM_PRIORITY:
                if low == p:
                    score += 3
                elif p in low:
                    score += 1
            scored.append((score, name))

        scored.sort(key=lambda x: (-x[0], x[1]))
        return [name for _, name in scored][:8]

    def _executable_reflection(self, body, marker):
        body_low = body.lower()
        marker_low = marker.lower()
        if marker_low not in body_low:
            return False, "marker-not-reflected"

        script_ctx = re.search(r"<script[^>]*>[^<]*" + re.escape(marker_low), body_low)
        attr_ctx = re.search(r"on\w+\s*=\s*['\"][^'\"]*" + re.escape(marker_low), body_low)
        js_ctx = re.search(r"javascript:\s*[^\s'\"]*" + re.escape(marker_low), body_low)

        if script_ctx:
            return True, "script-context"
        if attr_ctx:
            return True, "event-handler-context"
        if js_ctx:
            return True, "javascript-url-context"
        return False, "reflected-non-executable"

    def _encoded_only_reflection(self, body, payload):
        encoded_payload = html.escape(payload)
        return encoded_payload in body and payload not in body

    def _test_url_parameters(self, parsed_target):
        params = parse_qs(parsed_target.query)
        if not params:
            return

        candidate_params = self._prioritized_params(params)
        marker = self._marker()

        for param_name in candidate_params:
            for payload in self._payloads(marker):
                test_params = params.copy()
                test_params[param_name] = [payload]
                query = urlencode(test_params, doseq=True)
                test_url = f"{parsed_target.scheme}://{parsed_target.netloc}{parsed_target.path}?{query}"
                response = self._safe_get(test_url)
                if not response:
                    continue

                executable, ctx = self._executable_reflection(response.text, marker)
                if executable:
                    self._add_vulnerability(
                        "Reflected XSS",
                        "High",
                        f'Parameter "{param_name}" reflected executable payload',
                        location=test_url,
                        payload=payload,
                        payload2=f"parameter={param_name};context={ctx}",
                        parameter=param_name,
                        evidence=f"marker={marker}",
                    )
                    break

                if self._encoded_only_reflection(response.text, payload):
                    self._add_vulnerability(
                        "Reflected XSS (Sanitized Reflection)",
                        "Low",
                        f'Parameter "{param_name}" reflects encoded payload',
                        location=test_url,
                        payload=payload,
                        payload2=f"parameter={param_name};context=encoded",
                        parameter=param_name,
                        evidence=f"marker={marker}",
                    )
                    break

    def _extract_form_inputs(self, form):
        names = []
        for field in form.find_all(["input", "textarea"]):
            field_type = (field.get("type") or "text").lower()
            name = (field.get("name") or "").strip()
            if not name:
                continue
            if field_type in {"submit", "button", "hidden", "file", "image"}:
                continue
            names.append(name)
        return names[:6]

    def _crawl_targets(self, max_pages=20, max_depth=2):
        targets = []
        seen = set()
        queue = [(self.target_url, 0)]

        while queue and len(targets) < max_pages:
            page_url, depth = queue.pop(0)
            page_url = self._normalize_discovered_url(page_url)
            if page_url in seen or not self._same_host(page_url):
                continue
            seen.add(page_url)

            response = self._safe_get(page_url)
            if not response:
                continue

            content_type = response.headers.get("Content-Type", "")
            targets.append({"url": page_url, "response": response})
            if content_type and "html" not in content_type.lower():
                continue

            soup = BeautifulSoup(response.text, "html.parser")

            for form in soup.find_all("form"):
                method = (form.get("method") or "GET").upper()
                if method != "GET":
                    continue
                action = form.get("action") or ""
                form_url = urljoin(page_url, action) if action else page_url
                input_names = self._extract_form_inputs(form)
                if not input_names:
                    continue
                parsed_form = urlparse(form_url)
                existing = parse_qs(parsed_form.query)
                for name in input_names:
                    existing.setdefault(name, ["test"])
                query = urlencode(existing, doseq=True)
                queued_url = urlunparse((
                    parsed_form.scheme,
                    parsed_form.netloc,
                    parsed_form.path or "/",
                    parsed_form.params,
                    query,
                    "",
                ))
                if queued_url not in seen:
                    queue.append((queued_url, depth + 1))

            if depth >= max_depth:
                continue

            for tag in soup.find_all("a", href=True):
                href = tag["href"].strip()
                if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
                    continue
                link = self._normalize_discovered_url(urljoin(page_url, href))
                if self._same_host(link) and link not in seen:
                    queue.append((link, depth + 1))

        return targets

    def _test_forms(self, base_response, page_url=None):
        page_url = page_url or self.target_url
        soup = BeautifulSoup(base_response.text, "html.parser")
        forms = soup.find_all("form")
        if not forms:
            return

        marker = self._marker()
        payload = f'\"><svg/onload=alert("{marker}")>'

        for idx, form in enumerate(forms, start=1):
            method = (form.get("method") or "GET").upper()
            action = form.get("action") or ""
            form_url = urljoin(page_url, action) if action else page_url
            input_names = self._extract_form_inputs(form)
            if not input_names:
                continue

            for input_name in input_names:
                data = {name: "test" for name in input_names}
                data[input_name] = payload
                response = self._safe_submit(method, form_url, data)
                if not response:
                    continue

                executable, ctx = self._executable_reflection(response.text, marker)
                if executable:
                    self._add_vulnerability(
                        "Form-based XSS",
                        "High",
                        f'Form input "{input_name}" reflected executable payload',
                        location=form_url,
                        payload=payload,
                        payload2=f"form={idx};input={input_name};method={method};context={ctx}",
                        form=idx,
                        input=input_name,
                        method=method,
                        evidence=f"marker={marker}",
                    )
                    break

    def _collect_script_content(self, response, page_url=None):
        page_url = page_url or self.target_url
        soup = BeautifulSoup(response.text, "html.parser")
        scripts = []

        for script in soup.find_all("script"):
            inline = script.string or ""
            if inline.strip():
                scripts.append((page_url, inline.lower()))
                continue

            src = (script.get("src") or "").strip()
            if not src:
                continue
            src_url = urljoin(page_url, src)
            js_resp = self._safe_get(src_url)
            if js_resp and js_resp.text:
                scripts.append((src_url, js_resp.text.lower()))

            if len(scripts) >= 12:
                break

        return scripts

    def _analyze_dom_xss(self, response, page_url=None):
        scripts = self._collect_script_content(response, page_url=page_url)
        if not scripts:
            return

        for script_url, content in scripts:
            sink_hits = [s for s in self.DOM_SINKS if s in content]
            source_hits = [s for s in self.DOM_SOURCES if s in content]
            if not sink_hits or not source_hits:
                continue

            self._add_vulnerability(
                "Potential DOM-based XSS",
                "Medium",
                "DOM sink and user-controlled source detected in JavaScript",
                location=script_url,
                payload=sink_hits[0],
                payload2=f"source={source_hits[0]};sink={sink_hits[0]}",
                evidence="Manual verification required",
            )

    def _check_security_headers(self, response, page_url=None):
        page_url = page_url or self.target_url
        headers = response.headers
        csp = headers.get("Content-Security-Policy", "")

        if not csp:
            self._add_vulnerability(
                "Missing CSP Header",
                "Medium",
                "No Content-Security-Policy header found",
                location=page_url,
            )
        elif "'unsafe-inline'" in csp or "'unsafe-eval'" in csp:
            self._add_vulnerability(
                "Weak CSP Configuration",
                "Medium",
                "CSP allows unsafe directives that reduce XSS protection",
                location=page_url,
                payload=csp,
                payload2="contains unsafe-inline or unsafe-eval",
            )

        xcto = headers.get("X-Content-Type-Options", "")
        if xcto.lower() != "nosniff":
            self._add_vulnerability(
                "Missing X-Content-Type-Options",
                "Low",
                "Missing or invalid X-Content-Type-Options header",
                location=page_url,
            )

    def _check_content_type(self, response, page_url=None):
        page_url = page_url or self.target_url
        content_type = response.headers.get("Content-Type", "")
        if content_type and "charset" not in content_type.lower():
            self._add_vulnerability(
                "Missing Charset in Content-Type",
                "Low",
                "Content-Type header does not include charset",
                location=page_url,
                payload=content_type,
            )

    def scan(self):
        self.target_url = self._normalize_url(self.target_url)
        self._base_host = urlparse(self.target_url).netloc

        targets = self._crawl_targets()
        if not targets:
            response = self._safe_get(self.target_url)
            if not response:
                return self.vulnerabilities
            targets = [{"url": self.target_url, "response": response}]

        for target in targets:
            page_url = target["url"]
            response = target["response"]
            parsed_target = urlparse(page_url)

            self._test_url_parameters(parsed_target)
            self._test_forms(response, page_url=page_url)
            self._analyze_dom_xss(response, page_url=page_url)
            self._check_security_headers(response, page_url=page_url)
            self._check_content_type(response, page_url=page_url)

        return self.vulnerabilities
