import re
from difflib import SequenceMatcher
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup


class IDORScanner:
    PARAM_KEYWORDS = (
        "id", "user", "uid", "userid", "account", "profile",
        "order", "invoice", "doc", "file", "record", "customer"
    )

    FAIL_MARKERS = (
        "unauthorized", "forbidden", "access denied", "permission denied",
        "not allowed", "login required", "token invalid"
    )

    SENSITIVE_MARKERS = (
        "email", "username", "phone", "address", "account", "profile",
        "customer", "order", "invoice", "ssn", "token"
    )

    COMMON_ENDPOINTS = (
        "/api/users/{id}",
        "/api/user/{id}",
        "/api/orders/{id}",
        "/api/invoices/{id}",
        "/users/{id}",
        "/profile/{id}",
    )

    def __init__(self, target_url, timeout=8):
        self.target_url = self._normalize_url(target_url)
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(
            {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) WebScanner-IDOR/2.0"}
        )
        self.vulnerable_endpoints = []
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

    def _is_same_origin(self, url):
        base = urlparse(self.target_url)
        u = urlparse(url)
        return (u.scheme, u.netloc) == (base.scheme, base.netloc)

    def _normalized_text(self, text):
        if not text:
            return ""
        cleaned = text.lower()
        cleaned = re.sub(r"\b\d+\b", "N", cleaned)
        cleaned = re.sub(r"[a-f0-9]{24,}", "HEX", cleaned)
        cleaned = re.sub(r"\s+", " ", cleaned)
        return cleaned[:4000]

    def _is_fail_response(self, resp):
        if resp.status_code in {401, 403, 404}:
            return True
        text = (resp.text or "").lower()
        return any(marker in text for marker in self.FAIL_MARKERS)

    def _similar_enough(self, a_text, b_text):
        if not a_text or not b_text:
            return False
        score = SequenceMatcher(None, a_text, b_text).ratio()
        return score >= 0.72

    def _contains_sensitive_data(self, text):
        low = (text or "").lower()
        return any(marker in low for marker in self.SENSITIVE_MARKERS)

    def _is_spa_shell(self, resp):
        if not resp:
            return False
        ctype = (resp.headers.get("Content-Type", "") or "").lower()
        if "text/html" not in ctype:
            return False
        low = (resp.text or "").lower()
        markers = ("<app-root", "<base href=", "id=\"root\"", "<title>scanly", "<title>angular")
        return any(m in low for m in markers)

    def _is_numeric(self, value):
        try:
            int(value)
            return True
        except Exception:
            return False

    def _mutate_value(self, original):
        variants = []
        s = str(original)

        if self._is_numeric(s):
            base = int(s)
            variants.extend([base + 1, base + 2, max(base - 1, 1), 1, 2, 9999])
            return [str(v) for v in dict.fromkeys(v for v in variants if int(v) != base)]

        match = re.search(r"\d+", s)
        if match:
            n = int(match.group(0))
            variants.extend([
                s.replace(match.group(0), str(n + 1), 1),
                s.replace(match.group(0), str(max(n - 1, 1)), 1),
                s.replace(match.group(0), "1", 1),
            ])
        else:
            variants.extend(["admin", "user1", "guest", "test"])

        return list(dict.fromkeys(v for v in variants if v != s))

    def _add_finding(self, finding_type, parameter, original_value, test_value, url, response, reason):
        key = (finding_type, parameter, url, str(test_value))
        if key in self._seen:
            return
        self._seen.add(key)

        self.vulnerable_endpoints.append(
            {
                "type": finding_type,
                "parameter": parameter,
                "original_value": str(original_value),
                "test_value": str(test_value),
                "url": url,
                "status_code": response.status_code,
                "content_length": len(response.text or ""),
                "reason": reason,
            }
        )

    def _suspicious_access(self, baseline, test_resp):
        if not baseline or not test_resp:
            return False, "no-response"

        if self._is_fail_response(test_resp):
            return False, "blocked-response"

        if baseline.status_code not in {200, 201} or test_resp.status_code not in {200, 201}:
            return False, "non-success-status"

        if self._is_spa_shell(baseline) and self._is_spa_shell(test_resp):
            return False, "spa-shell-fallback"

        base_len = len(baseline.text or "")
        test_len = len(test_resp.text or "")
        if base_len < 80 or test_len < 80:
            return False, "tiny-response"

        size_ratio = abs(base_len - test_len) / max(base_len, 1)
        sim = self._similar_enough(self._normalized_text(baseline.text), self._normalized_text(test_resp.text))
        sensitive = self._contains_sensitive_data(test_resp.text)

        if sim and size_ratio <= 0.45:
            return True, f"similar-structure;size-delta={size_ratio:.2f}"
        if sensitive and size_ratio <= 0.55:
            return True, f"sensitive-content;size-delta={size_ratio:.2f}"

        return False, "insufficient-signal"

    def _priority_params(self, params):
        items = []
        for p in params:
            low = p.lower()
            score = 0
            for kw in self.PARAM_KEYWORDS:
                if low == kw:
                    score += 4
                elif kw in low:
                    score += 1
            items.append((score, p))

        items.sort(key=lambda x: (-x[0], x[1]))
        return [p for _, p in items][:8]

    def _discover_urls(self):
        urls = {self.target_url}
        resp = self._safe_get(self.target_url)
        if not resp:
            return list(urls)

        soup = BeautifulSoup(resp.text, "html.parser")
        for a in soup.find_all("a"):
            href = (a.get("href") or "").strip()
            if not href:
                continue
            absolute = urljoin(self.target_url, href)
            if not self._is_same_origin(absolute):
                continue

            parsed = urlparse(absolute)
            if parsed.scheme in {"http", "https"}:
                urls.add(urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", parsed.query, "")))

            if len(urls) >= 40:
                break

        return list(urls)

    def _test_query_params(self, url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            return

        baseline = self._safe_get(url)
        if not baseline:
            return

        for param in self._priority_params(params.keys()):
            original = (params.get(param) or [""])[0]
            for test_value in self._mutate_value(original)[:4]:
                changed = params.copy()
                changed[param] = [test_value]
                query = urlencode(changed, doseq=True)
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", query, ""))
                test_resp = self._safe_get(test_url)
                if not test_resp:
                    continue

                ok, reason = self._suspicious_access(baseline, test_resp)
                if ok:
                    self._add_finding(
                        "IDOR (Parameter Tampering)",
                        param,
                        original,
                        test_value,
                        test_url,
                        test_resp,
                        reason,
                    )
                    break

    def _test_path_ids(self, url):
        parsed = urlparse(url)
        parts = [p for p in parsed.path.split("/") if p]
        if not parts:
            return

        baseline = self._safe_get(url)
        if not baseline:
            return

        for idx, part in enumerate(parts):
            if not self._is_numeric(part):
                continue

            original = part
            for test_value in self._mutate_value(part)[:4]:
                new_parts = parts[:]
                new_parts[idx] = test_value
                new_path = "/" + "/".join(new_parts)
                test_url = urlunparse((parsed.scheme, parsed.netloc, new_path, "", parsed.query, ""))
                test_resp = self._safe_get(test_url)
                if not test_resp:
                    continue

                ok, reason = self._suspicious_access(baseline, test_resp)
                if ok:
                    self._add_finding(
                        "IDOR (Path ID Tampering)",
                        "path_id",
                        original,
                        test_value,
                        test_url,
                        test_resp,
                        reason,
                    )
                    break

    def _test_common_endpoints(self):
        parsed = urlparse(self.target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for template in self.COMMON_ENDPOINTS:
            url_1 = base + template.format(id=1)
            url_2 = base + template.format(id=2)
            r1 = self._safe_get(url_1)
            r2 = self._safe_get(url_2)
            if not r1 or not r2:
                continue

            c1 = (r1.headers.get("Content-Type", "") or "").lower()
            c2 = (r2.headers.get("Content-Type", "") or "").lower()
            if "application/json" not in c1 or "application/json" not in c2:
                continue

            if self._is_spa_shell(r1) or self._is_spa_shell(r2):
                continue

            ok, reason = self._suspicious_access(r1, r2)
            if ok:
                self._add_finding(
                    "IDOR (Predictable Endpoint Access)",
                    "id",
                    1,
                    2,
                    url_2,
                    r2,
                    reason,
                )

    def scan_for_idor(self):
        urls = self._discover_urls()
        for url in urls:
            self._test_query_params(url)
            self._test_path_ids(url)

        self._test_common_endpoints()
        return self.vulnerable_endpoints


class FastIDORScanner(IDORScanner):
    pass