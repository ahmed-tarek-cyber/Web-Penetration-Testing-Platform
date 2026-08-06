#!/usr/bin/env python3
"""
Professional Open Redirect Vulnerability Scanner
Version: 2.1
For authorized security testing only
"""

import requests
import re
import urllib.parse
import time
import logging
import threading
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup
from typing import List, Tuple
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('open_redirect_scan.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


@dataclass
class Vulnerability:
    """Data class for vulnerability information"""
    vuln_type: str
    parameter: str
    payload: str
    url: str
    method: str
    redirect_location: str
    status_code: int
    confidence: str  # high, medium, low

    def dedup_key(self) -> tuple:
        """Unique key used to deduplicate identical findings"""
        return (self.parameter, self.payload, self.redirect_location)


class ScanState:
    """Thread-safe deduplication guard that writes into an external list.

    The scanner keeps ``self.vulnerabilities`` as the public attribute (same as
    v2.0); ScanState only adds the lock + seen-key set so concurrent threads
    don't produce duplicate entries or corrupt the list.
    """

    def __init__(self, vulnerabilities: List[Vulnerability]):
        self._vulnerabilities = vulnerabilities   # reference to scanner.vulnerabilities
        self._seen_keys: set = set()
        self._lock = threading.Lock()

    def add(self, vuln: Vulnerability) -> bool:
        """Append vuln to the shared list; return True only when it is new."""
        key = vuln.dedup_key()
        with self._lock:
            if key in self._seen_keys:
                return False
            self._seen_keys.add(key)
            self._vulnerabilities.append(vuln)
            return True


class RateLimiter:
    """Thread-safe token-bucket rate limiter"""

    def __init__(self, max_requests: int = 10, time_window: float = 1.0):
        self.max_requests = max_requests
        self.time_window = time_window
        self._lock = threading.Lock()
        self._timestamps: List[float] = []

    def wait_if_needed(self):
        """Block until sending another request is within the rate limit."""
        while True:
            with self._lock:
                now = time.time()
                # Evict timestamps outside the window
                self._timestamps = [t for t in self._timestamps if now - t < self.time_window]

                if len(self._timestamps) < self.max_requests:
                    self._timestamps.append(now)
                    return

                # Determine how long to sleep before the oldest slot frees up
                sleep_time = self.time_window - (now - self._timestamps[0])

            if sleep_time > 0:
                time.sleep(sleep_time)


class OpenRedirectScanner:
    """Professional Open Redirect Vulnerability Scanner"""

    def __init__(self, target_url: str, max_workers: int = 5, timeout: int = 10):
        self.target_url = target_url
        self.timeout = timeout
        self.max_workers = max_workers
        self.vulnerabilities: List[Vulnerability] = []   # public — same as v2.0
        self._state = ScanState(self.vulnerabilities)
        self.rate_limiter = RateLimiter(max_requests=10, time_window=1)

        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'close'
        })

        self.test_domains = [
            'http://evil.com',
            'https://attacker.com',
            'http://redirect-test.io'
        ]

        self.redirect_params = [
            'redirect', 'url', 'next', 'target', 'rurl', 'dest', 'destination',
            'redir', 'redirect_url', 'redirect_uri', 'return', 'returnUrl',
            'return_url', 'callback', 'continue', 'r', 'u', 'goto', 'link',
            'forward', 'out', 'return_to', 'redirect_to', 'checkout_url'
        ]

        # Build payloads once; reuse across all tests
        self._payloads: List[str] = self._build_payloads()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_payloads(self) -> List[str]:
        """Build a deduplicated payload list (called once during __init__)."""
        payloads = []

        for domain in self.test_domains:
            host = urlparse(domain).netloc

            payloads.extend([
                domain,
                f"//{host}",
                urllib.parse.quote(domain),
                urllib.parse.quote_plus(domain),
                domain.replace(':', '%3A').replace('/', '%2F'),
                domain.replace('http://', 'http:/'),
                domain.replace('https://', 'https:/'),
                f"\\\\{host}",
                f"http://@{host}",
                f"http://localhost@{host}",
                f"http://127.0.0.1@{host}",
            ])

        payloads.extend([
            '//evil.com',
            '//evil.com/',
            '///evil.com',
            '////evil.com',
            'https:evil.com',
            'http:evil.com',
            '//google.com@evil.com',
            'javascript:alert(1)',
            'data:text/html,<script>alert(1)</script>',
        ])

        # Preserve insertion order while removing duplicates
        seen = set()
        unique = []
        for p in payloads:
            if p not in seen:
                seen.add(p)
                unique.append(p)
        return unique

    def _get_absolute_url(self, relative_url: str) -> str:
        """Convert a relative URL to absolute using self.target_url as base."""
        if relative_url.startswith(('http://', 'https://')):
            return relative_url

        parsed = urlparse(self.target_url)
        if relative_url.startswith('/'):
            return f"{parsed.scheme}://{parsed.netloc}{relative_url}"

        base = self.target_url.rsplit('/', 1)[0]
        return f"{base}/{relative_url}" if relative_url else self.target_url

    # ------------------------------------------------------------------
    # Public API preserved from v2.0
    # ------------------------------------------------------------------

    def generate_payloads(self) -> List[str]:
        """Return the pre-built payload list (kept for API compatibility)."""
        return self._payloads

    def verify_connection(self) -> bool:
        """Verify target is accessible."""
        try:
            logger.info(f"Testing connection to: {self.target_url}")
            response = self.session.get(
                self.target_url,
                timeout=self.timeout,
                allow_redirects=True,
                verify=False
            )
            logger.info(f"Connection successful - Status: {response.status_code}")
            return True
        except requests.exceptions.RequestException as e:
            logger.error(f"Connection failed: {str(e)}")
            return False

    def is_vulnerable(self, response: requests.Response, payload: str) -> Tuple[bool, str]:
        """
        Analyze response to determine if vulnerable.
        Returns: (is_vulnerable, confidence_level)
        """
        if response.status_code in [301, 302, 303, 307, 308]:
            location = response.headers.get('Location', '')

            if not location:
                return False, 'none'

            try:
                parsed_location = urlparse(location)
                parsed_target = urlparse(self.target_url)

                if parsed_location.netloc and parsed_location.netloc != parsed_target.netloc:
                    payload_clean = (
                        payload.lower()
                        .replace('http://', '')
                        .replace('https://', '')
                        .replace('//', '')
                        .strip('/')
                    )
                    location_clean = (
                        location.lower()
                        .replace('http://', '')
                        .replace('https://', '')
                        .replace('//', '')
                    )

                    if payload_clean in location_clean:
                        return True, 'high'

                    test_hosts = ['evil.com', 'attacker.com', 'redirect-test.io']
                    if any(host in location_clean for host in test_hosts):
                        return True, 'high'

                    return True, 'medium'

            except Exception as e:
                logger.debug(f"Error parsing redirect: {e}")

        # Check for meta refresh
        if response.status_code == 200:
            meta_pattern = (
                r'<meta[^>]+http-equiv=["\']refresh["\'][^>]*'
                r'content=["\'][^"\']*url=([^"\']*)["\']'
            )
            matches = re.findall(meta_pattern, response.text, re.IGNORECASE)

            for match in matches:
                if any(
                    domain.replace('http://', '') in match.lower()
                    for domain in self.test_domains
                ):
                    return True, 'medium'

        return False, 'none'

    def test_parameter(self, param_name: str, base_url: str, method: str = 'GET') -> List[Vulnerability]:
        """Test a specific parameter with all payloads; duplicates are silently skipped."""
        found_vulns: List[Vulnerability] = []
        parsed_url = urlparse(base_url)

        logger.info(f"Testing parameter: {param_name}")

        for payload in self._payloads[:30]:
            try:
                self.rate_limiter.wait_if_needed()

                params = parse_qs(parsed_url.query) if parsed_url.query else {}
                params[param_name] = [payload]
                new_query = urlencode(params, doseq=True)

                test_url = urlunparse((
                    parsed_url.scheme,
                    parsed_url.netloc,
                    parsed_url.path,
                    parsed_url.params,
                    new_query,
                    ''
                ))

                response = self.session.get(
                    test_url,
                    timeout=self.timeout,
                    allow_redirects=False,
                    verify=False
                )

                is_vuln, confidence = self.is_vulnerable(response, payload)

                if is_vuln:
                    vuln = Vulnerability(
                        vuln_type='Open Redirect - Parameter',
                        parameter=param_name,
                        payload=payload,
                        url=test_url,
                        method=method,
                        redirect_location=response.headers.get('Location', 'N/A'),
                        status_code=response.status_code,
                        confidence=confidence
                    )
                    if self._state.add(vuln):
                        found_vulns.append(vuln)
                        logger.warning(
                            f"Vulnerability found! Parameter: {param_name}, Payload: {payload}"
                        )

            except requests.exceptions.Timeout:
                logger.debug(f"Timeout for payload: {payload}")
            except requests.exceptions.RequestException as e:
                logger.debug(f"Request error: {str(e)}")
            except Exception as e:
                logger.error(f"Unexpected error: {str(e)}")

        return found_vulns

    def scan_url_parameters(self):
        """Scan existing URL parameters (threaded)."""
        logger.info("Starting URL parameter scan")

        parsed_url = urlparse(self.target_url)
        if not parsed_url.query:
            logger.info("No URL parameters found")
            return

        params = parse_qs(parsed_url.query)

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self.test_parameter, name, self.target_url, 'GET'): name
                for name in params
            }
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Thread error: {str(e)}")

    def scan_common_parameters(self):
        """Test common redirect parameters (threaded, consistent with scan_url_parameters)."""
        logger.info("Testing common redirect parameters")

        base_url = self.target_url.split('?')[0]

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self.test_parameter, param, base_url, 'GET'): param
                for param in self.redirect_params[:15]
            }
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Thread error: {str(e)}")

    def scan_forms(self):
        """Scan HTML forms for redirect vulnerabilities."""
        logger.info("Scanning HTML forms")

        try:
            response = self.session.get(self.target_url, timeout=self.timeout, verify=False)
            soup = BeautifulSoup(response.content, 'html.parser')
            forms = soup.find_all('form')

            logger.info(f"Found {len(forms)} form(s)")

            for form in forms:
                action = form.get('action', '')
                method = form.get('method', 'get').upper()

                for input_tag in form.find_all('input'):
                    input_name = input_tag.get('name')
                    if input_name and any(
                        rp in input_name.lower() for rp in self.redirect_params
                    ):
                        form_url = self._get_absolute_url(action)
                        self.test_parameter(input_name, form_url, method)

        except Exception as e:
            logger.error(f"Form scanning error: {str(e)}")

    def scan(self):
        """Alias for run_scan() — used by external wrappers."""
        return self.run_scan()

    def run_scan(self):
        """Execute complete scan."""
        logger.info("=" * 80)
        logger.info("Starting Open Redirect Vulnerability Scan")
        logger.info(f"Target: {self.target_url}")
        logger.info("=" * 80)

        if not self.verify_connection():
            logger.error("Cannot proceed - connection failed")
            return

        self.scan_url_parameters()
        self.scan_common_parameters()
        self.scan_forms()

        self._display_results()

    def _display_results(self):
        """Display scan results."""
        logger.info("=" * 80)
        logger.info("SCAN RESULTS")
        logger.info("=" * 80)

        if not self.vulnerabilities:
            logger.info("No vulnerabilities detected")
            logger.info("Note: This does not guarantee complete security")
        else:
            logger.warning(f"FOUND {len(self.vulnerabilities)} VULNERABILITY/VULNERABILITIES")

            high_conf = [v for v in self.vulnerabilities if v.confidence == 'high']
            medium_conf = [v for v in self.vulnerabilities if v.confidence == 'medium']

            if high_conf:
                logger.warning(f"\nHIGH CONFIDENCE: {len(high_conf)}")
                for vuln in high_conf[:5]:
                    logger.warning(f"  Parameter: {vuln.parameter}")
                    logger.warning(f"  Payload: {vuln.payload}")
                    logger.warning(f"  Redirects to: {vuln.redirect_location}")
                    logger.warning(f"  URL: {vuln.url}")
                    logger.warning("")

            if medium_conf:
                logger.info(f"\nMEDIUM CONFIDENCE: {len(medium_conf)}")
                for vuln in medium_conf[:3]:
                    logger.info(f"  Parameter: {vuln.parameter}")
                    logger.info(f"  Payload: {vuln.payload}")
                    logger.info("")

        logger.info("=" * 80)
        logger.info("RECOMMENDATIONS:")
        logger.info("- Validate all redirect URLs against allowlist")
        logger.info("- Use indirect reference maps for redirects")
        logger.info("- Implement proper input validation")
        logger.info("- Log and monitor redirect attempts")
        logger.info("=" * 80)


# ------------------------------------------------------------------
# Entry point — input/output identical to v2.0
# ------------------------------------------------------------------

def main():
    """Main entry point"""
    print("=" * 80)
    print("Professional Open Redirect Scanner v2.0")
    print("=" * 80)
    print()

    target = input("Enter target URL: ").strip()

    if not target:
        print("Error: URL required")
        return

    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target

    print()

    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    scanner = OpenRedirectScanner(target, max_workers=3, timeout=10)
    scanner.run_scan()

    print("\nScan complete. Check 'open_redirect_scan.log' for details")


if __name__ == "__main__":
    main()