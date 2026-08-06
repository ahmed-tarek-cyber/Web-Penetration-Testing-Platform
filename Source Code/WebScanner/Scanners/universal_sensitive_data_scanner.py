#!/usr/bin/env python3
"""
Alternative Sensitive Data Exposure Scanner 
"""

import re
import json
import time
import argparse
from urllib.parse import urlparse, urljoin
import requests
from bs4 import BeautifulSoup

requests.packages.urllib3.disable_warnings()

DEFAULT_HEADERS = {
    'User-Agent': 'AltSensitiveScanner/2.0'
}


PATTERNS = {
    'generic_api_key': re.compile(r'(?i)api[_-]?key\s*[:=]\s*[A-Za-z0-9]{12,}'),
    'email': re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'),
    'password_hint': re.compile(r'(?i)password\s*[:=]\s*\S+'),
    'jwt_like': re.compile(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')
}

SENSITIVE_FILES = ['.env', 'config.php', 'backup.sql', 'id_rsa']

class AltSensitiveDataScanner:
    def __init__(self, target_url, timeout=8, rate=0.5, crawl=False, depth=1, out_json=None):
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.rate = rate
        self.crawl = crawl
        self.depth = depth
        self.out_json = out_json
        self.session = requests.Session()
        self.session.headers.update(DEFAULT_HEADERS)
        self.vulnerabilities = []
        self.visited = set()

    def safe_get(self, url):
        try:
            return self.session.get(url, timeout=self.timeout, verify=False)
        except:
            return None

    def scan(self):
        print(f"[*] Starting alternative sensitive data scan on: {self.target_url}")
        urls = [self.target_url]
        if self.crawl:
            urls.extend(self._simple_crawl(self.target_url))

        for u in urls:
            if u in self.visited:
                continue
            self.visited.add(u)
            resp = self.safe_get(u)
            if not resp:
                continue
            self._check_headers(u, resp.headers)
            self._check_body(u, resp.text)
            self._check_sensitive_files(u)
            time.sleep(self.rate)

        self.print_results()

    def _check_headers(self, url, headers):
        server = headers.get('Server')
        if server:
            self._report('Server header disclosure', 'Low', url, 'Server header reveals technology', evidence=server)
        cookie = headers.get('Set-Cookie', '')
        if cookie and 'httponly' not in cookie.lower():
            self._report('Insecure Cookie', 'Medium', url, 'Cookie missing HttpOnly flag', evidence=cookie)

    def _check_body(self, url, body):
        for name, pat in PATTERNS.items():
            for m in pat.finditer(body):
                evidence = m.group(0)
                self._report(f'Pattern detected: {name}', 'High', url, f'Sensitive pattern "{name}" found', evidence=evidence)

        soup = BeautifulSoup(body, 'html.parser')
        for a in soup.find_all('a', href=True):
            href = a['href']
            if any(href.lower().endswith(f) for f in SENSITIVE_FILES):
                self._report('Link to sensitive file', 'Medium', url, f'Page links to {href}', evidence=href)

    def _check_sensitive_files(self, base_url):
        parsed = urlparse(base_url)
        root = f"{parsed.scheme}://{parsed.netloc}/"
        for f in SENSITIVE_FILES:
            test_url = urljoin(root, f)
            resp = self.safe_get(test_url)
            if resp and resp.status_code == 200:
                self._report('Accessible sensitive file', 'High', test_url, f'{f} accessible', evidence=resp.text[:100])

    def _simple_crawl(self, start_url):
        links = []
        resp = self.safe_get(start_url)
        if not resp:
            return links
        soup = BeautifulSoup(resp.text, 'html.parser')
        for a in soup.find_all('a', href=True):
            full = urljoin(start_url, a['href'])
            if urlparse(full).netloc == urlparse(start_url).netloc:
                links.append(full)
        return links

    def _report(self, v_type, severity, location, description, evidence=None):
        entry = {
            'type': v_type,
            'severity': severity,
            'location': location,
            'description': description,
            'evidence': evidence
        }
        self.vulnerabilities.append(entry)

    def print_results(self):
        print("\n=== Alternative Sensitive Data Scan Report ===")
        if not self.vulnerabilities:
            print("No exposures found")
        else:
            for i, v in enumerate(self.vulnerabilities, 1):
                print(f"{i}. [{v['severity']}] {v['type']} at {v['location']}")
                print(f"   Detail: {v['description']}")
                if v['evidence']:
                    print(f"   Evidence: {str(v['evidence'])[:80]}")

def main():
    parser = argparse.ArgumentParser(description='Alternative Sensitive Data Scanner — Backend-Compatible')
    parser.add_argument('--url', required=True, help='Target website')
    parser.add_argument('--crawl', action='store_true', help='Enable simple crawling')
    parser.add_argument('--depth', type=int, default=1, help='Crawl depth (unused in alt version)')
    parser.add_argument('--rate', type=float, default=0.5, help='Delay between requests')
    parser.add_argument('--out', help='Save results to JSON file')
    args = parser.parse_args()

    scanner = AltSensitiveDataScanner(args.url, rate=args.rate, crawl=args.crawl, depth=args.depth, out_json=args.out)
    scanner.scan()

    if args.out:
        with open(args.out, 'w') as fp:
            json.dump(scanner.vulnerabilities, fp, indent=4)
        print(f"Saved to {args.out}")

if __name__ == '__main__':
    main()
