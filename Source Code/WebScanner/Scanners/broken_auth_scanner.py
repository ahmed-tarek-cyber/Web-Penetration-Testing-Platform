#!/usr/bin/env python3
# Alternative Broken Authentication Scanner 

import requests
import argparse
import json
import random
import string
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

requests.packages.urllib3.disable_warnings()

class AltAuthScanner:
    def __init__(self, target_url, timeout=10):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'AltAuthScanner/1.0'})
        self.timeout = timeout
        self.vulnerabilities = []

    def random_string(self, length=8):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    def fetch(self, url):
        try:
            r = self.session.get(url, timeout=self.timeout, verify=False)
            return r
        except Exception:
            return None

    
    def check_https(self):
        parsed = urlparse(self.target_url)
        if parsed.scheme != 'https':
            self.vulnerabilities.append({
                'type': 'No HTTPS',
                'severity': 'Critical',
                'description': 'Site does not use HTTPS'
            })
        else:
            r = self.fetch(self.target_url)
            if r and 'Strict-Transport-Security' not in r.headers:
                self.vulnerabilities.append({
                    'type': 'Missing HSTS',
                    'severity': 'Medium',
                    'description': 'HTTPS used but without HSTS header'
                })

    def check_cookies(self):
        r = self.fetch(self.target_url)
        if not r:
            return
        for cookie in r.cookies:
            if not cookie.secure:
                self.vulnerabilities.append({
                    'type': 'Insecure Cookie',
                    'severity': 'High',
                    'description': f'Cookie {cookie.name} missing Secure flag'
                })
            if not cookie.has_nonstandard_attr('HttpOnly'):
                self.vulnerabilities.append({
                    'type': 'Cookie Accessible via JavaScript',
                    'severity': 'High',
                    'description': f'Cookie {cookie.name} missing HttpOnly flag'
                })
            if len(cookie.value) < 12:
                self.vulnerabilities.append({
                    'type': 'Weak Session ID',
                    'severity': 'High',
                    'description': f'Cookie {cookie.name} too short ({len(cookie.value)} chars)'
                })

    def check_forms(self):
        r = self.fetch(self.target_url)
        if not r:
            return
        soup = BeautifulSoup(r.text, 'html.parser')
        for form in soup.find_all('form'):
            inputs = [inp.get('type') for inp in form.find_all('input')]
            if 'password' in inputs:
                method = form.get('method', 'GET').upper()
                if method == 'GET':
                    self.vulnerabilities.append({
                        'type': 'Insecure HTTP Method',
                        'severity': 'Critical',
                        'description': 'Login form uses GET instead of POST'
                    })

                hidden_inputs = [inp.get('name','').lower() for inp in form.find_all('input', type='hidden')]
                if not any('csrf' in h or 'token' in h for h in hidden_inputs):
                    self.vulnerabilities.append({
                        'type': 'Missing CSRF Token',
                        'severity': 'High',
                        'description': 'Login form missing CSRF protection'
                    })

    def brute_force_test(self):

        test_url = self.target_url
        blocked = False
        for i in range(3):
            try:
                data = {'username': self.random_string(), 'password': 'wrong'}
                r = self.session.post(test_url, data=data, timeout=5)
                if r.status_code == 429:
                    blocked = True
                    break
            except:
                break
        if not blocked:
            self.vulnerabilities.append({
                'type': 'No Brute Force Protection',
                'severity': 'High',
                'description': 'No rate limiting detected'
            })

    def account_enum_test(self):

        try:
            data1 = {'username': 'admin', 'password': 'wrong'}
            data2 = {'username': 'nonexistent_' + self.random_string(), 'password': 'wrong'}
            r1 = self.session.post(self.target_url, data=data1, timeout=5)
            r2 = self.session.post(self.target_url, data=data2, timeout=5)
            if len(r1.text) != len(r2.text):
                self.vulnerabilities.append({
                    'type': 'Account Enumeration',
                    'severity': 'Medium',
                    'description': 'Different responses reveal valid accounts'
                })
        except:
            pass

    def scan(self):
        print(f"[*] Scanning {self.target_url}")
        self.check_https()
        self.check_cookies()
        self.check_forms()
        self.brute_force_test()
        self.account_enum_test()
        self.print_results()

    def print_results(self):
        print("\n=== Broken Authentication Scan Report ===")
        if not self.vulnerabilities:
            print(" No obvious vulnerabilities found")
        else:
            for i, v in enumerate(self.vulnerabilities, 1):
                print(f"{i}. [{v['severity']}] {v['type']} - {v['description']}")



def main():
    parser = argparse.ArgumentParser(description='Alternative Broken Authentication Scanner — Backend-Compatible')
    parser.add_argument('--url', required=True, help='Target website')
    parser.add_argument('--out', help='Save results to JSON file')
    args = parser.parse_args()

    scanner = AltAuthScanner(args.url)
    scanner.scan()

    if args.out:
        with open(args.out, 'w') as fp:
            json.dump(scanner.vulnerabilities, fp, indent=4)
        print(f"Saved to {args.out}")

if __name__ == '__main__':
    main()
