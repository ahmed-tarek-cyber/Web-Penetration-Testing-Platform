#!/usr/bin/env python3
# Alternative CSRF Scanner 

import requests
import argparse
import json
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import random
import string
import time

requests.packages.urllib3.disable_warnings()


def random_token(length=16):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def fetch(url):
    try:
        r = requests.get(url, timeout=6, verify=False, allow_redirects=True)
        return r
    except Exception:
        return None



def crawl(start_url, limit=30):
    visited = set()
    stack = [start_url]
    pages = []

    while stack and len(pages) < limit:
        url = stack.pop()
        if url in visited:
            continue
        visited.add(url)

        r = fetch(url)
        if not r:
            continue

        pages.append(url)
        soup = BeautifulSoup(r.text, 'html.parser')
        for a in soup.find_all('a', href=True):
            full = urljoin(url, a['href'])
            if urlparse(full).netloc == urlparse(start_url).netloc and full not in visited:
                stack.append(full)

    return pages

def extract_forms(html, base_url):
    soup = BeautifulSoup(html, 'html.parser')
    forms = []
    for form in soup.find_all('form'):
        action = form.get('action') or ''
        method = (form.get('method') or 'GET').upper()
        inputs = {inp.get('name'): inp.get('value') for inp in form.find_all('input') if inp.get('name')}
        full_action = urljoin(base_url, action)
        forms.append({'action': full_action, 'method': method, 'inputs': inputs})
    return forms


def detect_token_field(inputs):
    keywords = ['csrf', 'xsrf', 'token', '_token', 'authenticity']
    for name in inputs.keys():
        if any(k in name.lower() for k in keywords):
            return name
    return None

def token_strength(token):
    if not token:
        return 'missing'
    if len(token) < 12:
        return 'weak'
    if any(c in "!@#$%^&*" for c in token):
        return 'strong'
    return 'predictable'


def test_csrf(form):
    test_data = form['inputs'].copy()
    for k in test_data:
        test_data[k] = random_token()
    try:
        if form['method'] == 'POST':
            r = requests.post(form['action'], data=test_data, timeout=6, verify=False)
        else:
            r = requests.get(form['action'], params=test_data, timeout=6, verify=False)

        return r.status_code, len(r.text)
    except Exception:
        return None, None


def analyze_form(form, page_url):
    result = {
        'page': page_url,
        'action': form['action'],
        'method': form['method'],
        'token_name': None,
        'token_strength': None,
        'bypass_possible': False,
        'details': ''
    }

    token_name = detect_token_field(form['inputs'])
    result['token_name'] = token_name

    if not token_name:
        result['token_strength'] = 'missing'
        result['bypass_possible'] = True
        result['details'] = 'Form has no CSRF token.'
        return result

    token_value = form['inputs'].get(token_name)
    result['token_strength'] = token_strength(token_value)

    status, size = test_csrf(form)
    if status and size and size > 100:
        result['bypass_possible'] = True
        result['details'] = f'CSRF token bypassed (response size={size}).'
    else:
        result['details'] = 'CSRF token appears enforced.'

    return result


def scan_page(url):
    r = fetch(url)
    if not r:
        return []
    forms = extract_forms(r.text, url)
    results = []
    for f in forms:
        results.append(analyze_form(f, url))
    return results


def main():
    parser = argparse.ArgumentParser(description='Alternative CSRF Scanner — Different Logic, Backend-Compatible')
    parser.add_argument('--url', required=True, help='Target website')
    parser.add_argument('--limit', type=int, default=30, help='Max pages to crawl')
    parser.add_argument('--out', help='Save results to JSON file')

    args = parser.parse_args()

    print(f"[*] Crawling: {args.url}")
    pages = crawl(args.url, limit=args.limit)

    print(f"[+] Discovered {len(pages)} pages")

    all_results = []
    for p in pages:
        print(f"[*] Scanning: {p}")
        all_results.extend(scan_page(p))

    print("=== Summary ===")
    for r in all_results:
        status = "VULNERABLE" if r['bypass_possible'] else "OK"
        print(f"[+] {status} | {r['method']} | {r['action']} | {r['details']}")

    if args.out:
        with open(args.out, 'w') as fp:
            json.dump(all_results, fp, indent=4)
        print(f"Saved to {args.out}")

if __name__ == '__main__':
    main()
