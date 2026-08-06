import re
import json
import sys
import os
import math
import multiprocessing as mp
from typing import List, Set, Tuple

try:
    import esprima  # type: ignore[import-not-found]
except ImportError:
    esprima = None

try:
    from bs4 import BeautifulSoup  # type: ignore[import-not-found]
except ImportError:
    BeautifulSoup = None

# Configuration
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB
SCAN_TIMEOUT = 30  # seconds
DEDUP_KEY_CACHE: Set[Tuple] = set()


def get_entropy(data):
    """Calculate Shannon entropy to filter out dummy/low-entropy strings."""
    if not data or len(data) < 2:
        return 0
    entropy = 0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return entropy


RULES = [
    {"id": "AWS-KEY", "name": "AWS Access Key", "regex": re.compile(r"(?i)(AKIA|ASIA)[0-9A-Z]{16}"), "severity": "Critical"},
    {"id": "GOOGLE-KEY", "name": "Google API Key", "regex": re.compile(r"AIza[0-9A-Za-z_-]{35}"), "severity": "High"},
    {"id": "HARDCODED-SEC", "name": "Hardcoded Secret/Token", "regex": re.compile(r"(?i)(password|secret|token|api_key|private_key)[\s]*[=:]\s*['\"]([^'\"]{6,})['\"]"), "severity": "Critical"},
    {"id": "JWT-TOKEN", "name": "JWT Token", "regex": re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]+"), "severity": "High"},
    {"id": "INTERNAL-API", "name": "Admin/Internal API Endpoint", "regex": re.compile(r"(/api/(admin|internal|debug|private)[^\"'\s>]*)"), "severity": "Medium"},
    {"id": "S3-BUCKET", "name": "S3 Bucket URL", "regex": re.compile(r"(?i)[\"'](https?://[a-zA-Z0-9._-]+\.s3[.-][a-zA-Z0-9._-]*\.amazonaws\.com[^\"']*)[\"']"), "severity": "High"},
    {"id": "DEBUG-MODE", "name": "Debug Mode Enabled", "regex": re.compile(r"(?i)(debug|DEBUG)\s*[=:]\s*(true|1|yes)"), "severity": "Medium"},
    {"id": "SQLI-CONCAT", "name": "Potential SQLi (String Concatenation)", "regex": re.compile(r"(?i)(SELECT|UPDATE|DELETE|INSERT)\s+.+[\+\s]+[a-zA-Z0-9_.]+"), "severity": "Critical"},
    {"id": "IDOR-URL", "name": "Insecure Direct Object Reference", "regex": re.compile(r"(?i)(/api/(?:users|profile|data|account)/)\s*\+\s*[a-zA-Z0-9_]+"), "severity": "High"},
    {"id": "AUTH-BYPASS", "name": "Client-Side Privilege Storage", "regex": re.compile(r"(?i)localStorage\.(set|get)Item\(['\"](role|is_admin|permissions|privilege)['\"]"), "severity": "High"},
    {"id": "HTML-INPUT", "name": "Sensitive Hidden Input Field", "regex": re.compile(r"(?i)<input[^>]*type=[\"']hidden[\"'][^>]*name=[\"'](role|admin|price|token|user_id|id)[\"'][^>]*>"), "severity": "Medium"},
    {"id": "GITHUB-TOKEN", "name": "GitHub Token/PAT", "regex": re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,255}"), "severity": "Critical"},
    {"id": "SLACK-TOKEN", "name": "Slack Token", "regex": re.compile(r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9_-]{24,34}"), "severity": "High"},
]

# DOM XSS Sinks - Extended list
DOM_XSS_SINKS = [
    'innerHTML', 'outerhtml', 'insertadjacenthtml', 'insertadjacenttext',
    'document.write', 'document.writeln', 'eval', 'settimeout', 'setinterval',
    'innertext', 'textcontent', 'createcontextualfragment', 'replacechild'
]

# DOM Sources - User-controlled input points
DOM_SOURCES = [
    'location.hash', 'location.search', 'location.href', 'document.url',
    'document.referrer', 'window.name', 'document.cookie', 'window.location'
]


def walk_ast(node, results, filepath, content_lines):
    """Traverse AST to detect dangerous patterns and potential data flows."""
    if not isinstance(node, dict):
        if isinstance(node, list):
            for item in node:
                walk_ast(item, results, filepath, content_lines)
        return

    if node.get('type') == 'AssignmentExpression':
        left = node.get('left', {})

        if left.get('type') == 'MemberExpression':
            prop = left.get('property', {})
            sink_name = prop.get('name', '').lower()

            if sink_name in DOM_XSS_SINKS:
                line_num = node.get('loc', {}).get('start', {}).get('line', 1)
                dedup_key = (filepath, line_num, 'DOM_XSS_SINK', sink_name)
                if dedup_key not in DEDUP_KEY_CACHE:
                    DEDUP_KEY_CACHE.add(dedup_key)
                    context = _get_context_line(content_lines, line_num)
                    results.append({
                        "vuln_id": "DOM-XSS-SINK",
                        "name": f"DOM XSS Sink: {sink_name}",
                        "severity": "High",
                        "file": filepath,
                        "line": line_num,
                        "match": sink_name,
                        "context": context
                    })

    elif node.get('type') == 'CallExpression':
        callee = node.get('callee', {})
        func_name = callee.get('name', '').lower() if isinstance(callee, dict) else ''

        if func_name == 'eval':
            line_num = node.get('loc', {}).get('start', {}).get('line', 1)
            dedup_key = (filepath, line_num, 'EVAL_CALL')
            if dedup_key not in DEDUP_KEY_CACHE:
                DEDUP_KEY_CACHE.add(dedup_key)
                context = _get_context_line(content_lines, line_num)
                results.append({
                    "vuln_id": "AST-EVAL",
                    "name": "Unsafe eval() Execution",
                    "severity": "Critical",
                    "file": filepath,
                    "line": line_num,
                    "match": "eval()",
                    "context": context
                })

    for key, value in node.items():
        walk_ast(value, results, filepath, content_lines)


def _get_context_line(content_lines: List[str], line_num: int) -> str:
    """Extract context line from content."""
    if line_num <= 0 or line_num > len(content_lines):
        return "Line not found"
    line = content_lines[line_num - 1].strip()
    if len(line) > 150:
        line = line[:147] + "..."
    return line


def analyze_ast(filepath, content):
    """Parse JavaScript and traverse AST for security vulnerabilities."""
    results = []
    if not esprima:
        return results

    content_lines = content.split('\n')
    try:
        tree = esprima.parseScript(content, {"loc": True, "range": True})
        walk_ast(tree.toDict(), results, filepath, content_lines)
    except Exception:
        pass

    return results


def extract_js_from_html(html_content):
    """Extract JavaScript from HTML <script> tags and preserve line mapping."""
    if not BeautifulSoup:
        return None

    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        scripts = []

        for idx, script_tag in enumerate(soup.find_all('script'), 1):
            if script_tag.string:
                js_code = script_tag.string
                scripts.append({
                    'code': js_code,
                    'inline': True,
                    'index': idx
                })

        return scripts if scripts else None
    except Exception:
        return None


def scan_html_for_embedded_js(filepath, content):
    """Scan HTML content for embedded JavaScript vulnerabilities."""
    results = []
    extracted_scripts = extract_js_from_html(content)

    if not extracted_scripts:
        return results

    for script_data in extracted_scripts:
        js_code = script_data['code']
        script_idx = script_data['index']

        if esprima:
            try:
                js_lines = js_code.split('\n')
                tree = esprima.parseScript(js_code, {"loc": True})
                ast_results = []
                walk_ast(tree.toDict(), ast_results, filepath, js_lines)

                for vuln in ast_results:
                    vuln['context'] = f"Embedded script #{script_idx}, line {vuln.get('line', '?')}"
                    results.append(vuln)
            except Exception:
                pass

    return results


def scan_content(filepath, content):
    """Perform line-by-line regex scanning and AST analysis."""
    results = []
    lines = content.split('\n')
    seen_findings = set()

    for line_num, line in enumerate(lines, 1):
        for rule in RULES:
            for match in rule["regex"].finditer(line):
                payload = match.group(0).strip()

                if rule["id"] == "HARDCODED-SEC":
                    secret_value = match.group(2) if len(match.groups()) > 1 else ""
                    if secret_value and get_entropy(secret_value) < 3.5:
                        continue

                dedup_key = (rule["id"], line_num, payload[:50])
                if dedup_key in seen_findings:
                    continue
                seen_findings.add(dedup_key)

                context = line.strip()
                if len(context) > 150:
                    context = context[:147] + "..."

                results.append({
                    "vuln_id": rule["id"],
                    "name": rule["name"],
                    "severity": rule["severity"],
                    "file": filepath,
                    "line": line_num,
                    "match": payload,
                    "context": context
                })

    if filepath.lower().endswith('.js'):
        ast_results = analyze_ast(filepath, content)
        results.extend(ast_results)

    elif filepath.lower().endswith(('.html', '.htm')):
        html_ast_results = scan_html_for_embedded_js(filepath, content)
        results.extend(html_ast_results)

    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    results.sort(key=lambda x: (severity_order.get(x.get("severity", "Info"), 5), x.get("line", 0)))

    return results


def run_scan_worker(queue, scan_target, scan_content_text, scan_file_size):
    try:
        findings = scan_content(scan_target, scan_content_text)
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for finding in findings:
            sev = finding.get("severity", "Info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        if severity_counts["Critical"] > 0:
            overall_status = "Dangerous"
        elif severity_counts["High"] > 0:
            overall_status = "Suspicious"
        elif severity_counts["Medium"] > 0:
            overall_status = "Concerning"
        elif findings:
            overall_status = "Safe (Info Only)"
        else:
            overall_status = "Safe"

        queue.put({
            "engine": "SphinxEye-Core v2",
            "status": "success",
            "file": scan_target,
            "file_size": scan_file_size,
            "overall_status": overall_status,
            "total_findings": len(findings),
            "severity_breakdown": severity_counts,
            "findings": findings
        })
    except Exception as worker_error:
        queue.put({"error": f"Unexpected error: {str(worker_error)}", "status": "error"})


def main():
    """Main entry point: validate input, scan file, and output structured JSON."""
    try:
        if len(sys.argv) < 2:
            print(json.dumps({"error": "Usage: python script.py <file_path>", "status": "error"}))
            sys.exit(1)

        target = sys.argv[1]

        if not os.path.exists(target):
            print(json.dumps({"error": f"File not found: {target}", "status": "error"}))
            sys.exit(1)

        if not target.lower().endswith(('.js', '.html', '.htm')):
            print(json.dumps({"error": "Only .js, .html, and .htm files are supported", "status": "error"}))
            sys.exit(1)

        file_size = os.path.getsize(target)
        if file_size > MAX_FILE_SIZE:
            print(json.dumps({
                "error": f"File exceeds maximum size ({file_size} > {MAX_FILE_SIZE} bytes)",
                "status": "error"
            }))
            sys.exit(1)

        try:
            with open(target, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
        except Exception as e:
            print(json.dumps({"error": f"Failed to read file: {str(e)}", "status": "error"}))
            sys.exit(1)

        queue = mp.Queue()
        process = mp.Process(target=run_scan_worker, args=(queue, target, content, file_size))
        process.start()
        process.join(SCAN_TIMEOUT)

        if process.is_alive():
            process.terminate()
            process.join()
            print(json.dumps({"error": "Scan timeout exceeded", "status": "timeout"}))
            sys.exit(1)

        if queue.empty():
            print(json.dumps({"error": "Scan failed without output", "status": "error"}))
            sys.exit(1)

        report = queue.get()
        print(json.dumps(report, indent=2))

    except Exception as e:
        print(json.dumps({"error": f"Unexpected error: {str(e)}", "status": "error"}))
        sys.exit(1)


if __name__ == "__main__":
    main()
