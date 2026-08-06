import sys, json, argparse, os


current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.append(current_dir)


from contextlib import redirect_stdout
from xss_scanner2 import UniversalXSSScanner

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', required=True)
    parser.add_argument('--out', required=False)
    args = parser.parse_args()

    scanner = UniversalXSSScanner(args.url, timeout=10)
    
    with open(os.devnull, 'w') as fnull:
        with redirect_stdout(fnull):
            try: scanner.scan()
            except: pass

    mapped_results = []
    for v in scanner.vulnerabilities:
        mapped_results.append({
            "Name": v.get('type', 'XSS'),
            "Type": v.get('type', 'XSS'),
            "Severity": v.get('severity', 'Medium'),
            "Description": v.get('description', 'XSS Vulnerability Detected'),
            "Location": v.get('location', args.url),
            "Payload": v.get('payload', ''),
            "Payload2": v.get('payload2', ''),
            "Source": v.get('source', 'Python: run_xss.py')
        })

    if args.out:
        with open(args.out, 'w') as f:
            json.dump(mapped_results, f)
    else:
        print(json.dumps(mapped_results))

if __name__ == "__main__": main()