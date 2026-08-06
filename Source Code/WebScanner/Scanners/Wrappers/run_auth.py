import sys, json, argparse, os


current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.append(current_dir)


from contextlib import redirect_stdout
from broken_auth_scanner import AltAuthScanner

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', required=True)
    parser.add_argument('--out', required=False)
    args = parser.parse_args()
    
    scanner = AltAuthScanner(args.url)
    
    with open(os.devnull, 'w') as fnull:
        with redirect_stdout(fnull):
            try: scanner.scan()
            except: pass

    mapped_results = []
    for v in scanner.vulnerabilities:
        mapped_results.append({
            "Name": v.get('type', 'Broken Authentication'),
            "Type": v.get('type', 'Broken Authentication'),
            "Severity": v.get('severity', 'High'),
            "Description": v.get('description', ''),
            "Location": args.url,
            "Payload": v.get('recommendation', '')
        })

    if args.out:
        with open(args.out, 'w') as f:
            json.dump(mapped_results, f)
    else:
        print(json.dumps(mapped_results))

if __name__ == "__main__": main()