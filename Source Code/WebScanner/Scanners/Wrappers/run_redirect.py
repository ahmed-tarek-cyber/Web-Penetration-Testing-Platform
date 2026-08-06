import sys, json, argparse, os
from contextlib import redirect_stdout, redirect_stderr

current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.append(current_dir)

from open_redirect_scanner import OpenRedirectScanner

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', required=True)
    parser.add_argument('--out', required=False)
    args = parser.parse_args()

    
    scanner = OpenRedirectScanner(args.url, max_workers=5)
    
    with open(os.devnull, 'w') as fnull:
        
        with redirect_stdout(fnull), redirect_stderr(fnull):
            try: scanner.scan()
            except: pass

    mapped_results = []
    for v in scanner.vulnerabilities:
        
        mapped_results.append({
            "Name": "Open Redirect",
            "Type": "Open Redirect",
            "Severity": "Medium", 
            "Description": f"Open Redirect found on parameter '{v.parameter}' redirecting to {v.redirect_location}",
            "Location": v.url,
            "Payload": v.payload,
            "Evidence": f"Redirected to: {v.redirect_location}"
        })

    if args.out:
        with open(args.out, 'w') as f:
            json.dump(mapped_results, f)
    else:
        print(json.dumps(mapped_results))

if __name__ == "__main__":
    main()