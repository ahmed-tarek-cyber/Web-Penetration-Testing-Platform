import sys, json, argparse, os
from contextlib import redirect_stdout


current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.append(current_dir)

from directory_traversal_scanner import DirectoryTraversalScanner

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', required=True)
    parser.add_argument('--out', required=False)
    args = parser.parse_args()

    
    scanner = DirectoryTraversalScanner(args.url)
    
    
    with open(os.devnull, 'w') as fnull:
        with redirect_stdout(fnull):
            try: scanner.scan_for_traversal()
            except: pass

    mapped_results = []
    for v in scanner.vulnerabilities:
        mapped_results.append({
            "Name": "Directory Traversal",
            "Type": "LFI / Path Traversal",
            "Severity": "High",
            "Description": f"File access successful: {v.get('file')} via parameter '{v.get('parameter')}'",
            "Location": v.get('url', args.url),
            "Payload": v.get('payload', ''),
            "Evidence": v.get('evidence', '')[:200]  
        })

    if args.out:
        with open(args.out, 'w') as f:
            json.dump(mapped_results, f)
    else:
        print(json.dumps(mapped_results))

if __name__ == "__main__":
    main()