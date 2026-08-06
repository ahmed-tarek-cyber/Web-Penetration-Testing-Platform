import sys, json, argparse, os
from collections import defaultdict


current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.append(current_dir)

from contextlib import redirect_stdout
from idor_scanner import IDORScanner

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', required=True)
    parser.add_argument('--out', required=False)
    args = parser.parse_args()
    
    scanner = IDORScanner(args.url)
    
    
    with open(os.devnull, 'w') as fnull:
        with redirect_stdout(fnull):
            try: scanner.scan_for_idor()
            except: pass

    
    
    grouped_vulns = defaultdict(list)
    
    for v in scanner.vulnerable_endpoints:
        
        key = (v.get('type', 'IDOR'), v.get('url', args.url), v.get('parameter', 'unknown'))
        
        grouped_vulns[key].append(str(v.get('test_value')))

    
    mapped_results = []
    
    for (v_type, url, param), values in grouped_vulns.items():
        count = len(values)
        
        examples = ", ".join(values[:5])
        if count > 5:
            examples += f", ... and {count - 5} more"

        
        description = f"Mass IDOR detected on parameter '{param}'. Detected {count} vulnerable IDs. Examples: [{examples}]"

        mapped_results.append({
            "Name": v_type, 
            "Severity": "High",
            "Description": description,
            "Location": url,
            "Payload": f"Parameter: {param}", 
            "Payload2": f"Total Hits: {count}", 
            "Source": "Python IDOR (Aggregated)"
        })

    
    if args.out:
        with open(args.out, 'w') as f:
            json.dump(mapped_results, f)
    else:
        print(json.dumps(mapped_results))

if __name__ == "__main__": main()