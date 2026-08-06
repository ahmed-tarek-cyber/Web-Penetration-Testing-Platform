import sys, json, argparse, os


current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.append(current_dir)


from contextlib import redirect_stdout
from csrf_scanner import crawl, scan_page

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', required=True)
    parser.add_argument('--out', required=False)
    args = parser.parse_args()
    
    raw_results = []
    with open(os.devnull, 'w') as fnull:
        with redirect_stdout(fnull):
            try:
                pages = crawl(args.url, limit=3)
                if not pages: pages = [args.url]
                
                for p in pages:
                    res = scan_page(p)
                    raw_results.extend(res)
            except: pass

    mapped_results = []
    for r in raw_results:
        if r.get('bypass_possible'):
            mapped_results.append({
                "Name": "CSRF Vulnerability",
                "Type": "CSRF Vulnerability",
                "Severity": "Medium",
                "Description": r.get('details', 'Potential CSRF detected'),
                "Location": r.get('action', args.url),
                "Payload": f"Method: {r.get('method')}"
            })

    if args.out:
        with open(args.out, 'w') as f:
            json.dump(mapped_results, f)
    else:
        print(json.dumps(mapped_results))

if __name__ == "__main__": main()