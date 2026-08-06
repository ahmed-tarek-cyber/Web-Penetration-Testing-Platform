import sys, json, argparse, os


current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.append(current_dir)


from contextlib import redirect_stdout
from sqlmap_script import run_sqlmap_scan

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', required=True)
    parser.add_argument('--out', required=False)
    args = parser.parse_args()

    mapped_results = []
    
    try:
        data = run_sqlmap_scan(args.url)
        if data:
            mapped_results.append({
                "Name": "SQL Injection (Advanced)",
                "Type": "SQL Injection (Advanced)",
                "Severity": "Critical",
                "Description": "SQLMap identified injection points.",
                "Location": args.url,
                "Payload": "Refer to SQLMap logs"
            })
    except Exception as e:
        pass

    if args.out:
        with open(args.out, 'w') as f:
            json.dump(mapped_results, f)
    else:
        print(json.dumps(mapped_results))

if __name__ == "__main__": main()