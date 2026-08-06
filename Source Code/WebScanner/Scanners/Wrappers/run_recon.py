import argparse
import json
import os
import sys
from contextlib import redirect_stdout

current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.append(current_dir)

from recon_scanner import ReconScanner


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--out", required=False)
    args = parser.parse_args()

    scanner = ReconScanner(args.url, timeout=8)

    with open(os.devnull, "w") as fnull:
        with redirect_stdout(fnull):
            try:
                scanner.scan()
            except Exception:
                pass

    mapped_results = []
    for v in scanner.vulnerabilities:
        mapped_results.append(
            {
                "Name": v.get("type", "Recon"),
                "Type": v.get("type", "Recon"),
                "Severity": v.get("severity", "Info"),
                "Description": v.get("description", "Reconnaissance information"),
                "Location": v.get("location", args.url),
                "Payload": v.get("payload", ""),
                "Payload2": v.get("payload2", ""),
                "Source": v.get("source", "Python: run_recon.py"),
            }
        )

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(mapped_results, f)
    else:
        print(json.dumps(mapped_results))


if __name__ == "__main__":
    main()
