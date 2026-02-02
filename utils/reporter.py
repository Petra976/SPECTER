import json

def print_report(results):
    print("\n=== SCAN REPORT ===\n")
    for r in results:
        print(f"[{r['severity'].upper()}] {r['module']}")
        print(f" → {r['description']}")
        if r["evidence"]:
            print(f" → Evidence: {r['evidence']}")
        print()

def save_json(results, filename="report.json"):
    with open(filename, "w") as f:
        json.dump(results, f, indent=4)
