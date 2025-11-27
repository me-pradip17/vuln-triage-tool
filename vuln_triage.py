
*(Rich is only used to print colored output. It’s lightweight.)*

---

# **vuln_triage.py**

```python
import json
import sys
from rich import print as rprint
from rich.table import Table

SEVERITY_ORDER = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0
}

def load_scan_file(path):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception as e:
        rprint(f"[red]Failed to load file:[/red] {e}")
        sys.exit(1)

def prioritize(vulns):
    return sorted(
        vulns,
        key=lambda v: SEVERITY_ORDER.get(v.get("severity", "").lower(), -1),
        reverse=True
    )

def print_summary(vulns):
    table = Table(title="Vulnerability Summary", show_lines=True)
    table.add_column("Severity", style="bold")
    table.add_column("CVE ID")
    table.add_column("Asset")
    table.add_column("Description")

    for v in vulns:
        table.add_row(
            v.get("severity", "N/A"),
            v.get("id", "N/A"),
            v.get("asset", "N/A"),
            v.get("description", "N/A")[:80] + "..."
            if len(v.get("description", "")) > 80 else v.get("description", "N/A")
        )

    rprint(table)

def main():
    if len(sys.argv) < 2:
        rprint("[yellow]Usage: python vuln_triage.py <scan_result.json>[/yellow]")
        sys.exit(1)

    path = sys.argv[1]
    data = load_scan_file(path)

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        rprint("[green]No vulnerabilities found.[/green]")
        return

    prioritized = prioritize(vulns)
    print_summary(prioritized)

if __name__ == "__main__":
    main()
