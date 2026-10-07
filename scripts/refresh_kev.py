"""Refreshes the bundled CISA KEV subset from the official CISA feed.

Usage: python scripts/refresh_kev.py [CVE-ID ...]
With no arguments, the CVE IDs already present in the bundled file are refreshed.
"""
import json
import os
import sys
import urllib.request

FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DEST = os.path.join(os.path.dirname(__file__), "..", "apps", "agents", "core", "data", "known_exploited_vulnerabilities.json")


def main() -> int:
    with open(DEST, encoding="utf-8") as f:
        current = [v["cveID"] for v in json.load(f).get("vulnerabilities", [])]
    wanted = set(sys.argv[1:] or current)
    with urllib.request.urlopen(FEED, timeout=60) as resp:
        live = json.loads(resp.read().decode("utf-8"))
    vulns = [v for v in live["vulnerabilities"] if v["cveID"] in wanted]
    missing = wanted - {v["cveID"] for v in vulns}
    out = {"title": live["title"], "catalogVersion": live["catalogVersion"], "dateReleased": live["dateReleased"],
           "count": len(vulns), "note": "Subset of the CISA KEV catalog relevant to mail clients. Refresh with scripts/refresh_kev.py.",
           "vulnerabilities": vulns}
    with open(DEST, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1)
    print(f"Wrote {len(vulns)} entries (catalog {live['catalogVersion']}).")
    if missing:
        print(f"Not in CISA KEV (dropped): {sorted(missing)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
