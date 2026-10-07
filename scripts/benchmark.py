"""
Benchmark FishingMails on a labelled email corpus.

Corpus formats:
  --corpus DIR       DIR/benign/*.eml, DIR/suspicious/*.eml, DIR/malicious/*.eml (folder name = label)
  --manifest CSV     rows of "path,label" (paths relative to the repository root)

A message counts as *flagged* when its severity is MEDIUM or higher, and as *contained* when quarantine
is proposed. "suspicious" and "malicious" are both positives for detection metrics.

Examples:
  python scripts/benchmark.py --manifest scripts/benchmark_manifest.csv --planner RULE --offline
  python scripts/benchmark.py --corpus ~/mail-corpus --planner HYBRID --out results/
"""

import argparse
import csv
import json
import os
import socket
import statistics
import sys
import tempfile
import time

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
POSITIVE = {"suspicious", "malicious"}


def load_cases(args):
    cases = []
    if args.manifest:
        with open(args.manifest, newline="", encoding="utf-8") as f:
            for row in csv.reader(f):
                if row and not row[0].startswith("#") and row[0] != "path":
                    cases.append((os.path.join(REPO, row[0]), row[1].strip().lower()))
    else:
        for label in ("benign", "suspicious", "malicious"):
            folder = os.path.join(args.corpus, label)
            if os.path.isdir(folder):
                cases += [(os.path.join(folder, n), label) for n in sorted(os.listdir(folder)) if n.lower().endswith(".eml")]
    if not cases:
        sys.exit("No labelled .eml files found.")
    return cases


def disable_network():
    real_connect, real_gai = socket.socket.connect, socket.getaddrinfo

    def connect(sock, addr):
        host = addr[0] if isinstance(addr, tuple) else addr
        if host not in ("127.0.0.1", "::1", "localhost"):
            raise OSError("network disabled (--offline)")
        return real_connect(sock, addr)

    def gai(host, *a, **k):
        if host not in (None, "127.0.0.1", "::1", "localhost"):
            raise socket.gaierror(socket.EAI_NONAME, "network disabled (--offline)")
        return real_gai(host, *a, **k)

    socket.socket.connect, socket.getaddrinfo = connect, gai


def pct(values, p):
    values = sorted(values)
    return values[min(len(values) - 1, int(round(p / 100 * (len(values) - 1))))]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--corpus")
    src.add_argument("--manifest")
    ap.add_argument("--planner", default="RULE", choices=["RULE", "LLM", "HYBRID"])
    ap.add_argument("--policy", default="RULE_FIRST")
    ap.add_argument("--offline", action="store_true", help="no reputation lookups or URL fetches (deterministic)")
    ap.add_argument("--out", default=os.path.join(REPO, "benchmark-results"))
    args = ap.parse_args()

    os.environ.setdefault("FISHINGMAILS_ENV", "development")
    os.environ["FISHINGMAILS_DB_PATH"] = os.path.join(tempfile.mkdtemp(prefix="fm-bench-"), "bench.db")
    if args.offline:
        disable_network()
    sys.path.insert(0, REPO)
    os.chdir(REPO)
    from apps.agents.core.agent_builder import PlannerSettings, save_planner_settings
    from apps.agents.investigation_service import InvestigationService

    tenant = "benchmark"
    save_planner_settings(tenant, PlannerSettings(planner_mode=args.planner, hybrid_arbitration_policy=args.policy))
    svc = InvestigationService()
    rows = []
    for path, label in load_cases(args):
        with open(path, "rb") as f:
            raw = f.read()
        t0 = time.perf_counter()
        inc = svc.run_investigation(tenant, raw, source_filename=os.path.basename(path))
        ms = (time.perf_counter() - t0) * 1000
        rows.append({
            "file": os.path.relpath(path, REPO), "label": label, "severity": inc.severity,
            "risk": inc.overall_risk_score, "category": inc.threat_category,
            "flagged": int(inc.severity != "LOW"),
            "contained": int(any(p["tool_name"] == "quarantine_email" for p in inc.pending_approvals)),
            "latency_ms": round(ms, 1), "tools": " ".join(t.tool_name for t in inc.tool_executions),
            "llm_calls": len(inc.forensic_audit.llm_calls),
        })
        print(f"{rows[-1]['label']:>10}  {inc.severity:<8} {inc.overall_risk_score:5.1f}  {ms:8.0f} ms  {rows[-1]['file']}")

    tp = sum(r["flagged"] and r["label"] in POSITIVE for r in rows)
    fp = sum(r["flagged"] and r["label"] == "benign" for r in rows)
    fn = sum((not r["flagged"]) and r["label"] in POSITIVE for r in rows)
    tn = sum((not r["flagged"]) and r["label"] == "benign" for r in rows)
    mal = [r for r in rows if r["label"] == "malicious"]
    lat = [r["latency_ms"] for r in rows]
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    summary = {
        "planner": args.planner, "offline": args.offline, "messages": len(rows),
        "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "precision": round(precision, 3), "recall": round(recall, 3),
        "f1": round(2 * precision * recall / (precision + recall), 3) if precision + recall else 0.0,
        "false_positive_rate": round(fp / (fp + tn), 3) if fp + tn else 0.0,
        "malicious_contained_rate": round(sum(r["contained"] for r in mal) / len(mal), 3) if mal else None,
        "latency_ms": {"p50": pct(lat, 50), "p95": pct(lat, 95), "mean": round(statistics.mean(lat), 1)},
        "llm_calls_total": sum(r["llm_calls"] for r in rows),
    }
    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, "verdicts.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    with open(os.path.join(args.out, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
