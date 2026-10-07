"""
Compare FishingMails against another product on the same labelled corpus.

1. Run scripts/benchmark.py to produce verdicts.csv (it contains the ground-truth labels).
2. Export the other product's verdicts for the same messages to a CSV with a filename column and a
   verdict column (for example, a Defender for Office 365 / Proofpoint / Mimecast message-trace export,
   or the result of submitting each .eml to that product's API).
3. Run:
   python scripts/compare_verdicts.py benchmark-results/verdicts.csv competitor.csv \
       --name "Vendor X" --file-column file --verdict-column verdict --positive phish,malware,spam,suspicious

Rows are matched by file basename. A competitor verdict counts as "flagged" when it is in --positive
(case-insensitive) or is a truthy number.
"""

import argparse
import csv
import os

POSITIVE_LABELS = {"suspicious", "malicious"}


def metrics(pairs):
    tp = sum(f and l in POSITIVE_LABELS for f, l in pairs)
    fp = sum(f and l == "benign" for f, l in pairs)
    fn = sum((not f) and l in POSITIVE_LABELS for f, l in pairs)
    tn = sum((not f) and l == "benign" for f, l in pairs)
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    return {"TP": tp, "FP": fp, "FN": fn, "TN": tn, "precision": p, "recall": r,
            "F1": 2 * p * r / (p + r) if p + r else 0.0, "FPR": fp / (fp + tn) if fp + tn else 0.0}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("fishingmails_csv")
    ap.add_argument("competitor_csv")
    ap.add_argument("--name", default="Competitor")
    ap.add_argument("--file-column", default="file")
    ap.add_argument("--verdict-column", default="verdict")
    ap.add_argument("--positive", default="phish,phishing,malware,malicious,spam,suspicious,quarantine,block,1,true")
    args = ap.parse_args()
    positive = {v.strip().lower() for v in args.positive.split(",")}

    with open(args.fishingmails_csv, newline="", encoding="utf-8") as f:
        ours = {os.path.basename(r["file"]): r for r in csv.DictReader(f)}
    with open(args.competitor_csv, newline="", encoding="utf-8") as f:
        theirs = {os.path.basename(r[args.file_column]): str(r[args.verdict_column]).strip().lower() for r in csv.DictReader(f)}

    common = sorted(set(ours) & set(theirs))
    if not common:
        raise SystemExit("No overlapping filenames between the two CSVs.")
    labels = {k: ours[k]["label"] for k in common}
    fm = [(ours[k]["flagged"] == "1", labels[k]) for k in common]
    cx = [(theirs[k] in positive, labels[k]) for k in common]

    m_fm, m_cx = metrics(fm), metrics(cx)
    print(f"Messages compared: {len(common)} (missing from competitor: {len(set(ours) - set(theirs))})\n")
    print(f"{'metric':<10}{'FishingMails':>14}{args.name:>16}")
    for key in ("precision", "recall", "F1", "FPR", "TP", "FP", "FN", "TN"):
        a, b = m_fm[key], m_cx[key]
        fmt = (lambda v: f"{v:.3f}") if isinstance(a, float) else str
        print(f"{key:<10}{fmt(a):>14}{fmt(b):>16}")

    both = sum(a and b for (a, _), (b, _) in zip(fm, cx))
    only_fm = [k for k, (a, _), (b, _) in zip(common, fm, cx) if a and not b]
    only_cx = [k for k, (a, _), (b, _) in zip(common, fm, cx) if b and not a]
    print(f"\nAgreement: both flagged {both}, only FishingMails {len(only_fm)}, only {args.name} {len(only_cx)}")
    for k in only_fm:
        print(f"  only FishingMails: {k} (label {labels[k]})")
    for k in only_cx:
        print(f"  only {args.name}: {k} (label {labels[k]})")


if __name__ == "__main__":
    main()
