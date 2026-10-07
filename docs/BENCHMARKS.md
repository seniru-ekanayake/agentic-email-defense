# Benchmarks

All numbers below were measured on 2026-10-08 on a Windows 11 laptop (Python 3.12), using the scripts in
this repository. Re-run them yourself: they are cheap, and your numbers on your own mail are the ones that matter.

## Corpus

`scripts/benchmark_manifest.csv` lists 15 labelled messages from this repository:

| Label | Count | Examples |
| --- | --- | --- |
| benign | 7 | lunch invite, GitHub digest, HR notice, newsletter that *mentions* a CVE, garbage bytes |
| suspicious | 3 | RTLO in subject, deceptive link with passing auth, SPF failure with a prompt-injection body |
| malicious | 5 | PayPal look-alike phish, Outlook MonikerLink, search-ms/UNC forced-authentication emails |

> ⚠️ This is a **regression corpus**, not an accuracy study. 15 hand-built messages say nothing about
> real-world precision/recall. Use the method below on a representative corpus before relying on verdicts.

## Detection

A message is *flagged* when its severity is MEDIUM or higher; suspicious and malicious messages are positives.

| Mode | Precision | Recall | F1 | False-positive rate | Malicious with quarantine proposed |
| --- | --- | --- | --- | --- | --- |
| Rule planner, offline | 1.00 | 1.00 | 1.00 | 0.00 | 5 / 5 |
| Rule planner, online (Quad9 + link fetch) | 1.00 | 1.00 | 1.00 | 0.00 | 5 / 5 |

## Latency per investigation

| Mode | p50 | p95 | Notes |
| --- | --- | --- | --- |
| Rule planner, offline | 15 ms | 44 ms | parser + local tools only |
| Rule planner, online | 26 ms | 0.56 s | emails with links add a Quad9 lookup and an HTTP fetch |
| LLM planner (`nvidia/nemotron-3-super-120b-a12b:free`) | — | — | 2–50 s **per planning step**; 3–5 steps per investigation (observed 13 s for a benign email, 34–70 s for phishing) |

The LLM figures come from live runs during development (about 35 requests in total) rather than a full
corpus run, to stay within free-tier quotas. Free models are also subject to upstream congestion
(`google/gemma-4-31b-it:free` returned HTTP 429 during testing), in which case the rule planner takes over.

## Reproduce

```bash
pip install -r requirements.txt
python scripts/benchmark.py --manifest scripts/benchmark_manifest.csv --planner RULE --offline
python scripts/benchmark.py --manifest scripts/benchmark_manifest.csv --planner RULE
OPENROUTER_API_KEY=... OPENROUTER_MODEL=nvidia/nemotron-3-super-120b-a12b:free \
  python scripts/benchmark.py --manifest scripts/benchmark_manifest.csv --planner LLM   # ~60 free requests
```

Each run writes `benchmark-results/verdicts.csv` (one row per message) and `benchmark-results/summary.json`.

## Benchmark against another product

1. **Build a labelled corpus.** Put `.eml` files in `corpus/benign/`, `corpus/suspicious/` and `corpus/malicious/`.
   Good sources: your own reported-phish mailbox and a sample of normal mail, or public corpora such as the
   SpamAssassin public corpus (ham) and the Nazario phishing corpus. Check each corpus's licence first.
2. **Run FishingMails:** `python scripts/benchmark.py --corpus corpus/ --planner RULE --out results/`
3. **Get the other product's verdicts for the same files.** For example, a message-trace export from
   Microsoft Defender for Office 365, Proofpoint or Mimecast after sending the corpus to a test mailbox,
   or results from that product's submission API. Save them as CSV with a filename column and a verdict column.
4. **Compare:**

   ```bash
   python scripts/compare_verdicts.py results/verdicts.csv vendor.csv \
     --name "Vendor X" --file-column file --verdict-column verdict --positive phish,malware,spam
   ```

   The script prints precision, recall, F1 and false-positive rate side by side, and lists every message only
   one product flagged so you can review the disagreements by hand.

Tips for a fair comparison: use the same messages, preserve original headers (Authentication-Results
especially), keep links live if you want reputation and link fetches to count, and compare both detection
*and* the time to a containment decision.
