"""
Performance Benchmark Suite for FishingMails Investigation Pipeline.
Measures Time-to-Verdict (P50, P95, Mean), Tool Execution Overhead, and Peak Memory Usage.
"""

import os
import sys
import time
import json
import tracemalloc
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from apps.agents.investigation_service import InvestigationService


def run_benchmarks(iterations: int = 20):
    tracemalloc.start()
    service = InvestigationService()
    latencies = []
    tool_durations = []

    # Sample payloads: clean, phishing url, unicode, and multi-vector
    test_emls = []
    
    # 1. Clean email
    m1 = MIMEMultipart()
    m1["Subject"] = "Team Sync Tomorrow"
    m1["From"] = "alice@corp.internal"
    m1["To"] = "bob@corp.internal"
    m1.attach(MIMEText("Hi Bob, see you at 10 AM tomorrow.", "plain"))
    test_emls.append(m1.as_bytes())

    # 2. Phishing URL email
    m2 = MIMEMultipart()
    m2["Subject"] = "Urgent: Reset your password"
    m2["From"] = "alerts@service-update.net"
    m2["To"] = "bob@corp.internal"
    m2.attach(MIMEText("Please verify credentials at http://login-portal.auth-check.org/login", "plain"))
    test_emls.append(m2.as_bytes())

    # 3. Unicode Tag / RTLO email
    m3 = MIMEMultipart()
    m3["Subject"] = "Document Revision \u202eDOC.PDF"
    m3["From"] = "hr@corporate.local"
    m3["To"] = "bob@corp.internal"
    m3.attach(MIMEText("Please find document attached.\u200b", "plain"))
    test_emls.append(m3.as_bytes())

    print(f"\n[BENCHMARK] Executing {iterations} investigation runs...")

    for i in range(iterations):
        raw_eml = test_emls[i % len(test_emls)]
        t0 = time.perf_counter()
        incident = service.run_investigation(
            tenant_id="tenant-benchmarking",
            raw_eml=raw_eml,
            autonomy_level=1,
            source_filename=f"bench_{i}.eml"
        )
        t_elapsed = (time.perf_counter() - t0) * 1000.0  # ms
        latencies.append(t_elapsed)

        for tool in incident.tool_executions:
            tool_durations.append(tool.duration_ms)

    current_mem, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    latencies.sort()
    p50 = latencies[int(len(latencies) * 0.50)]
    p95 = latencies[int(len(latencies) * 0.95)]
    mean_lat = sum(latencies) / len(latencies)
    mean_tool_dur = sum(tool_durations) / len(tool_durations) if tool_durations else 0.0

    benchmark_results = {
        "iterations": iterations,
        "time_to_verdict_ms": {
            "p50": round(p50, 2),
            "p95": round(p95, 2),
            "mean": round(mean_lat, 2)
        },
        "tool_execution_overhead_ms": {
            "mean_per_tool": round(mean_tool_dur, 2),
            "total_tools_measured": len(tool_durations)
        },
        "memory_usage_mb": {
            "peak_mb": round(peak_mem / (1024 * 1024), 2),
            "current_mb": round(current_mem / (1024 * 1024), 2)
        }
    }

    print("\n--- BENCHMARK RESULTS ---")
    print(json.dumps(benchmark_results, indent=2))

    with open("benchmark_results.json", "w") as f:
        json.dump(benchmark_results, f, indent=2)

    return benchmark_results


if __name__ == "__main__":
    run_benchmarks(20)
