"""
Verdict correctness on a labelled corpus.

Benign mail must never be flagged or receive containment proposals; malicious mail must be
flagged with containment proposed. Every risk factor must cite evidence recorded for that
incident, and no CVE may be attached unless the evidence supports it.
Runs offline (see conftest.py): reputation feeds and URL fetches are unavailable, so these
expectations rest on the deterministic parser/attachment evidence alone.
"""

import base64
import io
import os
import zipfile

import pytest

from apps.agents.investigation_service import InvestigationService

HERE = os.path.dirname(__file__)
CORPUS = os.path.join(HERE, "fixtures", "corpus")
REPO = os.path.abspath(os.path.join(HERE, ".."))


def _attachment_eml(filename: str, payload: bytes, content_type: str) -> bytes:
    return (
        "From: accounts@billing-notices.net\nTo: bob@acme-widgets.com\nSubject: Invoice\n"
        "Message-ID: <att@billing-notices.net>\nMIME-Version: 1.0\n"
        "Authentication-Results: mx.acme-widgets.com; spf=pass; dmarc=pass\n"
        'Content-Type: multipart/mixed; boundary="B"\n\n--B\nContent-Type: text/plain\n\nSee attached.\n'
        f'--B\nContent-Type: {content_type}; name="{filename}"\n'
        f'Content-Disposition: attachment; filename="{filename}"\nContent-Transfer-Encoding: base64\n\n'
        + base64.b64encode(payload).decode() + "\n--B--\n"
    ).encode()


def _zip_with_exe() -> bytes:
    pe = b"MZ" + b"\x90" * 58 + b"\x80\x00\x00\x00" + b"\x00" * 64 + b"PE\x00\x00" + b"\x4c\x01" + b"\x00" * 300
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("invoice.pdf.exe", pe)
    return buf.getvalue()


def _read(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


# (name, raw bytes, label) — label is BENIGN, SUSPICIOUS (flag, no auto-containment needed) or MALICIOUS
CASES = [
    ("lunch_invite", _read(os.path.join(CORPUS, "01_benign_auth_pass.eml")), "BENIGN"),
    ("no_auth_header", _read(os.path.join(CORPUS, "02_benign_no_auth_header.eml")), "BENIGN"),
    ("newsletter_mentions_cve", _read(os.path.join(CORPUS, "03_benign_newsletter_mentions_cve.eml")), "BENIGN"),
    ("github_digest", _read(os.path.join(CORPUS, "05_benign_with_url_auth_pass.eml")), "BENIGN"),
    ("garbage_bytes", _read(os.path.join(CORPUS, "08_malformed.eml")), "BENIGN"),
    ("internal_html_agenda", _read(os.path.join(CORPUS, "10_benign_html_newsletter.eml")), "BENIGN"),
    ("repo_benign_control", _read(os.path.join(REPO, "tests", "fixtures", "benign-control-73922.eml")), "BENIGN"),
    ("benign_text_attachment", _attachment_eml("notes.txt", b"quarterly notes", "text/plain"), "BENIGN"),
    ("rtlo_subject", _read(os.path.join(CORPUS, "06_rtlo_subject.eml")), "SUSPICIOUS"),
    ("spf_fail_only", _read(os.path.join(CORPUS, "07_prompt_injection.eml")), "SUSPICIOUS"),
    ("deceptive_link", _read(os.path.join(CORPUS, "11_deceptive_link_auth_pass.eml")), "SUSPICIOUS"),
    ("phish_spf_fail_deceptive", _read(os.path.join(CORPUS, "04_phish_spf_fail_url.eml")), "MALICIOUS"),
    ("search_ms_unc_exploit", _read(os.path.join(REPO, "packages", "email_parser", "samples",
                                                   "synthetic_cve_2023_35636_rendering_exploit.eml")), "MALICIOUS"),
    ("monikerlink", _read(os.path.join(CORPUS, "09_monikerlink_cve_2024_21413.eml")), "MALICIOUS"),
    ("zip_with_exe", _attachment_eml("invoice.zip", _zip_with_exe(), "application/zip"), "MALICIOUS"),
]


@pytest.fixture(scope="module")
def results():
    svc = InvestigationService()
    return {name: (svc.run_investigation("tenant-eval", raw, source_filename=f"{name}.eml"), label)
            for name, raw, label in CASES}


@pytest.mark.parametrize("name", [c[0] for c in CASES])
def test_verdict_matches_label(results, name):
    inc, label = results[name]
    proposed = {a["action"] for a in inc.recommended_actions}
    if label == "BENIGN":
        assert inc.severity == "LOW", (inc.severity, inc.overall_risk_score, inc.evidence_summary)
        assert inc.overall_risk_score < 20
        assert not inc.pending_approvals
        assert inc.cve is None
    elif label == "SUSPICIOUS":
        assert inc.severity in ("MEDIUM", "HIGH", "CRITICAL"), (inc.severity, inc.evidence_summary)
    else:
        assert inc.severity in ("HIGH", "CRITICAL"), (inc.severity, inc.evidence_summary)
        assert "quarantine_email" in proposed


@pytest.mark.parametrize("name", [c[0] for c in CASES])
def test_every_risk_factor_cites_recorded_evidence(results, name):
    inc, _ = results[name]
    evidence_ids = {e.evidence_id for e in inc.evidence_items}
    for adj in inc.risk_provenance.adjustments:
        assert adj.evidence_id in evidence_ids
    assert inc.risk_provenance.final_score == pytest.approx(min(100.0, sum(a.delta for a in inc.risk_provenance.adjustments)))
    assert inc.trust_score.unsupported_claim_count == 0


def test_missing_authentication_is_reported_as_unknown(results):
    inc, _ = results["no_auth_header"]
    auth = next(e for e in inc.evidence_items if e.type == "AUTHENTICATION")
    assert auth.metadata["result"] == "UNKNOWN"
    assert auth.status.value == "UNKNOWN"
    assert "dns_spf_dmarc_recon" in [t.tool_name for t in inc.tool_executions]


def test_subject_and_body_reach_the_tools(results):
    inc, _ = results["lunch_invite"]
    assert inc.subject == "Lunch on Thursday?"
    unicode_run = next(t for t in inc.tool_executions if t.tool_name == "UnicodeAnalyzer")
    assert "Lunch on Thursday?" in unicode_run.input_parameters["text"]
    assert "free for lunch" in unicode_run.input_parameters["text"]


def test_monikerlink_cve_is_verified_against_kev(results):
    inc, _ = results["monikerlink"]
    assert inc.cve == "CVE-2024-21413"
    kev = next(e for e in inc.evidence_items if e.type == "CISA_KEV_MATCH")
    assert kev.metadata["is_in_kev"] is True
    assert "CisaKevCorrelator" in [t.tool_name for t in inc.tool_executions]


def test_corpus_metrics(results):
    tp = fp = fn = tn = 0
    for name, (inc, label) in results.items():
        flagged = inc.severity != "LOW"
        if label == "BENIGN":
            fp += flagged
            tn += not flagged
        else:
            tp += flagged
            fn += not flagged
    print(f"\n[corpus] TP={tp} FP={fp} FN={fn} TN={tn} "
          f"precision={tp / max(1, tp + fp):.2f} recall={tp / max(1, tp + fn):.2f}")
    assert fp == 0 and fn == 0
