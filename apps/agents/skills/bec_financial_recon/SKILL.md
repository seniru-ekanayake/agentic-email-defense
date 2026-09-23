---
name: bec_financial_recon
description: Forensic investigation protocol for Business Email Compromise (BEC), VIP executive impersonation, supplier invoice redirection, and payroll fraud.
---

# BEC & Financial Fraud Investigation Playbook

## Context & Objectives
Business Email Compromise (BEC) attacks leverage social engineering, display-name spoofing, lookalike domains (typosquatting), and compromised legitimate vendor accounts to request urgent wire transfers, updated banking coordinates, or payroll account changes without attachments or malware.

## Procedural Triage Steps

1. **Sender Baseline & Historical Anomaly Query**:
   - Run `query_sender_history` with the sender email and recipient address.
   - Flag anomaly if `is_first_time_sender` is `True` or communication count is zero.

2. **Domain Permutation & Lookalike Analysis**:
   - Compare sender domain against enterprise VIP names and known vendors.
   - Check domain creation date and registration age via `dns_spf_dmarc_recon`.

3. **Financial Indicator & Urgency Extraction**:
   - Identify extracted banking keywords (IBAN, SWIFT, Routing Number, Payment Voucher).
   - Flag high urgency cues ("immediate transfer required", "confidential request from CEO").

4. **Prescribed Response Recommendations**:
   - Propose `quarantine_email` and `block_sender`.
   - Propose `create_soc_ticket` with `High` priority for secondary phone/out-of-band verification by finance.
