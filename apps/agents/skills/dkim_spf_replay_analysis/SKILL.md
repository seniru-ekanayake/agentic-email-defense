---
name: dkim_spf_replay_analysis
description: Forensic investigation protocol for DKIM replay attacks, ARC authentication breakdown, and header spoofing.
---

# DKIM Replay & Authentication Breakdown Playbook

## Context & Objectives
Attackers record legitimately signed marketing or transactional emails from reputable organizations, modify the body/recipient headers, and replay them through untrusted relays, exploiting lenient DMARC alignment rules or broken ARC (Authenticated Received Chain) validation.

## Procedural Triage Steps

1. **Authentication Alignment Audit**:
   - Compare RFC5322 `From` header domain with RFC5321 `Return-Path` and DKIM `d=` domain.
   - Flag alignment mismatches where `From` domain does not match `d=`.

2. **Public DNS & DMARC Enforcement Check**:
   - Run `dns_spf_dmarc_recon` on the sender domain.
   - Check if DMARC policy is `p=none` (vulnerable to spoofing) or `p=reject`.
   - Verify DKIM selector key validity using `dkim_selector_check`.

3. **ARC Chain Validation**:
   - Inspect `ARC-Authentication-Results`, `ARC-Message-Signature`, and `ARC-Seal` sequence numbers.
   - Check if any intermediate hop modified the message body or subject without updating ARC-Seal.

4. **Prescribed Response Recommendations**:
   - If spoofing vulnerability is confirmed: Propose `block_sender` at mail gateway.
   - Propose `quarantine_email` to prevent end-user inbox delivery.
