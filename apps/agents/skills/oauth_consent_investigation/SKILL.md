---
name: oauth_consent_investigation
description: Forensic investigation protocol for illicit OAuth 2.0 app registrations, multi-tenant consent grants, and token theft lures.
---

# Illicit OAuth App & Consent Grant Investigation Playbook

## Context & Objectives
Attackers use deceptive consent phishing lures to trick enterprise users into granting malicious Microsoft Entra ID (Azure AD) or Google Workspace applications high-privilege delegated permissions (e.g. `Mail.ReadWrite`, `Files.ReadWrite.All`, `offline_access`) without triggering credential change alerts or MFA.

## Procedural Triage Steps

1. **OAuth Endpoint & Parameter Extraction**:
   - Extract `client_id`, `redirect_uri`, `scope`, and `response_type` from embedded OAuth URLs.
   - Verify if `redirect_uri` routes to an unverified external third-party domain.

2. **Scope Severity Audit**:
   - Classify requested scopes:
     - High Risk: `Mail.ReadWrite`, `Mail.Send`, `User.ReadWrite.All`, `Files.ReadWrite.All`
     - Critical Risk: `Directory.AccessAsUser.All`, `FullAccess`, `offline_access`

3. **Reputation & Infrastructure Verification**:
   - Run `threat_intel_lookup` on the redirect domain to verify domain reputation.
   - Run `query_sender_history` to verify if the sending app vendor has prior communication history with the tenant.

4. **Prescribed Response Recommendations**:
   - Propose `quarantine_email` to eliminate victim click exposure.
   - Propose `revoke_user_sessions` if the user has already opened the consent prompt.
   - Recommend tenant administrator revoke application consent grant for the malicious `client_id`.
