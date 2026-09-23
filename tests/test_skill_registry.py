import pytest
from apps.agents.skills.skill_registry import SkillRegistry
from packages.schemas.python.models import (
    EmailAttackRepresentation,
    SenderInfo,
    RecipientInfo,
    AuthenticationResults,
    UrlFeature,
    ExploitIndicator,
    BodyFeatures,
)


def test_skill_registry_discovery():
    registry = SkillRegistry()
    assert len(registry.skills) >= 4
    assert "moniker_exploit_triage" in registry.skills
    assert "oauth_consent_investigation" in registry.skills
    assert "dkim_spf_replay_analysis" in registry.skills
    assert "bec_financial_recon" in registry.skills


def test_moniker_skill_matching():
    registry = SkillRegistry()
    ear = EmailAttackRepresentation(
        message_id="msg-moniker-01",
        timestamp="2026-09-23T22:00:00Z",
        sender=SenderInfo(address="attacker@evil.com", domain="evil.com"),
        recipients=[RecipientInfo(address="target@victim.com")],
        authentication=AuthenticationResults(spf="pass", dkim="pass", dmarc="pass"),
        headers={"Subject": "Urgent Document Review"},
        urls=[
            UrlFeature(
                url="search-ms:query=payload.exe&crumb=location:\\\\198.51.100.22\\share",
                domain="198.51.100.22"
            )
        ],
        exploit_indicators=[
            ExploitIndicator(
                indicator_type="MONIKER_LINK",
                evidence="CVE-2024-21413 Moniker link detected",
                target_cve="CVE-2024-21413",
                confidence=0.95
            )
        ]
    )

    matched = registry.match_skills(ear)
    matched_names = [m.name for m in matched]
    assert "moniker_exploit_triage" in matched_names

    prompt_ctx = registry.build_skill_prompt_context(matched)
    assert "MONIKER_EXPLOIT_TRIAGE" in prompt_ctx
    assert "CVE-2024-21413" in prompt_ctx


def test_oauth_skill_matching():
    registry = SkillRegistry()
    ear = EmailAttackRepresentation(
        message_id="msg-oauth-01",
        timestamp="2026-09-23T22:00:00Z",
        sender=SenderInfo(address="noreply@login-security.net", domain="login-security.net"),
        recipients=[RecipientInfo(address="target@victim.com")],
        authentication=AuthenticationResults(spf="pass", dkim="pass", dmarc="pass"),
        headers={"Subject": "Action Required: Re-authorize Office 365"},
        urls=[
            UrlFeature(
                url="https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=bad-app&scope=Mail.ReadWrite",
                domain="login.microsoftonline.com"
            )
        ]
    )

    matched = registry.match_skills(ear)
    matched_names = [m.name for m in matched]
    assert "oauth_consent_investigation" in matched_names


def test_dkim_replay_skill_matching():
    registry = SkillRegistry()
    ear = EmailAttackRepresentation(
        message_id="msg-dkim-01",
        timestamp="2026-09-23T22:00:00Z",
        sender=SenderInfo(address="service@spoofed.com", domain="spoofed.com"),
        recipients=[RecipientInfo(address="victim@corp.internal")],
        authentication=AuthenticationResults(spf="fail", dkim="fail", dmarc="none", auth_results_raw="dkim=fail (bad signature)"),
        headers={"Subject": "Delivery notification"}
    )

    matched = registry.match_skills(ear)
    matched_names = [m.name for m in matched]
    assert "dkim_spf_replay_analysis" in matched_names


def test_bec_financial_skill_matching():
    registry = SkillRegistry()
    ear = EmailAttackRepresentation(
        message_id="msg-bec-01",
        timestamp="2026-09-23T22:00:00Z",
        sender=SenderInfo(address="ceo@victim-corp.com", domain="victim-corp.com"),
        recipients=[RecipientInfo(address="finance@victim-corp.com")],
        authentication=AuthenticationResults(spf="pass", dkim="pass", dmarc="pass"),
        headers={"Subject": "URGENT: Confidential Wire Transfer Payment Required"},
        body=BodyFeatures(text_plain="Please update the vendor bank routing and swift numbers immediately.")
    )

    matched = registry.match_skills(ear)
    matched_names = [m.name for m in matched]
    assert "bec_financial_recon" in matched_names
