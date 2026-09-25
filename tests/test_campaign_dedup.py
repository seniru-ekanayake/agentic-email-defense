import pytest
import time
from packages.attack_surface.src.campaign_dedup import (
    CampaignFingerprinter,
    CampaignAggregator,
    CampaignCluster
)
from packages.schemas.python.models import (
    EmailAttackRepresentation,
    SenderInfo,
    RecipientInfo,
    AuthenticationResults,
    UrlFeature,
    ExploitIndicator
)


def create_sample_email(
    msg_id: str,
    sender_domain: str = "bad-actor.net",
    recipient_email: str = "user1@victim-corp.com",
    subject: str = "Urgent: Invoice [Ticket#99824] Review Required",
    cve: str = "CVE-2024-21413",
    url: str = "search-ms:query=payload.exe&crumb=location:\\\\bad-actor.net\\share"
) -> EmailAttackRepresentation:
    return EmailAttackRepresentation(
        message_id=msg_id,
        timestamp="2026-09-25T12:00:00Z",
        sender=SenderInfo(address=f"attacker@{sender_domain}", domain=sender_domain),
        recipients=[RecipientInfo(address=recipient_email)],
        authentication=AuthenticationResults(spf="pass", dkim="pass", dmarc="pass"),
        headers={"Subject": subject},
        urls=[UrlFeature(url=url, domain=sender_domain)],
        exploit_indicators=[
            ExploitIndicator(
                indicator_type="MONIKER_LINK",
                evidence=f"{cve} Moniker link detected",
                target_cve=cve,
                confidence=0.95
            )
        ] if cve else []
    )


def test_fingerprint_normalization():
    # Dynamic ticket numbers should normalize to the same fingerprint
    email1 = create_sample_email("msg-01", subject="Urgent: Invoice [Ticket#1001] Review Required")
    email2 = create_sample_email("msg-02", subject="Urgent: Invoice [Ticket#9948] Review Required")

    fp1 = CampaignFingerprinter.compute_fingerprint(email1)
    fp2 = CampaignFingerprinter.compute_fingerprint(email2)

    assert fp1 == fp2


def test_campaign_aggregator_rollup_500_emails():
    aggregator = CampaignAggregator(time_window_seconds=3600)
    aggregator.clear()

    # Simulate 500 emails sent to 50 distinct enterprise users within 10 minutes
    now = time.time()
    for i in range(500):
        recipient = f"employee_{i % 50}@victim-corp.com"
        email = create_sample_email(
            msg_id=f"msg-batch-{i}",
            recipient_email=recipient,
            subject=f"Urgent: Invoice [Ticket#{1000 + i}] Review Required"
        )
        camp, is_new = aggregator.register_email(
            ear=email,
            risk_score=85.0 + (i % 10),
            severity="CRITICAL",
            timestamp=now + (i * 0.5)
        )
        if i == 0:
            assert is_new is True
        else:
            assert is_new is False

    active_camps = aggregator.list_active_campaigns()
    assert len(active_camps) == 1

    camp = active_camps[0]
    assert camp.total_email_count == 500
    assert len(camp.recipients_targeted) == 50
    assert camp.unique_recipient_domains == ["victim-corp.com"]
    assert camp.target_cve == "CVE-2024-21413"
    assert camp.highest_risk_score == 94.0
    assert camp.highest_severity == "CRITICAL"


def test_distinct_campaign_separation():
    aggregator = CampaignAggregator()
    aggregator.clear()

    # Campaign A: Moniker exploit from domain A
    email_a = create_sample_email("msg-a", sender_domain="attacker-a.org", cve="CVE-2024-21413")
    camp_a, is_new_a = aggregator.register_email(email_a, risk_score=90.0)

    # Campaign B: BEC / Invoice lure from domain B (different CVE / URI)
    email_b = create_sample_email("msg-b", sender_domain="lookalike-ceo.com", cve="", url="https://lookalike-ceo.com/login")
    camp_b, is_new_b = aggregator.register_email(email_b, risk_score=75.0)

    assert is_new_a is True
    assert is_new_b is True
    assert camp_a.campaign_id != camp_b.campaign_id
    assert len(aggregator.list_active_campaigns()) == 2
