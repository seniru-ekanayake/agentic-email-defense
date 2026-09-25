import base64
import json
import pytest
from apps.agents.ingestion.m365_adapter import M365GraphAdapter
from apps.agents.ingestion.gmail_adapter import GmailPubSubAdapter
from apps.agents.ingestion.imap_daemon import IMAPPollingDaemon


def test_m365_validation_handshake():
    adapter = M365GraphAdapter(tenant_id="tenant-m365-demo")
    
    # Test query string format
    status, token = adapter.handle_validation_handshake("validationToken=SecretToken12345")
    assert status == 200
    assert token == "SecretToken12345"

    # Test plain token format
    status_raw, token_raw = adapter.handle_validation_handshake("PlainToken999")
    assert status_raw == 200
    assert token_raw == "PlainToken999"


def test_m365_notification_verification():
    adapter = M365GraphAdapter(tenant_id="tenant-m365-demo", client_state_secret="valid-secret")

    payload = {
        "value": [
            {
                "subscriptionId": "sub-01",
                "clientState": "valid-secret",
                "changeType": "created",
                "resource": "Users/target@victim.com/Messages/msg-graph-01",
                "resourceData": {"id": "msg-graph-01"}
            },
            {
                "subscriptionId": "sub-02",
                "clientState": "tampered-secret",
                "changeType": "created",
                "resource": "Users/other@victim.com/Messages/msg-graph-02"
            }
        ]
    }

    items = adapter.verify_and_parse_notification(payload)
    assert len(items) == 1
    assert items[0]["message_id"] == "msg-graph-01"
    assert items[0]["resource"] == "Users/target@victim.com/Messages/msg-graph-01"


def test_gmail_pubsub_adapter():
    adapter = GmailPubSubAdapter(tenant_id="tenant-google")

    # Encode Pub/Sub payload
    inner_data = json.dumps({"emailAddress": "victim@google-corp.com", "historyId": "123456789"})
    b64_data = base64.b64encode(inner_data.encode("utf-8")).decode("utf-8")

    pubsub_msg = {
        "message": {
            "data": b64_data,
            "messageId": "pubsub-msg-99",
            "publishTime": "2026-09-25T12:00:00Z"
        }
    }

    parsed = adapter.parse_pubsub_notification(pubsub_msg)
    assert parsed["email_address"] == "victim@google-corp.com"
    assert parsed["history_id"] == "123456789"
    assert parsed["message_id"] == "pubsub-msg-99"


def test_gmail_raw_message_decoding():
    adapter = GmailPubSubAdapter()
    sample_eml = b"From: sender@evil.com\r\nTo: target@victim.com\r\nSubject: Test\r\n\r\nHello World"
    # urlsafe base64
    b64_url = base64.urlsafe_b64encode(sample_eml).decode("utf-8")

    decoded_bytes = adapter.decode_raw_message_bytes(b64_url)
    assert decoded_bytes == sample_eml

    ear = adapter.ingest_raw_gmail_message(b64_url, tenant_id="tenant-test")
    assert ear.sender.address == "sender@evil.com"
    assert ear.recipients[0].address == "target@victim.com"


def test_imap_polling_mock_pipeline():
    daemon = IMAPPollingDaemon(tenant_id="tenant-imap")
    sample_eml = b"From: attacker@evil.com\r\nTo: finance@victim.internal\r\nSubject: Urgent Wire\r\n\r\nPlease transfer funds."

    results = daemon.poll_once_with_mock_data([sample_eml])
    assert len(results) == 1
    assert results[0].sender.address == "attacker@evil.com"
    assert results[0].recipients[0].address == "finance@victim.internal"
    assert results[0].headers.get("Subject") == "Urgent Wire"
