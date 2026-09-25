"""Google Workspace (Gmail API) Pub/Sub Ingestion Adapter.

Parses Google Cloud Pub/Sub push notifications for mailbox changes
and decodes base64url-encoded raw RFC 2822 email messages.
"""

from __future__ import annotations

import base64
import json
import logging
from typing import Any, Dict, Optional

from packages.email_parser.src.mime_parser import MimeParser
from packages.schemas.python.models import EmailAttackRepresentation

logger = logging.getLogger("ingestion.gmail")


class GmailPubSubAdapter:
    """Ingestion adapter for Google Workspace / Gmail API Pub/Sub notifications."""

    def __init__(self, tenant_id: str = "tenant-google-workspace"):
        self.tenant_id = tenant_id
        self.mime_parser = MimeParser()

    def parse_pubsub_notification(self, pubsub_payload: Dict[str, Any]) -> Dict[str, Any]:
        """Decode Google Cloud Pub/Sub push notification payload.

        Extracts the base64-encoded message data containing emailAddress and historyId.
        """
        message = pubsub_payload.get("message", {})
        data_b64 = message.get("data", "")

        if not data_b64:
            raise ValueError("Pub/Sub payload missing 'message.data' field")

        try:
            # Handle standard base64 and urlsafe base64 padding
            data_bytes = base64.urlsafe_b64decode(data_b64 + "==")
            data_json = json.loads(data_bytes.decode("utf-8"))
        except Exception as exc:
            logger.error(f"Failed to decode Pub/Sub data payload: {exc}")
            raise ValueError(f"Malformed Pub/Sub data: {exc}")

        return {
            "email_address": data_json.get("emailAddress"),
            "history_id": data_json.get("historyId"),
            "message_id": message.get("messageId"),
            "publish_time": message.get("publishTime")
        }

    def decode_raw_message_bytes(self, raw_b64_url: str) -> bytes:
        """Decode Gmail API raw message string (format='raw')."""
        # Replace base64url characters and add padding
        b64_clean = raw_b64_url.replace("-", "+").replace("_", "/")
        padding_needed = len(b64_clean) % 4
        if padding_needed:
            b64_clean += "=" * (4 - padding_needed)
        return base64.b64decode(b64_clean)

    def ingest_raw_gmail_message(
        self,
        raw_b64_url: str,
        tenant_id: Optional[str] = None
    ) -> EmailAttackRepresentation:
        """Decode raw Gmail base64url string and parse into EmailAttackRepresentation."""
        raw_bytes = self.decode_raw_message_bytes(raw_b64_url)
        return self.mime_parser.parse_eml(raw_bytes)
