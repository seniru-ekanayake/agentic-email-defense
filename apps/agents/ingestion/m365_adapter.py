"""Microsoft 365 Graph API Webhook & Mailbox Ingestion Adapter.

Subscribes to Microsoft 365 / Exchange Online change notifications,
validates Graph webhook handshakes, and retrieves raw MIME ($value) messages.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from packages.email_parser.src.mime_parser import MimeParser
from packages.schemas.python.models import EmailAttackRepresentation

logger = logging.getLogger("ingestion.m365")


class M365GraphAdapter:
    """Ingestion adapter for Microsoft 365 / Exchange Online change notifications."""

    def __init__(self, tenant_id: str = "tenant-enterprise", client_state_secret: Optional[str] = None):
        self.tenant_id = tenant_id
        self.client_state_secret = client_state_secret or "agentic-m365-secret"
        self.mime_parser = MimeParser()

    def handle_validation_handshake(self, query_string_or_token: str) -> Tuple[int, str]:
        """Respond to Microsoft Graph webhook validation handshake.

        Microsoft Graph sends a GET/POST request with ?validationToken=... during subscription creation.
        The endpoint MUST return 200 OK with plain text validationToken within 10 seconds.
        """
        token = query_string_or_token
        if "?" in query_string_or_token or "=" in query_string_or_token:
            parsed = parse_qs(query_string_or_token.lstrip("?"))
            token = parsed.get("validationToken", [query_string_or_token])[0]

        logger.info("Validated Microsoft Graph subscription handshake token.")
        return 200, token

    def verify_and_parse_notification(self, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Validate Microsoft Graph change notification payload and extract resource IDs."""
        notifications = payload.get("value", [])
        valid_items = []

        for notif in notifications:
            # Verify clientState if configured
            client_state = notif.get("clientState")
            if self.client_state_secret and client_state != self.client_state_secret:
                logger.warning(f"Rejected notification with invalid clientState: {client_state}")
                continue

            resource = notif.get("resource", "")
            change_type = notif.get("changeType", "created")
            resource_data = notif.get("resourceData", {})
            message_id = resource_data.get("id") or notif.get("subscriptionId")

            valid_items.append({
                "resource": resource,
                "change_type": change_type,
                "message_id": message_id,
                "tenant_id": notif.get("tenantId", self.tenant_id),
                "timestamp": notif.get("subscriptionExpirationDateTime")
            })

        return valid_items

    def ingest_mime_bytes(self, raw_eml_bytes: bytes, tenant_id: Optional[str] = None) -> EmailAttackRepresentation:
        """Parse raw RFC 2822 MIME bytes received from Graph API $value endpoint."""
        return self.mime_parser.parse_eml(raw_eml_bytes)
