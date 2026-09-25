"""IMAP4_SSL & TLS Gateway Polling Daemon.

Continuously polls on-premise Exchange, Zimbra, Postfix, or standard IMAP mailboxes
for UNSEEN messages, extracts raw RFC 822 EML bytes, and submits to the Agentic Pipeline.
"""

from __future__ import annotations

import imaplib
import logging
import time
from typing import Callable, Dict, List, Optional

from packages.email_parser.src.mime_parser import MimeParser
from packages.schemas.python.models import EmailAttackRepresentation

logger = logging.getLogger("ingestion.imap")


class IMAPPollingDaemon:
    """Continuous or batch IMAP4_SSL mailbox listener."""

    def __init__(
        self,
        host: str = "mail.enterprise-corp.internal",
        port: int = 993,
        username: str = "security-ingest@enterprise-corp.internal",
        password: str = "placeholder_secret",
        folder: str = "INBOX",
        tenant_id: str = "tenant-onprem-exchange",
        use_ssl: bool = True
    ):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.folder = folder
        self.tenant_id = tenant_id
        self.use_ssl = use_ssl
        self.mime_parser = MimeParser()
        self._is_running = False

    def fetch_unseen_messages(self, client: Optional[imaplib.IMAP4] = None) -> List[EmailAttackRepresentation]:
        """Connect to IMAP server, search for UNSEEN messages, and return parsed representations."""
        parsed_emails: List[EmailAttackRepresentation] = []
        should_close = False

        try:
            if client is None:
                if self.use_ssl:
                    client = imaplib.IMAP4_SSL(self.host, self.port)
                else:
                    client = imaplib.IMAP4(self.host, self.port)
                client.login(self.username, self.password)
                should_close = True

            client.select(self.folder)
            status, response = client.search(None, "UNSEEN")
            if status != "OK":
                logger.warning(f"IMAP search returned status: {status}")
                return []

            msg_ids = response[0].split()
            logger.info(f"Found {len(msg_ids)} UNSEEN messages in {self.folder}")

            for msg_id in msg_ids:
                fetch_status, data = client.fetch(msg_id, "(RFC822)")
                if fetch_status == "OK" and data and isinstance(data[0], tuple):
                    raw_bytes = data[0][1]
                    ear = self.mime_parser.parse_eml(raw_bytes)
                    parsed_emails.append(ear)
                    # Mark as read
                    client.store(msg_id, "+FLAGS", "\\Seen")

        except Exception as exc:
            logger.error(f"IMAP fetch error from {self.host}:{self.port} - {exc}")
        finally:
            if should_close and client:
                try:
                    client.close()
                    client.logout()
                except Exception:
                    pass

        return parsed_emails

    def poll_once_with_mock_data(self, mock_raw_emls: List[bytes]) -> List[EmailAttackRepresentation]:
        """Simulate polling a list of raw EML byte payloads (used in test and offline pipelines)."""
        results = []
        for raw in mock_raw_emls:
            ear = self.mime_parser.parse_eml(raw)
            results.append(ear)
        return results
