"""SSRF protection: literal, encoded, DNS-resolved and connect-time checks, end to end through an email."""

import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from apps.sandbox.src.network_guard import NetworkGuard
from apps.sandbox.src.url_sandbox import UrlSandboxRunner

guard = NetworkGuard()


@pytest.mark.parametrize("url", [
    "http://localhost/", "http://LOCALHOST./", "http://127.0.0.1/", "http://127.1/", "http://2130706433/",
    "http://0x7f000001/", "http://0177.0.0.1/", "http://10.0.0.5/", "http://192.168.1.1/", "http://172.16.0.1/",
    "http://169.254.169.254/latest/meta-data/", "http://metadata.google.internal./", "http://100.64.0.1/",
    "http://[::1]/", "http://[::ffff:127.0.0.1]/", "http://[fd00::1]/", "http://host.corp/", "http://printer.local/",
])
def test_internal_destinations_blocked(url):
    allowed, reason, _ = guard.evaluate_destination(url)
    assert not allowed, reason


def test_public_literal_allowed():
    assert guard.evaluate_destination("https://93.184.215.14/")[0]


def test_hostname_resolving_to_internal_address_blocked(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.1.2.3", 0))])
    allowed, reason, is_ssrf = guard.evaluate_destination("http://innocent-looking.example/", resolve=True)
    assert not allowed and is_ssrf and "10.1.2.3" in reason


class _Internal(BaseHTTPRequestHandler):
    hits = []

    def log_message(self, *a):
        pass

    def do_GET(self):
        _Internal.hits.append(self.path)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"internal secret")


@pytest.fixture()
def internal_server():
    _Internal.hits = []
    srv = HTTPServer(("127.0.0.1", 0), _Internal)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv
    srv.shutdown()


def test_connect_time_guard_defeats_dns_rebinding(monkeypatch, internal_server):
    """Name check passes (resolves public), but the connection lands on loopback: the fetch must be refused."""
    calls = {"n": 0}
    real = socket.getaddrinfo

    def rebinding(host, *a, **k):
        if host == "rebind.example":
            calls["n"] += 1
            ip = "93.184.215.14" if calls["n"] == 1 else "127.0.0.1"
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, a[0] if a else 0))]
        return real(host, *a, **k)

    monkeypatch.setattr(socket, "getaddrinfo", rebinding)
    report = UrlSandboxRunner().analyze_url(f"http://rebind.example:{internal_server.server_port}/admin")
    assert report.verdict == "BLOCKED_SSRF"
    assert _Internal.hits == []


def test_email_borne_ssrf_does_not_reach_internal_service(monkeypatch, internal_server):
    """Regression for the audit finding: an emailed link resolving to loopback must not be fetched."""
    from apps.agents.investigation_service import InvestigationService
    real = socket.getaddrinfo
    monkeypatch.setattr(socket, "getaddrinfo", lambda host, *a, **k: real("127.0.0.1", *a, **k) if host == "localtest.me" else real(host, *a, **k))
    eml = (f'From: x@attacker-mail.com\nTo: bob@acme-widgets.com\nSubject: hi\nContent-Type: text/html\n\n'
           f'<a href="http://localtest.me:{internal_server.server_port}/internal-admin">click</a>').encode()
    inc = InvestigationService().run_investigation("tenant-ssrf", eml)
    assert "UrlSandboxRunner" in [t.tool_name for t in inc.tool_executions]
    assert _Internal.hits == []
    sandbox = next(e for e in inc.evidence_items if e.type == "BEHAVIORAL_SANDBOX")
    assert sandbox.metadata["verdict"] == "BLOCKED_SSRF"
