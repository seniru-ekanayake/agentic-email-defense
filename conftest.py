import ipaddress
import os
import socket
import sys
import tempfile

import pytest

repo_root = os.path.abspath(os.path.dirname(__file__))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

# Test environment. Must be set before any application module creates its singletons.
os.environ["FISHINGMAILS_ENV"] = "test"
os.environ["ENVIRONMENT"] = "test"
os.environ.setdefault("FISHINGMAILS_AUTH_SECRET", "test-only-jwt-secret-not-for-production-0123456789")
os.environ.setdefault("FISHINGMAILS_APPROVAL_HMAC_SECRET", "test-only-approval-secret-not-for-production-0123")
os.environ["FISHINGMAILS_DB_PATH"] = os.path.join(tempfile.mkdtemp(prefix="fishingmails-test-"), "test.db")
for var in ("OPENROUTER_API_KEY", "URLHAUS_AUTH_KEY", "MAIL_GATEWAY_URL", "M365_GRAPH_ENDPOINT", "IDP_API_URL",
            "ACTIVE_DIRECTORY_URL", "MAILBOX_SEARCH_URL", "SOC_TICKET_WEBHOOK_URL"):
    os.environ.pop(var, None)

_real_connect = socket.socket.connect
_real_getaddrinfo = socket.getaddrinfo


def _is_loopback(host) -> bool:
    if host in ("localhost",):
        return True
    try:
        return ipaddress.ip_address(str(host).split("%")[0]).is_loopback
    except ValueError:
        return False


def pytest_configure(config):
    config.addinivalue_line("markers", "network: test needs real outbound network access")


def _guarded_connect(sock, address):
    host = address[0] if isinstance(address, tuple) else address
    if not _is_loopback(host):
        raise OSError(f"External network disabled in tests (attempted {host})")
    return _real_connect(sock, address)


def _guarded_getaddrinfo(host, *args, **kwargs):
    if host is None or _is_loopback(host):
        return _real_getaddrinfo(host, *args, **kwargs)
    try:
        ipaddress.ip_address(str(host).strip("[]"))
        return _real_getaddrinfo(host, *args, **kwargs)
    except ValueError:
        raise socket.gaierror(socket.EAI_NONAME, f"DNS disabled in tests ({host})")


# Offline for the whole session (including module/session-scoped fixtures).
socket.socket.connect = _guarded_connect
socket.getaddrinfo = _guarded_getaddrinfo


@pytest.fixture(autouse=True)
def _network_opt_in(request):
    """Tests marked @pytest.mark.network temporarily get real sockets and DNS."""
    if not request.node.get_closest_marker("network"):
        yield
        return
    socket.socket.connect = _real_connect
    socket.getaddrinfo = _real_getaddrinfo
    try:
        yield
    finally:
        socket.socket.connect = _guarded_connect
        socket.getaddrinfo = _guarded_getaddrinfo


@pytest.fixture(autouse=True)
def _isolate_environment():
    """Restore os.environ after every test so configuration cannot leak between tests."""
    snapshot = dict(os.environ)
    yield
    os.environ.clear()
    os.environ.update(snapshot)
